const express = require('express');
const WebSocket = require('ws'); // Thêm WebSocket
const cors = require('cors');
const { google } = require('googleapis');
const NodeCache = require('node-cache');
const winston = require('winston');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Khởi tạo cache với TTL (time-to-live) là 1 giờ (3600 giây)
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 }); // Kiểm tra hết hạn mỗi 2 phút
const app = express();
let sheetsClient;
let wss;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

// ID của Google Sheet
const SPREADSHEET_ID = '1mDJIil1rmEXEl7tV5qq3j6HkbKe1padbPhlQMiYaq9U';
// Lưu trữ kết nối WebSocket theo username và deviceId
const clients = new Map(); // Map<username_deviceId, WebSocket>
let cachedUsernames = [];
const otpStore = new Map(); // Lưu trữ { username: { code, expiry } }

// Middleware kiểm tra sheetsClient
const ensureSheetsClient = (req, res, next) => {
  if (!sheetsClient) {
    return res.status(503).json({ success: false, message: 'Service unavailable, server not fully initialized' });
  }
  next();
};
app.use(ensureSheetsClient);

// Hàm khởi tạo Google Sheets client
async function initializeSheetsClient(retries = 3, delay = 5000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
  try {
    const auth = new google.auth.GoogleAuth({
      credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS),
      scopes: ['https://www.googleapis.com/auth/spreadsheets']
    });
    const authClient = await auth.getClient();
    sheetsClient = google.sheets({ version: 'v4', auth: authClient });
    logger.info('Google Sheets client initialized successfully');
    return; // Thành công thì thoát
  } catch (error) {
    logger.error(`Attempt ${attempt} failed to initialize Google Sheets client:`, error);
      if (attempt === retries) {
        logger.error('All attempts failed. Server cannot start.');
        throw error; // Ném lỗi để middleware xử lý
      }
      await new Promise(resolve => setTimeout(resolve, delay)); // Đợi trước khi thử lại
    }
  }
}

let isLoadingUsernames = false;
async function loadUsernames() {
  if (isLoadingUsernames) return;
  isLoadingUsernames = true;
  try{
        const range = 'Accounts';
        const response = await sheetsClient.spreadsheets.values.get({
            spreadsheetId: SPREADSHEET_ID,
            range,
        });

        if (!response || !response.data || !response.data.values) {
            console.error("⚠️ Không thể tải danh sách username.");
            return;
        }

        const rows = response.data.values;
        const headers = rows[0] || [];
        const usernameIndex = headers.indexOf("Username");

        if (usernameIndex === -1) {
            console.error("⚠️ Không tìm thấy cột Username.");
            return;
        }

        cachedUsernames = rows.slice(1).map(row => row[usernameIndex]?.trim().toLowerCase());
        console.log("✅ Tải danh sách username thành công.");
    } catch (error) {
        logger.error("❌ Lỗi khi tải danh sách username:", error);
    } finally {
      isLoadingUsernames = false;
    }
}

// Hàm khởi động server
async function startServer() {
  try {
    // Chờ khởi tạo Google Sheets client
    await initializeSheetsClient();

    // Sau khi sheetsClient sẵn sàng, tải danh sách username
    await loadUsernames();

    // Cấu hình CORS và middleware khác
    const allowedOrigins = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['https://pedmed-vnch.web.app', 'http://localhost:3000'];

    app.use(cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
      optionsSuccessStatus: 204
    }));
    app.use(express.json({ limit: '10kb' }));

    // Khởi tạo WebSocket server
    const PORT = process.env.PORT || 3000;
    const server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`Server đang chạy tại http://0.0.0.0:${PORT}`);
    });
    wss = new WebSocket.Server({ server });
    wss.on('connection', (ws, req) => {
      const urlParams = new URLSearchParams(req.url.split('?')[1]);
      const username = urlParams.get('username');
      const deviceId = urlParams.get('deviceId');
    
      if (!username || !deviceId) {
        ws.close(1008, 'Missing username or deviceId');
        return;
      }
    
      const clientKey = `${username}_${deviceId}`;
      // Đóng kết nối cũ nếu tồn tại
      const existingClient = clients.get(clientKey);
      if (existingClient && existingClient.readyState === WebSocket.OPEN) {
        existingClient.close(1000, 'New connection established');
        logger.info(`Closed old WebSocket connection for ${clientKey}`);
      }
    
      clients.set(clientKey, ws);
      logger.info(`WebSocket connected: ${clientKey}`);
    
      ws.on('close', () => {
        clients.delete(clientKey);
        logger.info(`WebSocket disconnected: ${clientKey}`);
      });
    
      ws.on('error', (error) => {
        logger.error(`WebSocket error for ${clientKey}:`, error);
      });
    });

    // Tải danh sách username ban đầu và định kỳ
    setInterval(loadUsernames, 5 * 60 * 1000);
  } catch (error) {
    logger.error('Server startup failed:', error);
    process.exit(1);
  }
}

// API lấy dữ liệu từ Google Sheets
app.get('/api/drugs', ensureSheetsClient, async (req, res) => {
  logger.info('Request received for /api/drugs', { query: req.query });
  const { query, page: pageRaw = 1, limit: limitRaw = 10 } = req.query;

  const page = isNaN(parseInt(pageRaw)) || parseInt(pageRaw) < 1 ? 1 : parseInt(pageRaw);
  const limit = isNaN(parseInt(limitRaw)) || parseInt(limitRaw) < 1 ? 10 : parseInt(limitRaw);

  const cacheKey = query ? `drugs_${query}_${page}_${limit}` : 'all_drugs';

  try {
    // Kiểm tra cache trước
    let drugs = cache.get(cacheKey);
    if (!drugs) {
      console.log('Cache miss - Lấy dữ liệu từ Google Sheets');
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
      throw new Error('Request to Google Sheets timed out after 10 seconds');
    }, 10000);

      const response = await sheetsClient.spreadsheets.values.get({
        spreadsheetId: SPREADSHEET_ID,
        range: 'pedmedvnch',
        signal: controller.signal
      });
      clearTimeout(timeout);

    const rows = response.data.values || [];
    console.log('Dữ liệu thô từ Google Sheets:', rows);

    drugs = rows.slice(1).map(row => ({
      'Hoạt chất': row[2], // Cột C
      'Cập nhật': row[3], // Cột D
      'Phân loại dược lý': row[4], // Cột E
      'Liều thông thường trẻ sơ sinh': row[5], // Cột F
      'Liều thông thường trẻ em': row[6], // Cột G
      'Hiệu chỉnh liều theo chức năng thận': row[7], // Cột H
      'Hiệu chỉnh liều theo chức năng gan': row[8], // Cột I
      'Chống chỉ định': row[9], // Cột J
      'Tác dụng không mong muốn': row[10], // Cột K
      'Cách dùng (ngoài IV)': row[11], // Cột L
      'Tương tác thuốc chống chỉ định': row[12], // Cột M
      'Ngộ độc/Quá liều': row[13], // Cột N
      'Các thông số cần theo dõi': row[14], // Cột O
      'Bảo hiểm y tế thanh toán': row[15], // Cột P
    }));

    // Lưu vào cache
    cache.set(cacheKey, drugs);
    console.log('Dữ liệu đã được lưu vào cache');
  } else {
    console.log('Cache hit - Lấy dữ liệu từ cache');
  }

    // Lọc dữ liệu nếu có query
    if (query) {
      const filteredDrugs = drugs.filter(drug =>
        drug['Hoạt chất']?.toLowerCase().includes(query.toLowerCase()));
        const start = (page - 1) * limit;
        return res.json({
          total: filteredDrugs.length,
          page,
          data: filteredDrugs.slice(start, start + parseInt(limit))
        });
    }

    console.log('Dữ liệu đã ánh xạ:', drugs);
    res.json(drugs);
  } catch (error) {
    clearTimeout(timeout);
    logger.error('Lỗi khi lấy dữ liệu từ Google Sheets:', error);
    res.status(500).json({ error: 'Không thể lấy dữ liệu' });
  }
});

app.post('/api/drugs/invalidate-cache', ensureSheetsClient, async (req, res) => {
  cache.del('all_drugs');
  if (wss) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ action: 'cache_invalidated' }));
    }
  });
  }
  res.json({ success: true, message: 'Cache đã được làm mới' });
});

// Tạo store để lưu trữ số lần thử cho từng username (dùng bộ nhớ RAM)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 5, // 5 lần thử
  message: { success: false, message: "Quá nhiều lần thử đăng nhập với tài khoản này. Vui lòng thử lại sau 15 phút!" },
  keyGenerator: (req) => {
    const username = req.body.username ? req.body.username.trim().toLowerCase() : 'unknown';
    return username;
  },
  skipSuccessfulRequests: true, // Chỉ bỏ qua khi đăng nhập thành công
  handler: (req, res) => {
    res.status(429).json({ success: false, message: "Quá nhiều lần thử đăng nhập với tài khoản này. Vui lòng thử lại sau 15 phút!" });
  }
});

// API kiểm tra đăng nhập
app.post('/api/login', loginLimiter, async (req, res, next) => {
  const { username, password, deviceId, deviceName } = req.body;
  logger.info('Login request received', { username, deviceId, deviceName });

  if (!username || !password || !deviceId) {
    return res.status(400).json({ success: false, message: "Thiếu thông tin đăng nhập!" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts',
      signal: controller.signal
    });
    clearTimeout(timeout);

    const rows = response.data.values;
    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const passwordIndex = headers.indexOf("Password");
    const approvedIndex = headers.indexOf("Approved");
    const device1IdIndex = headers.indexOf("Device_1_ID");
    const device1NameIndex = headers.indexOf("Device_1_Name");
    const device2IdIndex = headers.indexOf("Device_2_ID");
    const device2NameIndex = headers.indexOf("Device_2_Name");

    if ([usernameIndex, passwordIndex, approvedIndex, device1IdIndex, device1NameIndex, device2IdIndex, device2NameIndex].includes(-1)) {
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const userRowIndex = rows.findIndex(row => row[usernameIndex] === username);
    if (userRowIndex === -1) {
      return res.status(401).json({ success: false, message: "Tài khoản hoặc mật khẩu chưa đúng!" });
    }

    const user = rows[userRowIndex];
    const isPasswordValid = await bcrypt.compare(password.trim(), user[passwordIndex]?.trim() || '');
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: "Tài khoản hoặc mật khẩu chưa đúng!" });
    }

    if (user[approvedIndex]?.trim().toLowerCase() !== "đã duyệt") {
      return res.status(403).json({ success: false, message: "Tài khoản chưa được phê duyệt bởi quản trị viên." });
    }

    let currentDevices = [
      { id: user[device1IdIndex], name: user[device1NameIndex] },
      { id: user[device2IdIndex], name: user[device2NameIndex] }
    ].filter(d => d.id);

    if (currentDevices.some(d => d.id === deviceId)) {
      return res.status(200).json({ success: true, message: "Đăng nhập thành công!" });
    }

    if (currentDevices.length >= 2) {
      return res.status(403).json({
        success: false,
        message: "Tài khoản đã đăng nhập trên 2 thiết bị. Vui lòng chọn thiết bị cần đăng xuất.",
        devices: currentDevices.map(d => ({ id: d.id, name: d.name })) // Trả về cả id và name
      });
    }

    currentDevices.push({ id: deviceId, name: deviceName });
    currentDevices = currentDevices.slice(-2);

    const values = [
      currentDevices[0]?.id || "",
      currentDevices[0]?.name || "",
      currentDevices[1]?.id || "",
      currentDevices[1]?.name || ""
    ];

    // Tính range động dựa trên chỉ số cột
    const startCol = String.fromCharCode(65 + device1IdIndex); // Ví dụ: L (11 -> 76)
    const endCol = String.fromCharCode(65 + device2NameIndex); // Ví dụ: O (14 -> 79)
    await sheetsClient.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!${startCol}${userRowIndex + 1}:${endCol}${userRowIndex + 1}`,
      valueInputOption: "RAW",
      resource: { values: [values] }
    });

    return res.status(200).json({ success: true, message: "Đăng nhập thành công và thiết bị đã được lưu!" });
  } catch (error) {
    clearTimeout(timeout);
    logger.error('Lỗi khi kiểm tra tài khoản:', error);
    next(error);
  }
});

// Hàm đặt OTP với TTL
const setOtp = (username, otpCode, ttlInSeconds) => {
  const hashedOtp = bcrypt.hashSync(otpCode, 10); // Mã hóa OTP
  const expiry = Date.now() + ttlInSeconds * 1000;
  otpStore.set(username, { code: hashedOtp, expiry });
  logger.info(`Stored OTP for ${username}, expires at ${new Date(expiry).toISOString()}`);
  
  // Tự động xóa sau khi hết hạn
  setTimeout(() => {
    if (otpStore.get(username)?.expiry === expiry) {
      otpStore.delete(username);
      logger.info(`OTP for ${username} expired and removed`);
    }
  }, ttlInSeconds * 1000);
};

// Hàm lấy và kiểm tra OTP
const getOtp = async (username, inputOtp) => {
  const otpData = otpStore.get(username);
  if (!otpData || Date.now() > otpData.expiry) {
    otpStore.delete(username); // Xóa nếu hết hạn
    return false;
  }
  return await bcrypt.compare(inputOtp, otpData.code); // So sánh mã hóa
};

// Hàm xóa OTP
const deleteOtp = (username) => {
  otpStore.delete(username);
  logger.info(`OTP for ${username} deleted`);
};

async function getAccessToken() {
  logger.info("🔄 Đang lấy Access Token...");

  try {
      const refreshToken = process.env.REFRESH_TOKEN;
      const clientId = process.env.CLIENT_ID;
      const clientSecret = process.env.CLIENT_SECRET;

      if (!refreshToken || !clientId || !clientSecret) {
          throw new Error("Thiếu thông tin OAuth (REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET) trong môi trường!");
      }

      const tokenUrl = "https://oauth2.googleapis.com/token";
      const payload = new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          refresh_token: refreshToken,
          grant_type: "refresh_token"
      });

      const response = await fetch(tokenUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: payload
      });

      const json = await response.json();
      if (!response.ok) {
          throw new Error(`Lỗi khi lấy Access Token: ${json.error}`);
      }

      logger.info("✅ Access Token lấy thành công!");
      return json.access_token;
  } catch (error) {
      logger.error("❌ Lỗi khi lấy Access Token:", error.message);
      throw error;
  }
}

// 📧 Hàm gửi email bằng Gmail API
async function sendEmailWithGmailAPI(toEmail, subject, body, retries = 3, delay = 5000) {
  logger.info(`📧 Chuẩn bị gửi email đến: ${toEmail}`);
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
        const accessToken = await getAccessToken();
        const url = "https://www.googleapis.com/gmail/v1/users/me/messages/send";
        const rawEmail = [
            "MIME-Version: 1.0",
            "Content-Type: text/html; charset=UTF-8",
            `From: PedMedVN <pedmedvn.nch@gmail.com>`,
            `To: <${toEmail}>`,
            `Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`,
            "",
            body
        ].join("\r\n");

        const encodedMessage = Buffer.from(rawEmail)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ raw: encodedMessage })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(`Lỗi gửi email: ${result.error.message}`);
        }

        logger.info("✅ Email đã gửi thành công:", result);
        return true; // Thành công
    } catch (error) {
      logger.error(`Attempt ${attempt} failed to send email to ${toEmail}:`, error.message);
      if (attempt === retries) {
        throw new Error(`Không thể gửi email sau ${retries} lần thử: ${error.message}`);
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

//API kiểm tra trạng thái đã duyệt
app.post('/api/check-session', async (req, res, next) => {
  logger.info('Request received for /api/check-session', { body: req.body });
  const { username, deviceId } = req.body;

  if (!username || !deviceId) {
    console.log("Lỗi: Không có tên đăng nhập hoặc Device ID");
    return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản hoặc thiết bị!" });
  }

  try {
    console.log(`📌 Kiểm tra trạng thái tài khoản của: ${username}, DeviceID: ${deviceId}`);
    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts',
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      console.log("Không tìm thấy tài khoản trong Google Sheets");
      return res.json({ success: false, message: "Không tìm thấy tài khoản!" });
    }

    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const approvedIndex = headers.indexOf("Approved");
    const device1IdIndex = headers.indexOf("Device_1_ID");
    const device2IdIndex = headers.indexOf("Device_2_ID");

    if ([usernameIndex, approvedIndex, device1IdIndex, device2IdIndex].includes(-1)) {
      console.log("Lỗi: Không tìm thấy cột cần thiết");
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const accounts = rows.slice(1);
    const user = accounts.find(row => row[usernameIndex]?.trim() === username.trim());

    if (!user) {
      console.log("Tài khoản không tồn tại!");
      return res.json({ success: false, message: "Tài khoản không tồn tại!" });
    }

    console.log(`📌 Trạng thái tài khoản: ${user[approvedIndex]}`);

    if (!user[approvedIndex] || user[approvedIndex]?.trim().toLowerCase() !== "đã duyệt") {
      console.log("⚠️ Tài khoản bị hủy duyệt, cần đăng xuất!");
      return res.json({ success: false, message: "Tài khoản đã bị hủy duyệt!" });
    }

    // Kiểm tra xem thiết bị còn hợp lệ không
    const currentDevices = [user[device1IdIndex], user[device2IdIndex]].filter(Boolean);
    console.log(`📌 Danh sách thiết bị hợp lệ: ${currentDevices}`);

    if (!currentDevices.includes(deviceId)) {
      console.log("⚠️ Thiết bị không còn hợp lệ, cần đăng xuất!");
      return res.json({ success: false, message: "Thiết bị của bạn đã bị đăng xuất!" });
    }

    res.json({ success: true });

  } catch (error) {
    logger.error("❌ Lỗi khi kiểm tra trạng thái tài khoản:", error);
    next(error);
  }
});

app.post('/api/logout-device', async (req, res, next) => {
  logger.info('Request received for /api/logout-device', { body: req.body });
  try {
    const { username, deviceId, newDeviceId, newDeviceName } = req.body;

    if (!username || !deviceId || !newDeviceId || !newDeviceName) {
      return res.status(400).json({ success: false, message: "Thiếu thông tin cần thiết" });
    }

    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts',
    });

    const rows = response.data.values;
    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const device1IdIndex = headers.indexOf("Device_1_ID");
    const device1NameIndex = headers.indexOf("Device_1_Name");
    const device2IdIndex = headers.indexOf("Device_2_ID");
    const device2NameIndex = headers.indexOf("Device_2_Name");

    if ([usernameIndex, device1IdIndex, device1NameIndex, device2IdIndex, device2NameIndex].includes(-1)) {
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const userRowIndex = rows.findIndex(row => row[usernameIndex] === username);
    if (userRowIndex === -1) {
      return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản" });
    }

    let devices = [
      { id: rows[userRowIndex][device1IdIndex], name: rows[userRowIndex][device1NameIndex] },
      { id: rows[userRowIndex][device2IdIndex], name: rows[userRowIndex][device2NameIndex] }
    ].filter(d => d.id);

    // Gửi thông báo đến thiết bị cũ trước khi xóa
    const oldDevice = devices.find(d => d.id === deviceId);
    if (oldDevice) {
      const clientKey = `${username}_${deviceId}`;
      const oldClient = clients.get(clientKey);
      if (oldClient && oldClient.readyState === WebSocket.OPEN) {
        oldClient.send(JSON.stringify({ action: 'logout', message: 'Thiết bị của bạn đã bị đăng xuất bởi thiết bị mới!' }));
        logger.info(`Sent logout notification to ${clientKey}`);
      } else if (oldClient) {
        clients.delete(clientKey); // Xóa kết nối không còn hoạt động
        logger.info(`Removed stale WebSocket connection for ${clientKey}`);
      }
    }

    // Xóa thiết bị cũ
    devices = devices.filter(d => d.id !== deviceId && d.id !== newDeviceId);
    // Thêm thiết bị mới
    devices.push({ id: newDeviceId, name: newDeviceName });

    const values = [
      devices[0]?.id || "", devices[0]?.name || "",
      devices[1]?.id || "", devices[1]?.name || ""
    ];

    const startCol = String.fromCharCode(65 + device1IdIndex);
    const endCol = String.fromCharCode(65 + device2NameIndex);
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!${startCol}${userRowIndex + 1}:${endCol}${userRowIndex + 1}`,
      valueInputOption: "RAW",
      resource: { values: [values] }
    });

    return res.json({ success: true, message: "Đăng xuất thành công!" });
  } catch (error) {
    logger.error('Lỗi khi đăng xuất thiết bị:', error);
    next(error);
  }
});

app.post('/api/logout-device-from-sheet', async (req, res) => {
    const { username, deviceId } = req.body;

    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts',
    });
  
    const rows = response.data.values;
    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const device1IdIndex = headers.indexOf("Device_1_ID");
    const device1NameIndex = headers.indexOf("Device_1_Name");
    const device2IdIndex = headers.indexOf("Device_2_ID");
    const device2NameIndex = headers.indexOf("Device_2_Name");

    if ([usernameIndex, device1IdIndex, device1NameIndex, device2IdIndex, device2NameIndex].includes(-1)) {
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }
  
    const userRowIndex = rows.findIndex(row => row[usernameIndex] === username);
    if (userRowIndex === -1) {
      return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản!" });
    }
  
    let devices = [
      { id: rows[userRowIndex][device1IdIndex], name: rows[userRowIndex][device1NameIndex] },
      { id: rows[userRowIndex][device2IdIndex], name: rows[userRowIndex][device2NameIndex] }
    ].filter(d => d.id);
  
    if (!devices.some(d => d.id === deviceId)) {
      return res.status(400).json({ success: false, message: "Thiết bị không tồn tại trong danh sách!" });
    }
  
    devices = devices.filter(d => d.id !== deviceId);
    const values = [
      devices[0]?.id || "", devices[0]?.name || "",
      devices[1]?.id || "", devices[1]?.name || ""
    ];
  
  const startCol = String.fromCharCode(65 + device1IdIndex);
  const endCol = String.fromCharCode(65 + device2NameIndex);
  await sheets.spreadsheets.values.update({
    spreadsheetId: SPREADSHEET_ID,
    range: `Accounts!${startCol}${userRowIndex + 1}:${endCol}${userRowIndex + 1}`,
    valueInputOption: "RAW",
    resource: { values: [values] }
  });
  
    return res.json({ success: true, message: "Thiết bị đã được xóa khỏi danh sách!" });
  });

// API kiểm tra username
app.post('/api/check-username', async (req, res, next) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ exists: false, message: "Thiếu tên đăng nhập!" });
        }

        const isUsernameTaken = cachedUsernames.includes(username.trim().toLowerCase());

        return res.json({ exists: isUsernameTaken });
    } catch (error) {
        console.error("❌ Lỗi khi kiểm tra username:", error);
        next(error);
    }
});

// Hàm kiểm tra định dạng email hợp lệ
function isValidEmail(email) {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(email);
}

function isValidPhone(phone) {
  const phonePattern = /^(0[35789])[0-9]{8}$/; // Định dạng VN: 09x, 08x, 07x, 03x, 05x + 8 số
  return phonePattern.test(phone);
}

//API đăng ký user
app.post('/api/register', async (req, res, next) => {
  logger.info('Request received for /api/register', { body: req.body });
  const { username, password, fullname, email, phone, occupation, workplace, province } = req.body;

  if (username.length > 50 || password.length > 100 || email.length > 255 || phone.length > 15) {
    return res.status(400).json({ success: false, message: "Dữ liệu đầu vào vượt quá giới hạn độ dài!" });
  }

  if (!username || !password || !fullname || !email || !phone || !occupation || !workplace || !province) {
      return res.status(400).json({ success: false, message: "Vui lòng điền đầy đủ thông tin!" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Email không hợp lệ!" });
  }

  if (!isValidPhone(phone)) {
    return res.status(400).json({ success: false, message: "Số điện thoại không hợp lệ!" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
      const response = await sheetsClient.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range: 'Accounts',
          signal: controller.signal
      });
      clearTimeout(timeout);

      const rows = response.data.values;
      if (!rows || rows.length === 0) {
          return res.status(500).json({ success: false, message: "Lỗi dữ liệu Google Sheets!" });
      }

      const headers = rows[0];
      const usernameIndex = headers.indexOf("Username");
      const emailIndex = headers.indexOf("Email");

      if (usernameIndex === -1 || emailIndex === -1) {
        return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
      }

      const accounts = rows.slice(1);
      const isTaken = accounts.some(row => row[usernameIndex]?.trim() === username.trim());
      if (isTaken) {
          return res.json({ success: false, message: "Tên đăng nhập không hợp lệ!" });
      }

      const isEmailTaken = accounts.some(row => row[emailIndex]?.trim() === email.trim());
      if (isEmailTaken) {
        return res.json({ success: false, message: "Email đã được sử dụng!" });
      }

      // Hash mật khẩu
      const hashedPassword = await bcrypt.hash(password, 10); // 10 là số vòng hash

      // 🔹 Thêm cột Date (ngày đăng ký)
      const today = new Date().toISOString().split("T")[0]; // Lấy ngày hiện tại YYYY-MM-DD
      const newUser = [
        username,
        hashedPassword,
        fullname,
        email,
        phone,
        "Chưa duyệt",
        today,
        occupation,
        workplace,
        province,
        "", // Notified
        "", // Device_1_ID
        "", // Device_1_Name
        "", // Device_2_ID
        ""  // Device_2_Name
      ];

      await sheets.spreadsheets.values.append({
          spreadsheetId: SPREADSHEET_ID,
          range: 'Accounts',
          valueInputOption: "USER_ENTERED",
          resource: { values: newUser }
      });

      await sendRegistrationEmail(email, username);

      res.json({ success: true, message: "Đăng ký thành công! Thông báo phê duyệt tài khoản thành công sẽ được gửi tới email của bạn (có thể cần kiểm tra trong mục Spam)." });

  } catch (error) {
      clearTimeout(timeout);
      logger.error("Lỗi khi đăng ký tài khoản:", error);
      next(error);
  }
});

async function sendRegistrationEmail(toEmail, username) {
  try {
  const emailBody = `
    <h2 style="color: #4CAF50;">Xin chào ${username}!</h2>
    <p>Cảm ơn bạn đã đăng ký tài khoản tại PedMedVN. Tài khoản của bạn đã được tạo thành công và đang chờ phê duyệt từ quản trị viên.</p>
    <p>Chúng tôi sẽ thông báo qua email này khi tài khoản được phê duyệt.</p>
    <p>Trân trọng,<br>Đội ngũ PedMedVN</p>
  `;
  await sendEmailWithGmailAPI(toEmail, "ĐĂNG KÝ TÀI KHOẢN PEDMEDVN THÀNH CÔNG", emailBody);
} catch (error) {
  logger.error(`Failed to send registration email to ${toEmail}:`, error);
  // Có thể ghi log hoặc xử lý thêm, nhưng không crash server
}
}

app.post('/api/check-approval', async (req, res, next) => {

  try {
    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts'
    });

    const rows = response.data.values;
    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const emailIndex = headers.indexOf("Email");
    const approvedIndex = headers.indexOf("Approved");

    if ([usernameIndex, emailIndex, approvedIndex].includes(-1)) {
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const accounts = rows.slice(1);
    for (let i = 0; i < accounts.length; i++) {
      const username = accounts[i][usernameIndex];
      const email = accounts[i][emailIndex];
      const approved = accounts[i][approvedIndex]?.trim().toLowerCase();

      if (approved === "đã duyệt" && !cache.get(`approved_${username}`)) {
        await sendApprovalEmail(email, username);
        cache.set(`approved_${username}`, true);
      }
    }

    res.json({ success: true, message: "Kiểm tra và gửi email hoàn tất" });
  } catch (error) {
    logger.error("Lỗi khi kiểm tra phê duyệt:", error);
    next(error);
  }
});

async function sendApprovalEmail(toEmail, username) {
  const emailBody = `
    <h2 style="color: #4CAF50;">Xin chào ${username}!</h2>
    <p style="font-weight: bold">Tài khoản ${username} của bạn đã được phê duyệt thành công.</p>
    <p>Bạn có thể đăng nhập tại: <a href="https://pedmed-vnch.web.app">Đăng nhập ngay</a></p>
    <p>Cảm ơn bạn đã sử dụng dịch vụ của chúng tôi!</p>
  `;
  await sendEmailWithGmailAPI(toEmail, "TÀI KHOẢN PEDMEDVN ĐÃ ĐƯỢC PHÊ DUYỆT", emailBody);
}

const crypto = require("crypto");

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 5, // 5 lần thử
  message: { success: false, message: "Quá nhiều lần thử gửi OTP. Vui lòng đợi 15 phút!" },
  keyGenerator: (req) => req.body.username || 'unknown'
});

//API gửi OTP đến email user
app.post('/api/send-otp', otpLimiter, async (req, res, next) => {
  logger.info('Request received for /api/send-otp', { body: req.body });

  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản!" });
  }

  try {
    logger.info(`Fetching user data for ${username}`);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await sheetsClient.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'Accounts',
      signal: controller.signal
    });
    clearTimeout(timeout);

    const rows = response.data.values || [];
    if (!rows.length) {
      logger.warn('No data found in Accounts sheet');
      return res.status(404).json({ success: false, message: "Không tìm thấy dữ liệu tài khoản!" });
    }
    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const emailIndex = headers.indexOf("Email");

    const user = rows.find(row => row[usernameIndex]?.trim() === username.trim());
    if (!user) {
      logger.warn(`User ${username} not found`);
      return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản!" });
    }

    const userEmail = user[emailIndex];
    if (!isValidEmail(userEmail)) {
      logger.warn(`Invalid email for ${username}: ${userEmail}`);
      return res.status(400).json({ success: false, message: "Email không hợp lệ!" });
    }

    const otpCode = Math.floor(100000 + Math.random() * 900000);
    setOtp(username, otpCode.toString(), 300); // Lưu OTP với TTL 300 giây

    await sendEmailWithGmailAPI(userEmail, "MÃ XÁC NHẬN ĐỔI MẬT KHẨU", `
      <h2 style="color: #4CAF50;">Xin chào ${username}!</h2>
      <p style="font-weight: bold">Mã xác nhận đổi mật khẩu của bạn là: 
      <h3 style="font-weight: bold">${otpCode}</h3></p>
      <p>Vui lòng nhập ngay mã này vào trang web để tiếp tục đổi mật khẩu.</p>
    `);

    return res.json({ success: true, message: "Mã xác nhận đã được gửi đến email của bạn!" });
  } catch (error) {
    logger.error("❌ Lỗi máy chủ khi gửi OTP:", error);
    next(error);
  }
});

//API xác thực OTP
app.post('/api/verify-otp', async (req, res, next) => {
  logger.info('Request received for /api/verify-otp', { body: req.body });

  const { username, otp } = req.body;
  if (!username || !otp) return res.status(400).json({ success: false, message: "Thiếu thông tin xác minh!" });

  try {
    const isValid = await getOtp(username, otp);
    if (!isValid) return res.status(400).json({ success: false, message: "OTP không hợp lệ hoặc đã hết hạn!" });

    deleteOtp(username);
    return res.json({ success: true, message: "Xác minh thành công, hãy đặt lại mật khẩu mới!" });
  } catch (error) {
    logger.error("❌ Lỗi khi xác minh OTP:", error);
    next(error);
  }
});

//API cập nhật mật khẩu mới
app.post('/api/reset-password', async (req, res, next) => {
  logger.info('Request received for /api/reset-password', { body: req.body });
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
      return res.status(400).json({ success: false, message: "Vui lòng nhập đầy đủ thông tin!" });
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || authHeader !== `Bearer ${username}`) { // Giả sử token đơn giản
    return res.status(403).json({ success: false, message: "Không có quyền truy cập!" });
  }

  try {
      const response = await sheetsClient.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range: 'Accounts',
      });

      const rows = response.data.values;
      const headers = rows[0];
      const usernameIndex = headers.indexOf("Username");
      const passwordIndex = headers.indexOf("Password");
      const device1IdIndex = headers.indexOf("Device_1_ID");
      const device1NameIndex = headers.indexOf("Device_1_Name");
      const device2IdIndex = headers.indexOf("Device_2_ID");
      const device2NameIndex = headers.indexOf("Device_2_Name");

      if ([usernameIndex, passwordIndex, device1IdIndex, device1NameIndex, device2IdIndex, device2NameIndex].includes(-1)) {
          console.log("❌ Không tìm thấy cột cần thiết trong Google Sheets!");
          return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
      }

      const userRowIndex = rows.findIndex(row => row[usernameIndex]?.trim() === username.trim());
      if (userRowIndex === -1) {
          console.log("❌ Tài khoản không tồn tại!");
          return res.status(404).json({ success: false, message: "Tài khoản không tồn tại!" });
      }

      const oldPasswordHash = rows[userRowIndex][passwordIndex];
    if (await bcrypt.compare(newPassword, oldPasswordHash)) {
      return res.status(400).json({ success: false, message: "Mật khẩu mới không được giống mật khẩu cũ!" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!${String.fromCharCode(65 + passwordIndex)}${userRowIndex + 1}`, // Cột Password
      valueInputOption: "RAW",
      resource: { values: [[hashedNewPassword]] }
    });

    const startCol = String.fromCharCode(65 + device1IdIndex);
    const endCol = String.fromCharCode(65 + device2NameIndex);
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!${startCol}${userRowIndex + 1}:${endCol}${userRowIndex + 1}`,
      valueInputOption: "RAW",
      resource: { values: [["", "", "", ""]] }
    });

    // Gửi thông báo đăng xuất qua WebSocket (nếu có)
    const devices = [
      { id: rows[userRowIndex][device1IdIndex], name: rows[userRowIndex][device1NameIndex] },
      { id: rows[userRowIndex][device2IdIndex], name: rows[userRowIndex][device2NameIndex] }
    ].filter(d => d.id);

    devices.forEach(device => {
      const clientKey = `${username}_${device.id}`;
      const oldClient = clients.get(clientKey);
      if (oldClient && oldClient.readyState === WebSocket.OPEN) {
        oldClient.send(JSON.stringify({ action: 'logout', message: 'Mật khẩu đã được thay đổi, thiết bị của bạn đã bị đăng xuất!' }));
        logger.info(`Sent logout notification to ${clientKey}`);
      }
    });

      return res.json({ success: true, message: "Đổi mật khẩu thành công! Hãy đăng nhập lại." });

  } catch (error) {
      logger.error("❌ Lỗi khi cập nhật mật khẩu:", error);
      next(error);
  }
});

// Gọi hàm khởi động
startServer();

// Middleware xử lý lỗi
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.stack });
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Lỗi máy chủ không xác định'
  });
});