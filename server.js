const express = require('express');
const WebSocket = require('ws'); // Thêm WebSocket
const cors = require('cors');
const { google } = require('googleapis');
const NodeCache = require('node-cache');
const winston = require('winston');
const bcrypt = require('bcrypt');

// Khởi tạo cache với TTL (time-to-live) là 1 giờ (3600 giây)
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 }); // Kiểm tra hết hạn mỗi 2 phút

const app = express();

const PORT = process.env.PORT || 3000;

// Cấu hình CORS
app.use(cors({
  origin: "https://pedmed-vnch.web.app",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true // Nếu cần gửi cookie hoặc auth token
}));

// Xử lý tất cả yêu cầu OPTIONS một cách rõ ràng
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://pedmed-vnch.web.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(204); // No Content
});

app.use(express.json());

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server đang chạy tại http://0.0.0.0:${PORT}`);
});

// Khởi tạo WebSocket server
const wss = new WebSocket.Server({ server });

// Lưu trữ kết nối WebSocket theo username và deviceId
const clients = new Map(); // Map<username_deviceId, WebSocket>

wss.on('connection', (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const username = urlParams.get('username');
  const deviceId = urlParams.get('deviceId');

  if (!username || !deviceId) {
    ws.close(1008, 'Missing username or deviceId');
    return;
  }

  const clientKey = `${username}_${deviceId}`;
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

// Thay Redis bằng Map để lưu OTP
const otpStore = new Map(); // Lưu trữ { username: { code, expiry } }

// Hàm đặt OTP với TTL
const setOtp = (username, otpCode, ttlInSeconds) => {
  const expiry = Date.now() + ttlInSeconds * 1000;
  otpStore.set(username, { code: otpCode, expiry });
  logger.info(`Stored OTP for ${username}: ${otpCode}, expires at ${new Date(expiry).toISOString()}`);
  
  // Tự động xóa sau khi hết hạn
  setTimeout(() => {
    if (otpStore.get(username)?.expiry === expiry) {
      otpStore.delete(username);
      logger.info(`OTP for ${username} expired and removed`);
    }
  }, ttlInSeconds * 1000);
};

// Hàm lấy và kiểm tra OTP
const getOtp = (username) => {
  const otpData = otpStore.get(username);
  if (!otpData || Date.now() > otpData.expiry) {
    otpStore.delete(username); // Xóa nếu hết hạn
    return null;
  }
  return otpData.code;
};

// Hàm xóa OTP
const deleteOtp = (username) => {
  otpStore.delete(username);
  logger.info(`OTP for ${username} deleted`);
};

// ID của Google Sheet
const SPREADSHEET_ID = '1mDJIil1rmEXEl7tV5qq3j6HkbKe1padbPhlQMiYaq9U';

// Khởi tạo Google Sheets API client
const auth = new google.auth.GoogleAuth({
  credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS),
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

async function getSheetsClient() {
  logger.info('Initializing Google Sheets client');
  try {
    const authClient = await auth.getClient();
    return google.sheets({ version: 'v4', auth: authClient });
  } catch (error) {
    logger.error('Failed to initialize Google Sheets client:', error);
    throw error;
  }
}

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
async function sendEmailWithGmailAPI(toEmail, subject, body) {
  logger.info(`📧 Chuẩn bị gửi email đến: ${toEmail}`);

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
        logger.error("❌ Lỗi khi gửi email:", error.message);
        throw error; // Ném lỗi để endpoint bắt
    }
}

// API lấy dữ liệu từ Google Sheets
app.get('/api/drugs', async (req, res) => {
  logger.info('Request received for /api/drugs', { query: req.query });
  const { query, page: pageRaw = 1, limit: limitRaw = 10 } = req.query;

  const page = isNaN(parseInt(pageRaw)) || parseInt(pageRaw) < 1 ? 1 : parseInt(pageRaw);
  const limit = isNaN(parseInt(limitRaw)) || parseInt(limitRaw) < 1 ? 10 : parseInt(limitRaw);

  const cacheKey = 'all_drugs'; // Key cố định cho toàn bộ dữ liệu

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000); // 10 giây
  try {
    // Kiểm tra cache trước
    let drugs = cache.get(cacheKey);
    if (!drugs) {
      console.log('Cache miss - Lấy dữ liệu từ Google Sheets');
      const sheets = await getSheetsClient();
      const response = await sheets.spreadsheets.values.get({
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
        const end = start + parseInt(limit);
        return res.json({
          total: filteredDrugs.length,
          page: parseInt(page),
          data: filteredDrugs.slice(start, end)
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

app.post('/api/drugs/invalidate-cache', async (req, res) => {
  cache.del('all_drugs'); // Xóa cache với node-cache
  res.json({ success: true, message: 'Cache đã được làm mới' });
});

const rateLimit = require('express-rate-limit');

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
app.post('/api/login', loginLimiter, async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://pedmed-vnch.web.app');
  const { username, password, deviceId, deviceName } = req.body;
  logger.info('Login request received', { username, deviceId, deviceName });

  if (!username || !password || !deviceId) {
    return res.status(400).json({ success: false, message: "Thiếu thông tin đăng nhập!" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const sheets = await getSheetsClient();
    const response = await sheets.spreadsheets.values.get({
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

    if (usernameIndex === -1 || passwordIndex === -1 || approvedIndex === -1 || device1IdIndex === -1) {
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

    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!I${userRowIndex + 1}:L${userRowIndex + 1}`, // Cập nhật 4 cột
      valueInputOption: "RAW",
      resource: { values: [values] }
    });

    return res.status(200).json({ success: true, message: "Đăng nhập thành công và thiết bị đã được lưu!" });
  } catch (error) {
    clearTimeout(timeout);
    logger.error('Lỗi khi kiểm tra tài khoản:', error);
    return res.status(500).json({ success: false, message: 'Lỗi máy chủ.' });
  }
});

//API kiểm tra trạng thái đã duyệt
app.post('/api/check-session', async (req, res) => {
  logger.info('Request received for /api/check-session', { body: req.body });
  const { username, deviceId } = req.body;

  if (!username || !deviceId) {
    console.log("Lỗi: Không có tên đăng nhập hoặc Device ID");
    return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản hoặc thiết bị!" });
  }

  try {
    console.log(`📌 Kiểm tra trạng thái tài khoản của: ${username}, DeviceID: ${deviceId}`);
    const sheets = await getSheetsClient();
    const range = 'Accounts'; 
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
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

    if (usernameIndex === -1 || approvedIndex === -1 || device1IdIndex === -1 || device2IdIndex === -1) {
      console.log("Lỗi: Không tìm thấy cột Username, Approved, Device_1_ID hoặc Device_2_ID");
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
    res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

app.post('/api/logout-device', async (req, res) => {
  logger.info('Request received for /api/logout-device', { body: req.body });
  try {
    const { username, deviceId, newDeviceId, newDeviceName } = req.body;

    if (!username || !deviceId || !newDeviceId || !newDeviceName) {
      return res.status(400).json({ success: false, message: "Thiếu thông tin cần thiết" });
    }

    const sheets = await getSheetsClient();
    const response = await sheets.spreadsheets.values.get({
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

    if (usernameIndex === -1 || device1IdIndex === -1 || device2IdIndex === -1) {
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
      }
    }

    // Xóa thiết bị cũ
    devices = devices.filter(d => d.id !== deviceId);
    // Thêm thiết bị mới
    devices.push({ id: newDeviceId, name: newDeviceName });

    const values = [
      devices[0]?.id || "", devices[0]?.name || "",
      devices[1]?.id || "", devices[1]?.name || ""
    ];

    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!I${userRowIndex + 1}:L${userRowIndex + 1}`, // Cập nhật 4 cột
      valueInputOption: "RAW",
      resource: { values: [values] }
    });

    return res.json({ success: true, message: "Đăng xuất thành công!" });
  } catch (error) {
    logger.error('Lỗi khi đăng xuất thiết bị:', error);
    return res.status(500).json({ success: false, message: "Lỗi máy chủ" });
  }
});

app.post('/api/logout-device-from-sheet', async (req, res) => {
    const { username, deviceId } = req.body;
  
    const sheets = await getSheetsClient();
    const response = await sheets.spreadsheets.values.get({
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
  
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `Accounts!I${userRowIndex + 1}:L${userRowIndex + 1}`,
      valueInputOption: "RAW",
      resource: { values: [values] }
    });
  
    return res.json({ success: true, message: "Thiết bị đã được xóa khỏi danh sách!" });
  });
  
//API kiểm tra tên đăng nhập
let cachedUsernames = [];

async function loadUsernames() {
    try {
        const sheets = await getSheetsClient();
        const range = 'Accounts';
        const response = await sheets.spreadsheets.values.get({
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
        console.error("❌ Lỗi khi tải danh sách username:", error);
    }
}

// Tải danh sách username khi server khởi động
loadUsernames();

// API kiểm tra username
app.post('/api/check-username', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ exists: false, message: "Thiếu tên đăng nhập!" });
        }

        const isUsernameTaken = cachedUsernames.includes(username.trim().toLowerCase());

        return res.json({ exists: isUsernameTaken });
    } catch (error) {
        console.error("❌ Lỗi khi kiểm tra username:", error);
        return res.status(500).json({ exists: false, message: "Lỗi máy chủ!" });
    }
});

// Hàm kiểm tra định dạng email hợp lệ
function isValidEmail(email) {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(email);
}

//API đăng ký user
app.post('/api/register', async (req, res) => {
  logger.info('Request received for /api/register', { body: req.body });
  const { username, password, fullname, email, phone } = req.body;

  if (!username || !password || !fullname || !email || !phone) {
      return res.status(400).json({ success: false, message: "Vui lòng điền đầy đủ thông tin!" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Email không hợp lệ!" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
      const sheets = await getSheetsClient();
      
      // 🔹 Kiểm tra xem username đã tồn tại chưa
      const response = await sheets.spreadsheets.values.get({
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
      const newUser = [[username, hashedPassword, fullname, email, phone, "Chưa duyệt", today]];

      await sheets.spreadsheets.values.append({
          spreadsheetId: SPREADSHEET_ID,
          range,
          valueInputOption: "USER_ENTERED",
          resource: { values: newUser }
      });

      res.json({ success: true, message: "Đăng ký thành công! Thông báo phê duyệt tài khoản thành công sẽ được gửi tới email của bạn (có thể cần kiểm tra trong mục Spam)." });

  } catch (error) {
      clearTimeout(timeout);
      logger.error("Lỗi khi đăng ký tài khoản:", error);
      res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

const crypto = require("crypto");

//API gửi OTP đến email user
app.post('/api/send-otp', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://pedmed-vnch.web.app');
  logger.info('Request received for /api/send-otp', { body: req.body });

  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản!" });
  }

  try {
    logger.info(`Fetching user data for ${username}`);
    const sheets = await getSheetsClient();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await sheets.spreadsheets.values.get({
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
    return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

//API xác thực OTP
app.post('/api/verify-otp', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://pedmed-vnch.web.app');
  logger.info('Request received for /api/verify-otp', { body: req.body });

  const { username, otp } = req.body;
  if (!username || !otp) return res.status(400).json({ success: false, message: "Thiếu thông tin xác minh!" });

  try {
    const savedOtp = getOtp(username);
    if (!savedOtp) return res.status(400).json({ success: false, message: "OTP không hợp lệ hoặc đã hết hạn!" });

    if (savedOtp !== otp) return res.status(400).json({ success: false, message: "Mã OTP không đúng!" });

    deleteOtp(username);
    return res.json({ success: true, message: "Xác minh thành công, hãy đặt lại mật khẩu mới!" });
  } catch (error) {
    logger.error("❌ Lỗi khi xác minh OTP:", error);
    return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

//API cập nhật mật khẩu mới
app.post('/api/reset-password', async (req, res) => {
  logger.info('Request received for /api/reset-password', { body: req.body });
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
      return res.status(400).json({ success: false, message: "Vui lòng nhập đầy đủ thông tin!" });
  }

  try {
      const sheets = await getSheetsClient();
      const response = await sheets.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range: 'Accounts',
      });

      const rows = response.data.values;
      const headers = rows[0];
      const usernameIndex = headers.indexOf("Username");
      const passwordIndex = headers.indexOf("Password");
      const device1Index = headers.indexOf("Device_1");
      const device2Index = headers.indexOf("Device_2");

      if (usernameIndex === -1 || passwordIndex === -1 || device1Index === -1 || device2Index === -1) {
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
      range: `Accounts!B${userRowIndex + 1}`,
      valueInputOption: "RAW",
      resource: { values: [[hashedNewPassword]] }
    });

      // Xóa Device_1 & Device_2 nhưng giữ nguyên các cột khác
      await sheets.spreadsheets.values.update({
        spreadsheetId: SPREADSHEET_ID,
        range: `Accounts!I${userRowIndex + 1}:J${userRowIndex + 1}`, // Cột I & J chứa thiết bị
        valueInputOption: "RAW",
        resource: { values: [["", ""]] }
      });

      return res.json({ success: true, message: "Đổi mật khẩu thành công! Hãy đăng nhập lại." });

  } catch (error) {
      logger.error("❌ Lỗi khi cập nhật mật khẩu:", error);
      return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

// Middleware xử lý lỗi
app.use((err, req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://pedmed-vnch.web.app');
  logger.error('Unhandled error', { error: err.stack });
  res.status(500).json({ success: false, message: 'Lỗi máy chủ không xác định' });
});