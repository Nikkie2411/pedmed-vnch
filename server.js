const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');

const app = express();
app.use(cors({
  origin: "https://pedmed-vnch.web.app", // Chỉ cho phép từ frontend này
  methods: "GET,POST,PUT,DELETE",
  allowedHeaders: "Content-Type,Authorization"
}));
app.use(express.json());

// ID của Google Sheet
const SPREADSHEET_ID = '1mDJIil1rmEXEl7tV5qq3j6HkbKe1padbPhlQMiYaq9U';

// Khởi tạo Google Sheets API client
const auth = new google.auth.GoogleAuth({
  credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS),
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

async function getSheetsClient() {
  const authClient = await auth.getClient();
  return google.sheets({ version: 'v4', auth: authClient });
}

async function getAccessToken() {
  console.log("🔄 Đang lấy Access Token...");

  try {
      const refreshToken = process.env.REFRESH_TOKEN;
      const clientId = process.env.CLIENT_ID;
      const clientSecret = process.env.CLIENT_SECRET;

      if (!refreshToken || !clientId || !clientSecret) {
          throw new Error("Thiếu thông tin OAuth (REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET) trong môi trường!");
      }

      console.log(`📌 Dùng Client ID: ${clientId}`);

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
      console.log("📌 Phản hồi từ Google khi lấy Access Token:", json);

      if (!response.ok) {
          throw new Error(`Lỗi khi lấy Access Token: ${json.error}`);
      }

      console.log("✅ Access Token lấy thành công!");
      return json.access_token;
  } catch (error) {
      console.error("❌ Lỗi khi lấy Access Token:", error.message);
  }
}

const fetch = require('node-fetch'); // Nếu bạn dùng node-fetch để gửi request

// 📧 Hàm gửi email bằng Gmail API
async function sendEmailWithGmailAPI(toEmail, subject, body) {
    console.log(`📧 Chuẩn bị gửi email đến: ${toEmail}`);

    try {
        console.log("🔄 Đang lấy Access Token...");
        const accessToken = await getAccessToken();
        console.log(`✅ Lấy được Access Token: ${accessToken ? "Thành công" : "Không có Access Token"}`);

        if (!accessToken) {
            throw new Error("Không thể lấy Access Token!");
        }
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
        
        console.log("📤 Gửi request tới Gmail API...");
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
            console.error("❌ Lỗi gửi email:", result);
            throw new Error(`Lỗi gửi email: ${result.error.message}`);
        }

        console.log("✅ Email đã gửi thành công:", result);
    } catch (error) {
        console.error("❌ Lỗi khi gửi email:", error.message);
    }
}

// API lấy dữ liệu từ Google Sheets
app.get('/api/drugs', async (req, res) => {
  try {
    const sheets = await getSheetsClient();
    const range = 'pedmedvnch'; // Tên sheet chứa dữ liệu
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(404).send('Không có dữ liệu trong Google Sheet.');
    }

    const data = rows.map(row => row); // Trả về mảng con từ Google Sheets
    res.json(data);
  } catch (error) {
    console.error('Lỗi khi lấy dữ liệu từ Google Sheets:', error);
    res.status(500).send('Không thể lấy dữ liệu.');
  }
});

// API kiểm tra đăng nhập
app.post('/api/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  console.log("📌 Nhận yêu cầu đăng nhập:", { username, password, deviceId });

  try {
    const sheets = await getSheetsClient();
    const range = 'Accounts'; // Tên sheet chứa tài khoản
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
        return res.status(404).send('Không có dữ liệu tài khoản.');
    }

    const headers = rows[0];
    const usernameIndex = headers.indexOf("Username");
    const passwordIndex = headers.indexOf("Password");
    const approvedIndex = headers.indexOf("Approved");
    const device1Index = headers.indexOf("Device_1");
    const device2Index = headers.indexOf("Device_2");

    if (usernameIndex === -1 || passwordIndex === -1 || approvedIndex === -1) {
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const userRowIndex = rows.findIndex(row => row[usernameIndex] === username);
    if (userRowIndex === -1) {
      console.log("❌ Sai tài khoản hoặc mật khẩu!");
      return res.json({ success: false, message: "Tài khoản hoặc mật khẩu chưa đúng!" });
    }

    const user = rows[userRowIndex];

    // 🔹 Kiểm tra mật khẩu
    if (user[passwordIndex]?.trim() !== password.trim()) {
      console.log("❌ Sai mật khẩu!");
      return res.json({ success: false, message: "Tài khoản hoặc mật khẩu chưa đúng!" });
    }

    // 🔹 Kiểm tra trạng thái "Đã duyệt"
    if (user[approvedIndex]?.trim().toLowerCase() !== "đã duyệt") {
      console.log("⚠️ Tài khoản chưa được phê duyệt!");
      return res.json({ success: false, message: "Tài khoản chưa được phê duyệt bởi quản trị viên." });
    }

    let currentDevices = [user[device1Index], user[device2Index]].filter(Boolean);
    console.log(`📌 Danh sách thiết bị hiện tại của ${username}: ${currentDevices}`);

    if (currentDevices.includes(deviceId)) {
        return res.json({ success: true, message: "Đăng nhập thành công!" });
    }

    if (currentDevices.length >= 2) {
        return res.json({
            success: false,
            message: "Tài khoản đã đăng nhập trên 2 thiết bị. Vui lòng chọn thiết bị cần đăng xuất.",
            devices: currentDevices
        });
    }

    currentDevices.push(deviceId);
    currentDevices = currentDevices.slice(-2);

    console.log(`📌 Cập nhật thiết bị mới cho ${username}: ${currentDevices}`);

    await sheets.spreadsheets.values.update({
        spreadsheetId: SPREADSHEET_ID,
        range: `Accounts!I${userRowIndex + 1}:J${userRowIndex + 1}`,
        valueInputOption: "RAW",
        resource: { values: [currentDevices] }
    });

    return res.json({ success: true, message: "Đăng nhập thành công và thiết bị đã được lưu!" });

} catch (error) {
    console.error('Lỗi khi kiểm tra tài khoản:', error);
    return res.status(500).send('Lỗi máy chủ.');
}
});

//API kiểm tra trạng thái đã duyệt
app.post('/api/check-session', async (req, res) => {
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
    const device1Index = headers.indexOf("Device_1");
    const device2Index = headers.indexOf("Device_2");

    if (usernameIndex === -1 || approvedIndex === -1 || device1Index === -1 || device2Index === -1) {
      console.log("Lỗi: Không tìm thấy cột Username, Approved hoặc Device");
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
    const currentDevices = [user[device1Index], user[device2Index]].filter(Boolean);
    console.log(`📌 Danh sách thiết bị hợp lệ: ${currentDevices}`);

    if (!currentDevices.includes(deviceId)) {
      console.log("⚠️ Thiết bị không còn hợp lệ, cần đăng xuất!");
      return res.json({ success: false, message: "Thiết bị của bạn đã bị đăng xuất!" });
    }

    res.json({ success: true });

  } catch (error) {
    console.error("❌ Lỗi khi kiểm tra trạng thái tài khoản:", error);
    res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

app.post('/api/logout-device', async (req, res) => {
  try {
      const { username, deviceId, newDeviceId } = req.body;

      if (!username || !deviceId || !newDeviceId) {
          return res.status(400).json({ success: false, message: "Thiếu thông tin cần thiết" });
      }

      const sheets = await getSheetsClient();
      const range = 'Accounts';
      const response = await sheets.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range,
      });

      const rows = response.data.values;
      const headers = rows[0];
      const usernameIndex = headers.indexOf("Username");
      const device1Index = headers.indexOf("Device_1");
      const device2Index = headers.indexOf("Device_2");

      const userRowIndex = rows.findIndex(row => row[usernameIndex] === username);
      if (userRowIndex === -1) {
          return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản" });
      }

      let devices = [rows[userRowIndex][device1Index], rows[userRowIndex][device2Index]].filter(Boolean);

      devices = devices.filter(id => id !== deviceId); // Xóa thiết bị đã chọn
      devices.push(newDeviceId);

      await sheets.spreadsheets.values.update({
          spreadsheetId: SPREADSHEET_ID,
          range: `Accounts!I${userRowIndex + 1}:J${userRowIndex + 1}`,
          valueInputOption: "RAW",
          resource: { values: [devices] }
      });

      return res.json({ success: true, message: "Đăng xuất thành công!" });

    } catch (error) {
      console.error('Lỗi khi đăng xuất thiết bị:', error);
      return res.status(500).json({ success: false, message: "Lỗi máy chủ" });
    }
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
  const { username, password, fullname, email, phone } = req.body;

  if (!username || !password || !fullname || !email || !phone) {
      return res.status(400).json({ success: false, message: "Vui lòng điền đầy đủ thông tin!" });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Email không hợp lệ!" });
  }

  try {
      const sheets = await getSheetsClient();
      const range = 'Accounts';
      
      // 🔹 Kiểm tra xem username đã tồn tại chưa
      const response = await sheets.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range,
      });

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
      const isEmailTaken = accounts.some(row => row[emailIndex]?.trim() === email.trim());

      if (isTaken) {
          return res.json({ success: false, message: "Tên đăng nhập không hợp lệ!" });
      }

      if (isEmailTaken) {
        return res.json({ success: false, message: "Email đã được sử dụng!" });
      }

      // 🔹 Thêm cột Date (ngày đăng ký)
      const today = new Date().toISOString().split("T")[0]; // Lấy ngày hiện tại YYYY-MM-DD
      const newUser = [[username, password, fullname, email, phone, "Chưa duyệt", today]];

      await sheets.spreadsheets.values.append({
          spreadsheetId: SPREADSHEET_ID,
          range,
          valueInputOption: "USER_ENTERED",
          resource: { values: newUser }
      });

      res.json({ success: true, message: "Đăng ký thành công! Thông báo phê duyệt tài khoản thành công sẽ được gửi tới email của bạn (có thể cần kiểm tra trong mục Spam)." });

  } catch (error) {
      console.error("Lỗi khi đăng ký tài khoản:", error);
      res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

const crypto = require("crypto");

// Lưu OTP tạm thời (sẽ mất đi khi server restart)
const otpStore = new Map(); 

//API gửi OTP đến email user
app.post('/api/send-otp', async (req, res) => {
  const { username } = req.body;

  console.log("📌 Nhận yêu cầu gửi OTP từ:", username);

  if (!username) {
      console.log("❌ Thiếu username trong request!");
      return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản!" });
  }

  try {
      console.log(`📌 Kiểm tra tài khoản: ${username}`);
      const sheets = await getSheetsClient();
      const range = 'Accounts';
      const response = await sheets.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range,
      });

      if (!response || !response.data || !response.data.values) {
          console.log("❌ Không lấy được dữ liệu từ Google Sheets!");
          return res.status(500).json({ success: false, message: "Lỗi lấy dữ liệu tài khoản!" });
      }

      console.log("✅ Dữ liệu từ Google Sheets:", response.data.values);

      const rows = response.data.values;
      const headers = rows[0];
      const usernameIndex = headers.indexOf("Username");
      const emailIndex = headers.indexOf("Email");

      if (usernameIndex === -1 || emailIndex === -1) {
          console.log("❌ Không tìm thấy cột Username hoặc Email!");
          return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
      }

      const user = rows.find(row => row[usernameIndex]?.trim() === username.trim());

      if (!user) {
          console.log("❌ Không tìm thấy tài khoản!");
          return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản!" });
      }

      const userEmail = user[emailIndex];
      if (!userEmail || !userEmail.includes("@")) {
          console.log(`❌ Email không hợp lệ: ${userEmail}`);
          return res.status(400).json({ success: false, message: "Email không hợp lệ!" });
      }

      // 🔹 Tạo mã OTP 6 số ngẫu nhiên
      const otpCode = Math.floor(100000 + Math.random() * 900000);
      console.log(`📌 Mã OTP cho ${username}: ${otpCode}`);

      otpStore.set(username, otpCode); // Lưu OTP tạm thời

      // 🔹 Gửi email
      try {
          sendEmailWithGmailAPI(userEmail, "MÃ XÁC NHẬN ĐỔI MẬT KHẨU", `
              <h2 style="color: #4CAF50;">Xin chào ${username}!</h2>
              <p style="font-weight: bold">Mã xác nhận đổi mật khẩu của bạn là: 
              <h3 style="font-weight: bold">${otpCode}</h3></p>
              <p>Vui lòng nhập ngay mã này vào trang web để tiếp tục đổi mật khẩu.</p>
              <p>Cảm ơn bạn đã sử dụng dịch vụ của chúng tôi!</p>
          `);
      } catch (emailError) {
          console.log("❌ Lỗi khi gửi email:", emailError);
          return res.status(500).json({ success: false, message: "Lỗi khi gửi email!" });
      }

      return res.json({ success: true, message: "Mã xác nhận đã được gửi đến email của bạn!" });

  } catch (error) {
      console.error("❌ Lỗi máy chủ khi gửi OTP:", error);
      return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

//API xác thực OTP
app.post('/api/verify-otp', async (req, res) => {
  const { username, otp } = req.body;

  console.log(`📌 Nhận yêu cầu xác minh OTP - Username: ${username}, OTP: ${otp}`);

  if (!username || !otp) {
      console.log("❌ Thiếu username hoặc OTP trong request!");
      return res.status(400).json({ success: false, message: "Thiếu thông tin xác minh!" });
  }

  try {
      // Kiểm tra OTP đã lưu
      const savedOtp = otpStore.get(username);
      console.log(`🔍 OTP lưu trong hệ thống: ${savedOtp}`);

      if (!savedOtp) {
          console.log("❌ OTP không hợp lệ hoặc đã hết hạn!");
          return res.status(400).json({ success: false, message: "OTP không hợp lệ hoặc đã hết hạn!" });
      }

      if (savedOtp !== parseInt(otp)) {
          console.log("❌ OTP nhập vào không khớp!");
          return res.status(400).json({ success: false, message: "Mã OTP không đúng!" });
      }

      // Nếu OTP đúng, xóa OTP khỏi hệ thống
      otpStore.delete(username);

      console.log("✅ Xác minh OTP thành công!");
      return res.json({ success: true, message: "Xác minh thành công, hãy đặt lại mật khẩu mới!" });

  } catch (error) {
      console.error("❌ Lỗi khi xác minh OTP:", error);
      return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

//API cập nhật mật khẩu mới
app.post('/api/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;
  console.log(`📌 Nhận yêu cầu đổi mật khẩu - Username: ${username}`);

  if (!username || !newPassword) {
      console.log("❌ Thiếu thông tin đổi mật khẩu!");
      return res.status(400).json({ success: false, message: "Vui lòng nhập đầy đủ thông tin!" });
  }

  try {
      const sheets = await getSheetsClient();
      const range = 'Accounts';
      const response = await sheets.spreadsheets.values.get({
          spreadsheetId: SPREADSHEET_ID,
          range,
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

      const oldPassword = rows[userRowIndex][passwordIndex];
      console.log(`🔍 Mật khẩu cũ: ${oldPassword}`);

      if (newPassword === oldPassword) {
          console.log("❌ Mật khẩu mới không được trùng với mật khẩu cũ!");
          return res.status(400).json({ success: false, message: "Mật khẩu mới không được giống mật khẩu cũ!" });
      }

      // Cập nhật mật khẩu mới & Xóa thiết bị trong Google Sheets
      await sheets.spreadsheets.values.update({
          spreadsheetId: SPREADSHEET_ID,
          range: `Accounts!B${userRowIndex + 1}`, // Cột B chứa mật khẩu
          valueInputOption: "RAW",
          resource: { values: [[newPassword, "", "", "", "", "", "", ""]] } // Xóa Device_1 & Device_2
      });

      console.log("✅ Mật khẩu đã cập nhật thành công!");
      console.log("📌 Xóa toàn bộ thiết bị đăng nhập!");
      return res.json({ success: true, message: "Đổi mật khẩu thành công! Hãy đăng nhập lại." });

  } catch (error) {
      console.error("❌ Lỗi khi cập nhật mật khẩu:", error);
      return res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
