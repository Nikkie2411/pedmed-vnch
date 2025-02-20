const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const path = require('path');

const app = express();
app.use(cors({
  origin: "https://pedmed-vnch.web.app", // Chỉ cho phép từ frontend này
  methods: "GET,POST,PUT,DELETE",
  allowedHeaders: "Content-Type,Authorization"
}));
app.use(express.json());

const os = require("os");
const { v4: uuidv4 } = require("uuid");

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
          sendEmailWithGmailAPI(userEmail, "Mã xác nhận đổi mật khẩu", `
              <p>Xin chào ${username},</p>
              <p>Mã xác nhận đổi mật khẩu của bạn là: <b>${otpCode}</b></p>
              <p>Vui lòng nhập mã này vào trang web để tiếp tục đổi mật khẩu.</p>
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
app.post('/api/verify-otp', (req, res) => {
  const { username, otp } = req.body;

  if (!username || !otp) {
      return res.status(400).json({ success: false, message: "Thiếu thông tin xác nhận!" });
  }

  const storedOtp = otpStore.get(username);

  if (!storedOtp || storedOtp !== parseInt(otp, 10)) {
      return res.json({ success: false, message: "Mã xác nhận không đúng hoặc đã hết hạn!" });
  }

  otpStore.delete(username); // Xóa OTP sau khi dùng
  res.json({ success: true, message: "Mã xác nhận hợp lệ!" });
});

//API cập nhật mật khẩu mới
app.post('/api/reset-password', async (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
      return res.status(400).json({ success: false, message: "Thiếu thông tin mật khẩu!" });
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

      if (usernameIndex === -1 || passwordIndex === -1) {
          return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
      }

      const userRowIndex = rows.findIndex(row => row[usernameIndex]?.trim() === username.trim());

      if (userRowIndex === -1) {
          return res.json({ success: false, message: "Không tìm thấy tài khoản!" });
      }

      await sheets.spreadsheets.values.update({
          spreadsheetId: SPREADSHEET_ID,
          range: `Accounts!B${userRowIndex + 1}`, // Cột B chứa mật khẩu
          valueInputOption: "RAW",
          resource: { values: [[newPassword]] }
      });

      res.json({ success: true, message: "Mật khẩu đã được cập nhật thành công!" });

  } catch (error) {
      console.error("❌ Lỗi khi cập nhật mật khẩu:", error);
      res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
