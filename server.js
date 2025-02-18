const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const path = require('path');

const app = express();
app.use(cors());
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
  console.log("Yêu cầu đăng nhập:", { username, password }); // Debug

  try {
    const sheets = await getSheetsClient();
    const range = 'Accounts'; // Tên sheet chứa tài khoản
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    console.log("Dữ liệu từ Google Sheets:", response.data.values); // Debug

    if (!response || !response.data || !response.data.values) {
      console.error("Không lấy được dữ liệu từ Google Sheets!");
      return res.status(500).json({ success: false, message: "Lỗi lấy dữ liệu tài khoản!" });
    }

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(404).send('Không có dữ liệu tài khoản.');
    }

    const headers = rows[0]; // Lấy hàng tiêu đề
    const usernameIndex = headers.indexOf("Username");
    const passwordIndex = headers.indexOf("Password");
    const approvedIndex = headers.indexOf("Approved");
    const device1Index = headers.indexOf("Device_1");
    const device2Index = headers.indexOf("Device_2");

    if (usernameIndex === -1 || passwordIndex === -1 || approvedIndex === -1 || device1Index === -1 || device2Index === -1) {
      console.error("Cột dữ liệu không tồn tại trong Google Sheets.");
      return res.status(500).send('Lỗi cấu trúc dữ liệu trong Google Sheets.');
    }

    const accounts = rows.slice(1);
    const user = accounts.find(row => {
      return row[usernameIndex]?.trim() === username?.trim() &&
              row[passwordIndex]?.trim() === password?.trim()
    });

    if (!user) {
      console.log("Tài khoản hoặc mật khẩu không đúng.");
      return res.json({ success: false, message: "Tài khoản hoặc mật khẩu không đúng!" });
    }

    // In trạng thái phê duyệt ra console để debug
    console.log(`Tài khoản: ${username} - Trạng thái: ${user[approvedIndex]}`); // Debug

    if (user[approvedIndex]?.trim().toLowerCase() !== "đã duyệt") {
      console.log("Tài khoản chưa được duyệt.");
      return res.json({ success: false, message: "Tài khoản chưa được phê duyệt bởi quản trị viên." });
    }

    const currentDevices = [user[device1Index], user[device2Index]].filter(Boolean);

    if (currentDevices.includes(deviceId)) {
        return res.json({ success: true, message: "Đăng nhập thành công!" });
    }

    if (currentDevices.length >= 2) {
        return res.json({ success: false, message: "Tài khoản đã đăng nhập trên 2 thiết bị. Hãy đăng xuất 1 thiết bị trước!" });
    }

    // Cập nhật Google Sheets để lưu thiết bị mới
    const newDevices = [...currentDevices, deviceId].slice(-2);
    const userRowIndex = rows.findIndex(row => row[usernameIndex] === username) + 1;

    console.log(`📌 Cập nhật thiết bị cho user: ${username} tại hàng ${userRowIndex + 1}`);
    console.log(`📌 Thiết bị mới: ${newDevices}`);

    await sheets.spreadsheets.values.update({
        spreadsheetId: SPREADSHEET_ID,
        range: `Accounts!${String.fromCharCode(65 + device1Index)}${userRowIndex + 1}:${String.fromCharCode(65 + device2Index)}${userRowIndex + 1}`,
        valueInputOption: "RAW",
        resource: { values: [newDevices] }
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Lỗi khi kiểm tra tài khoản:', error.response ? error.response.data : error.message);
    res.status(500).json({ success: false, message: error.message || "Lỗi máy chủ!" });
  }
});

//API kiểm tra trạng thái đã duyệt
app.post('/api/check-session', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    console.log("Lỗi: Không có tên đăng nhập");
    return res.status(400).json({ success: false, message: "Thiếu thông tin tài khoản!" });
  }

  try {
    console.log("Kiểm tra trạng thái tài khoản của:", username);
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

    if (usernameIndex === -1 || approvedIndex === -1) {
      console.log("Lỗi: Không tìm thấy cột Username hoặc Approved");
      return res.status(500).json({ success: false, message: "Lỗi cấu trúc Google Sheets!" });
    }

    const accounts = rows.slice(1);
    const user = accounts.find(row => row[usernameIndex]?.trim() === username.trim());

    if (!user) {
      console.log("Tài khoản không tồn tại!");
      return res.json({ success: false, message: "Tài khoản không tồn tại!" });
    }

    console.log(`Trạng thái tài khoản: ${user[approvedIndex]}`);

    if (!user[approvedIndex] || user[approvedIndex]?.trim().toLowerCase() !== "đã duyệt") {
      console.log("Tài khoản bị hủy duyệt, cần đăng xuất!");
      return res.json({ success: false, message: "Tài khoản đã bị hủy duyệt!" });
    }

    res.json({ success: true });

  } catch (error) {
    console.error("Lỗi khi kiểm tra trạng thái tài khoản:", error);
    res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

app.post('/api/logout-device', async (req, res) => {
  const { username, deviceId } = req.body;

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
      const device1Index = headers.indexOf("Device_1");
      const device2Index = headers.indexOf("Device_2");

      const userRowIndex = rows.findIndex(row => row[usernameIndex] === username) + 1;
      let currentDevices = [rows[userRowIndex][device1Index], rows[userRowIndex][device2Index]].filter(Boolean);

      if (!currentDevices.includes(deviceId)) {
          return res.json({ success: false, message: "Thiết bị này không đăng nhập vào tài khoản này!" });
      }

      currentDevices = currentDevices.filter(id => id !== deviceId);

      await sheets.spreadsheets.values.update({
          spreadsheetId: SPREADSHEET_ID,
          range: `Accounts!D${userRowIndex}:E${userRowIndex}`,
          valueInputOption: "RAW",
          resource: { values: [currentDevices] }
      });

      return res.json({ success: true, message: "Đã đăng xuất thiết bị thành công!" });

  } catch (error) {
      console.error('Lỗi khi đăng xuất thiết bị:', error);
      return res.status(500).send('Lỗi máy chủ.');
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
