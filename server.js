const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Đường dẫn đến file JSON chứa thông tin đăng nhập
const SERVICE_ACCOUNT_FILE = path.join(__dirname, 'vietanhprojects-a9f573862a83.json');

// ID của Google Sheet
const SPREADSHEET_ID = '1mDJIil1rmEXEl7tV5qq3j6HkbKe1padbPhlQMiYaq9U';

// Khởi tạo Google Sheets API client
const auth = new google.auth.GoogleAuth({
  credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS),
  scopes: ['https://www.googleapis.com/auth/spreadsheets'],
});

const sheets = google.sheets({ version: 'v4', auth });

// API lấy dữ liệu từ Google Sheets
app.get('/api/drugs', async (req, res) => {
  try {
    const range = 'pedmedvnch'; // Tên sheet chứa dữ liệu
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(404).send('Không có dữ liệu trong Google Sheet.');
    }

    const headers = rows[0];
    const data = rows.map(row => row); // Trả về mảng con từ Google Sheets
    res.json(data);
  } catch (error) {
    console.error('Lỗi khi lấy dữ liệu từ Google Sheets:', error);
    res.status(500).send('Không thể lấy dữ liệu.');
  }
});

// API kiểm tra đăng nhập
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const range = 'Accounts'; // Tên sheet chứa tài khoản
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(404).send('Không có dữ liệu tài khoản.');
    }

    const headers = rows[0]; // Lấy hàng tiêu đề
    const usernameIndex = headers.indexOf("Username");
    const passwordIndex = headers.indexOf("Password");
    const approvedIndex = headers.indexOf("Approved");

    if (usernameIndex === -1 || passwordIndex === -1 || approvedIndex === -1) {
      return res.status(500).send('Lỗi cấu trúc dữ liệu trong Google Sheets.');
    }

    const accounts = rows.slice(1);
    const user = accounts.find(row => {
      const [sheetUsername, sheetPassword] = row;
      return (
        sheetUsername?.trim() === username?.trim() &&
        sheetPassword?.trim() === password?.trim()
      );
    });

    if (!user) {
      return res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu!" });
    }

    if (user[approvedIndex]?.trim() !== "Đã duyệt") {
      return res.json({ success: false, message: "Tài khoản chưa được phê duyệt bởi quản trị viên." });
    }

  } catch (error) {
    console.error('Lỗi khi kiểm tra tài khoản:', error);
    res.status(500).send('Lỗi máy chủ.');
  }
});

//API đăng ký user
app.post('/api/register', async (req, res) => {
  const { username, password, fullname, email, phone } = req.body;

  if (!username || !password || !fullname || !email || !phone) {
    return res.status(400).json({ success: false, message: "Vui lòng điền đầy đủ thông tin!" });
  }

  try {
    const range = 'Accounts'; // Sheet chứa tài khoản
    const newUser = [[username, password, fullname, email, phone, "Chưa duyệt"]];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SPREADSHEET_ID,
      range,
      valueInputOption: "USER_ENTERED",
      resource: { values: newUser }
    });

    res.json({ success: true, message: "Đăng ký thành công! Chờ quản trị viên phê duyệt." });
  } catch (error) {
    console.error("Lỗi khi đăng ký tài khoản:", error);
    res.status(500).json({ success: false, message: "Lỗi máy chủ!" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
