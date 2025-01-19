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
  keyFile: SERVICE_ACCOUNT_FILE,
  scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
});
const sheets = google.sheets({ version: 'v4', auth });

// API lấy dữ liệu từ Google Sheets
app.get('/api/drugs', async (req, res) => {
  try {
    const range = 'Sheet1'; // Tên sheet chứa dữ liệu
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(404).send('Không có dữ liệu trong Google Sheet.');
    }

    const headers = rows[0];
    const data = rows.slice(1).map(row => {
      const item = {};
      headers.forEach((header, index) => {
        item[header] = row[index] || '';
      });
      return item;
    });

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

    const accounts = rows.slice(1);
    const user = accounts.find(row => {
      const [sheetUsername, sheetPassword] = row;
      return (
        sheetUsername?.trim() === username?.trim() &&
        sheetPassword?.trim() === password?.trim()
      );
    });

    if (user) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu!" });
    }
  } catch (error) {
    console.error('Lỗi khi kiểm tra tài khoản:', error);
    res.status(500).send('Lỗi máy chủ.');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
