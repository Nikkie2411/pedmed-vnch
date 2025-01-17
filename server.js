const express = require('express');
const cors = require('cors');
const xlsx = require('xlsx');
const path = require('path');

const app = express();
app.use(cors()); // Cho phép kết nối từ frontend

// Đường dẫn chính xác tới file Excel
const FILE_PATH = path.join(__dirname, 'PedMed2025.xlsx');

// API lấy dữ liệu danh sách thuốc
app.get('/api/drugs', (req, res) => {
  try {
    const workbook = xlsx.readFile(FILE_PATH);
    const sheet = workbook.Sheets[workbook.SheetNames[0]]; // Sheet đầu tiên
    const data = xlsx.utils.sheet_to_json(sheet); // Chuyển đổi sang JSON
    res.json(data); // Trả về dữ liệu JSON
  } catch (error) {
    console.error('Lỗi khi đọc file Excel:', error);
    res.status(500).send('Lỗi khi đọc dữ liệu.');
  }
});

// API kiểm tra đăng nhập
app.get('/api/login', (req, res) => {
  const username = req.query.username;
  const password = req.query.password;

  try {
    const workbook = xlsx.readFile(FILE_PATH);
    const sheet = workbook.Sheets['Accounts']; // Tên sheet phải trùng với trong file Excel
    const accounts = xlsx.utils.sheet_to_json(sheet);

    const user = accounts.find(
      account =>
        account.Username?.toString().trim() === username?.trim() &&
        account.Password?.toString().trim() === password?.trim()
    );

    if (user) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  } catch (error) {
    console.error('Lỗi khi xử lý đăng nhập:', error);
    res.status(500).send('Lỗi server.');
  }
});

// Chạy server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
