# PassVault Pro – Python Password Manager (Tkinter + SQLite)

A simple, secure, master-password protected password manager built using **Python**, **Tkinter**, and **SQLite**.  
This project requires *no external libraries* and runs on any PC with Python installed.

---

## 🔐 Features

- Master password (PBKDF2-HMAC-SHA256)
- Add / Edit / Delete password entries  
- Search entries
- Built-in password generator
- Import & Export passwords as CSV
- Clean Tkinter GUI
- SQLite local encrypted-like storage (hash + salt)
- No internet connection required

---

## 📦 Installation

1. Install Python 3.10+  
2. Download this repository  
3. Install Tkinter if needed:

pip install tk

markdown
Copy code

4. Run the program:

python password_manager_master.py

yaml
Copy code

---

## 📁 Files in this Project

PassVault Pro.py # Main application
requirements.txt # Dependencies (Tk only)
.gitignore # Ignore cache + DB
README.md # Project documentation

yaml
Copy code

---

## 🛡 Security

- Master password stored using PBKDF2-HMAC-SHA256 + random salt  
- Passwords stored locally in an SQLite database  
- Nothing is uploaded or shared online  
- Safe for offline school/college use

---

## 📜 License

This project is provided for **educational use**.  
Feel free to fork and improve!
