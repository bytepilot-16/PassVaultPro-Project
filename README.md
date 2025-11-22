<p align="center">

  <!-- Python version -->
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">

  <!-- Tkinter -->
  <img src="https://img.shields.io/badge/GUI-Tkinter-FF9800?logo=windowsterminal&logoColor=white">

  <!-- SQLite -->
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white">

  <!-- Offline -->
  <img src="https://img.shields.io/badge/Offline-100%25-success?logo=linux&logoColor=white">

  <!-- License -->
  <img src="https://img.shields.io/badge/License-Educational-blue">

</p>
# PassVault Pro – Python Password Manager (Tkinter + SQLite)

**PassVault Pro** is a lightweight, offline password manager built using Python, Tkinter, and SQLite.  
It uses a master password (secured with PBKDF2-HMAC-SHA256 + salt) to protect access and offers a clean, functional GUI for managing your passwords locally.

The application is completely self-contained and requires no external services or online connectivity.

---

## 🔐 Features

- Master password protection  
- PBKDF2-HMAC-SHA256 hashing with unique salt  
- Add, edit, delete password entries  
- Search bar for quick filtering  
- Built-in password generator  
- Import and export entries as CSV  
- Clean, responsive Tkinter interface  
- 100% offline — all data stays on your device  

---

## 📦 Installation

1. Install **Python 3.10 or later**  
2. Download or clone this repository  
3. (Optional) Install Tkinter if not already present:

```bash
pip install tk
```

4. Run the application:

```bash
python "PassVault Pro.py"
```

---

## 📁 Project Structure

```
PassVault Pro.py                 # Main application
Technical Definitions for Imports.md   # Detailed import/module explanations
Screenshots.md                   # Output screenshots (ordered)
requirements.txt                 # Dependency list (Tkinter)
.gitignore                       # DB file, cache files ignored
README.md                        # Project documentation
```

---

## 🛠 How It Works (Short Summary)

- The master password is hashed using **PBKDF2-HMAC-SHA256** with a 16-byte salt and 120k iterations.  
- All entries (site, username, password, notes, timestamp) are stored inside a local **SQLite database**.  
- Passwords are displayed masked unless the "Show Passwords" toggle is enabled.  
- The built-in generator can create strong passwords with adjustable length and character sets.  
- Import/export functionality allows moving data between devices using standard **CSV** files.

For a deeper technical explanation, refer to:

👉 **Technical Definitions for Imports.md**

---

## 🖼 Screenshots

A full screenshot gallery showing all windows (login, main panel, add/edit entry, generator, export dialog, etc.) is available in:

👉 **Screenshots.md**

---

## 🛡 Security Notes

- Master password is **never stored in plaintext**  
- Hashing uses PBKDF2-HMAC-SHA256 with secure random salt  
- The application is local-first and stores everything offline  
- CSV exports contain plaintext — handle them carefully  
- No external network operations are performed  

---

## 📜 License

This project is provided for educational and personal use.  
You may modify or extend it as needed.

