# PassVault Pro – Python Password Manager (Tkinter + SQLite)

PassVault Pro is a simple, secure password manager built using Python, Tkinter, and SQLite.  
It uses a master password (protected with PBKDF2-HMAC-SHA256) and stores all data locally on your computer.  
The project works on any system with Python installed and does not require additional libraries except Tkinter.

---

## 🔐 Features

- Master password (PBKDF2-HMAC-SHA256 + salt)
- Add, edit, and delete password entries
- Search bar for quick filtering
- Built-in password generator
- Import and export passwords as CSV
- Clean Tkinter GUI
- Fully offline, local storage only

---

## 📦 Installation

1. Install Python 3.10 or later  
2. Download this repository  
3. Install Tkinter if required:

    pip install tk


4. Run the program (note the quotes because the filename contains spaces):
    
    python "PassVault Pro.py"


---

## 📁 Project Structure

PassVault Pro.py # Main Python application
requirements.txt # Tkinter dependency
.gitignore # Ignore cache + database file
README.md # Project documentation


---

## 🛡 Security Notes

- Master password hashed using PBKDF2-HMAC-SHA256
- Random salt for master password storage
- Passwords stored locally in an SQLite database
- No networking, no cloud storage, nothing leaves your device

---

## 📜 License

This project is provided for educational use.  
Feel free to improve or extend it.
