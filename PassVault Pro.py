# password_manager_master.py
"""
Password Manager with Master Login
- Single-file, no external libraries
- Master password stored via PBKDF2-HMAC-SHA256 + random salt
- SQLite DB: passwords + settings
- GUI: Tkinter + ttk, add/edit/delete/search/generate/copy/export/import
Save -> python password_manager_master.py
"""

import sqlite3
import os
import random
import string
import csv
import hashlib
import secrets
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

DB_FILE = "passwords_master.db"
# PBKDF2 parameters
PBKDF2_ITERS = 120_000
SALT_LEN = 16
KEY_LEN = 32

# ---------------- Utilities ----------------
def now_iso():
    return datetime.now(timezone.utc).isoformat(sep=" ", timespec="seconds")

def generate_password(length=16, use_upper=True, use_digits=True, use_punct=True):
    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_punct:
        chars += "!@#$%^&*()-_=+"
    while True:
        pw = "".join(random.choice(chars) for _ in range(length))
        if any(c.islower() for c in pw):
            if use_upper and not any(c.isupper() for c in pw):
                continue
            if use_digits and not any(c.isdigit() for c in pw):
                continue
            if use_punct and not any(c in "!@#$%^&*()-_=+" for c in pw):
                continue
            return pw

def _pbkdf2_hash(password: str, salt: bytes, iters=PBKDF2_ITERS, dklen=KEY_LEN):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen)

def _b64hex(b: bytes) -> str:
    return b.hex()

def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)

# ---------------- Database ----------------
def init_db():
    newdb = not os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            notes TEXT,
            date_added TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    if newdb:
        # seed tiny row so first-run UI is not empty
        c.execute("INSERT INTO passwords (site, username, password, notes, date_added) VALUES (?, ?, ?, ?, ?)",
                  ("example.com", "you@example.com", "password123", "Sample entry — replace me", now_iso()))
        conn.commit()
    return conn

# ---------------- Master password handling ----------------
def store_master_password(conn, password_plain: str):
    salt = secrets.token_bytes(SALT_LEN)
    digest = _pbkdf2_hash(password_plain, salt)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("master_salt", _b64hex(salt)))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("master_hash", _b64hex(digest)))
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("master_iters", str(PBKDF2_ITERS)))
    conn.commit()

def check_master_password(conn, password_plain: str) -> bool:
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = 'master_salt'")
    row = c.fetchone()
    if not row:
        return False
    salt = _unhex(row[0])
    c.execute("SELECT value FROM settings WHERE key = 'master_hash'")
    stored = c.fetchone()
    if not stored:
        return False
    stored_digest = _unhex(stored[0])
    # get iterations if stored (fallback to default)
    c.execute("SELECT value FROM settings WHERE key = 'master_iters'")
    it = c.fetchone()
    iters = int(it[0]) if it else PBKDF2_ITERS
    test_digest = hashlib.pbkdf2_hmac("sha256", password_plain.encode("utf-8"), salt, iters, len(stored_digest))
    return secrets.compare_digest(stored_digest, test_digest)

def has_master_password(conn) -> bool:
    c = conn.cursor()
    c.execute("SELECT 1 FROM settings WHERE key = 'master_hash' LIMIT 1")
    return c.fetchone() is not None

# ---------------- GUI App ----------------
class PasswordManagerMasterApp:
    def __init__(self, root):
        self.root = root
        self.conn = init_db()
        self.curs = self.conn.cursor()
        self.show_passwords = tk.BooleanVar(value=False)
        self._build_style()
        # block until master login success
        ok = self._master_auth_flow()
        if not ok:
            root.destroy()
            return
        self._build_ui()
        self.refresh_table()

    # ---- styling ----
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # clean light look
        style.configure("TFrame", background="#f5f5f5")
        style.configure("TLabel", background="#f5f5f5", foreground="#202020", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("TButton", padding=(6,4))
        style.configure("TEntry", fieldbackground="#ffffff")
        style.configure("TCombobox", fieldbackground="#ffffff")
        self.root.configure(bg="#f5f5f5")

    # ---- master login / setup ----
    def _master_auth_flow(self):
        """Return True if login OK, False cancel/failed."""
        if not has_master_password(self.conn):
            # ask to create a master password (twice)
            txt = ("No master password set.\nCreate one now. This will protect access to the app on this machine.\n"
                   )
            messagebox.showinfo("Set master password", txt)
            while True:
                p1 = simpledialog.askstring("Set Master Password", "Enter new master password (min 6 chars):", show="*")
                if p1 is None:
                    return False
                if len(p1) < 6:
                    messagebox.showwarning("Too short", "Use at least 6 characters.")
                    continue
                p2 = simpledialog.askstring("Confirm Password", "Confirm master password:", show="*")
                if p2 is None:
                    return False
                if p1 != p2:
                    messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
                    continue
                store_master_password(self.conn, p1)
                messagebox.showinfo("Saved", "Master password saved.")
                return True
        else:
            # ask to enter master password
            for attempt in range(5):
                p = simpledialog.askstring("Master Password", "Enter master password to unlock:", show="*")
                if p is None:
                    return False
                if check_master_password(self.conn, p):
                    return True
                else:
                    messagebox.showerror("Wrong", f"Wrong password. Attempts left: {4-attempt}")
            # too many failed attempts
            messagebox.showerror("Locked", "Too many failed attempts. Exiting.")
            return False

    # ---- UI build ----
    def _build_ui(self):
        self.root.title("Password Manager — Locked")
        pad = {"padx":8, "pady":6}

        # Top: search/add/export
        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(6,4))
        search_entry.bind("<Return>", lambda e: self.refresh_table())
        ttk.Button(top, text="Search", command=self.refresh_table).pack(side="left", padx=4)
        ttk.Button(top, text="Clear", command=lambda: (self.search_var.set(""), self.refresh_table())).pack(side="left", padx=4)
        ttk.Button(top, text="Add Entry", command=self.add_entry_dialog).pack(side="right", padx=4)
        ttk.Button(top, text="Import CSV", command=self.import_csv).pack(side="right", padx=4)
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="right", padx=4)

        # Table
        columns = ("id","site","username","password","notes","date")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col, label, w in (("id","ID",50), ("site","Site",200), ("username","Username",180),
                             ("password","Password",180), ("notes","Notes",250), ("date","Date Added",150)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=w, anchor="w" if col not in ("id","qcount") else "center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0,6))
        self.tree.bind("<Double-1>", lambda e: self.edit_selected())

        # Bottom controls
        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", **pad)
        ttk.Button(bottom, text="Edit Selected", command=self.edit_selected).pack(side="left")
        ttk.Button(bottom, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(bottom, text="Copy Password", command=self.copy_password).pack(side="left", padx=6)
        ttk.Button(bottom, text="Generate Password", command=self.generate_password_dialog).pack(side="right", padx=6)
        ttk.Checkbutton(bottom, text="Show passwords", variable=self.show_passwords, command=self.refresh_table).pack(side="right", padx=6)

        # Small status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, style="Subtle.TLabel").pack(fill="x", padx=8, pady=(0,6))

        # make window title show unlocked
        self.root.title("Password Manager — Unlocked")

    # ---- Table ops ----
    def refresh_table(self):
        q = "SELECT id, site, username, password, notes, date_added FROM passwords"
        s = self.search_var.get().strip()
        params = ()
        if s:
            q += " WHERE site LIKE ? OR username LIKE ? OR notes LIKE ?"
            pat = f"%{s}%"
            params = (pat, pat, pat)
        q += " ORDER BY site COLLATE NOCASE, id DESC"
        self.curs.execute(q, params)
        rows = self.curs.fetchall()
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in rows:
            rid, site, username, password, notes, date_added = row
            pw_display = password if self.show_passwords.get() else "*" * min(10, len(password))
            self.tree.insert("", "end", values=(rid, site, username, pw_display, notes or "", date_added))
        self.status_var.set(f"{len(rows)} entries")

    def add_entry_dialog(self):
        d = tk.Toplevel(self.root); d.title("Add Entry"); d.transient(self.root)
        frm = ttk.Frame(d, padding=8); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Site / App:").grid(row=0, column=0, sticky="w")
        site = tk.StringVar(); ttk.Entry(frm, textvariable=site, width=40).grid(row=0, column=1, pady=4)
        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="w")
        user = tk.StringVar(); ttk.Entry(frm, textvariable=user, width=40).grid(row=1, column=1, pady=4)
        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w")
        pw = tk.StringVar(); ttk.Entry(frm, textvariable=pw, width=40).grid(row=2, column=1, pady=4)
        ttk.Button(frm, text="Generate", command=lambda: pw.set(generate_password())).grid(row=2, column=2, padx=6)
        ttk.Label(frm, text="Notes:").grid(row=3, column=0, sticky="nw")
        notes = tk.Text(frm, height=4, width=40); notes.grid(row=3, column=1, pady=4)

        def submit():
            site_v = site.get().strip(); user_v = user.get().strip(); pw_v = pw.get().strip()
            notes_v = notes.get("1.0","end").strip() or None
            if not site_v or not user_v or not pw_v:
                messagebox.showerror("Missing", "Site, username and password are required.")
                return
            self.curs.execute("INSERT INTO passwords (site, username, password, notes, date_added) VALUES (?, ?, ?, ?, ?)",
                              (site_v, user_v, pw_v, notes_v, now_iso()))
            self.conn.commit()
            d.destroy()
            self.refresh_table()
            messagebox.showinfo("Saved", "Entry added.")
        ttk.Button(frm, text="Add", command=submit).grid(row=4, column=1, sticky="e", pady=6)

    def edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])['values']
        if not item:
            return
        rid = item[0]
        self.curs.execute("SELECT site, username, password, notes FROM passwords WHERE id = ?", (rid,))
        r = self.curs.fetchone()
        if not r:
            messagebox.showerror("Not found", "Entry no longer exists.")
            self.refresh_table()
            return
        site_v, user_v, pw_v, notes_v = r
        d = tk.Toplevel(self.root); d.title("Edit Entry"); d.transient(self.root)
        frm = ttk.Frame(d, padding=8); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Site / App:").grid(row=0, column=0, sticky="w")
        site = tk.StringVar(value=site_v); ttk.Entry(frm, textvariable=site, width=40).grid(row=0, column=1, pady=4)
        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="w")
        user = tk.StringVar(value=user_v); ttk.Entry(frm, textvariable=user, width=40).grid(row=1, column=1, pady=4)
        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w")
        pw = tk.StringVar(value=pw_v); ttk.Entry(frm, textvariable=pw, width=40).grid(row=2, column=1, pady=4)
        ttk.Button(frm, text="Gen", command=lambda: pw.set(generate_password())).grid(row=2, column=2, padx=6)
        ttk.Label(frm, text="Notes:").grid(row=3, column=0, sticky="nw")
        notes = tk.Text(frm, height=4, width=40); notes.grid(row=3, column=1, pady=4)
        if notes_v:
            notes.insert("1.0", notes_v)
        def save():
            ns = site.get().strip(); nu = user.get().strip(); npw = pw.get().strip(); nnotes = notes.get("1.0","end").strip() or None
            if not ns or not nu or not npw:
                messagebox.showerror("Missing", "Site, username and password are required.")
                return
            self.curs.execute("UPDATE passwords SET site=?, username=?, password=?, notes=? WHERE id=?",
                              (ns, nu, npw, nnotes, rid))
            self.conn.commit()
            d.destroy()
            self.refresh_table()
            messagebox.showinfo("Saved", "Changes saved.")
        ttk.Button(frm, text="Save", command=save).grid(row=4, column=1, sticky="e", pady=6)

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])['values']
        if not item:
            return
        rid = item[0]
        if not messagebox.askyesno("Confirm", "Delete selected entry?"):
            return
        self.curs.execute("DELETE FROM passwords WHERE id = ?", (rid,))
        self.conn.commit()
        self.refresh_table()

    def copy_password(self):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0])['values']
        if not values:
            return
        rid = values[0]
        self.curs.execute("SELECT password FROM passwords WHERE id = ?", (rid,))
        r = self.curs.fetchone()
        if not r:
            return
        pw = r[0]
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Clipboard failed", f"Could not copy to clipboard: {e}")

    def generate_password_dialog(self):
        d = tk.Toplevel(self.root); d.title("Generate Password"); d.transient(self.root)
        frm = ttk.Frame(d, padding=8); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Length:").grid(row=0, column=0, sticky="w")
        length = tk.IntVar(value=16); ttk.Entry(frm, textvariable=length, width=6).grid(row=0, column=1, sticky="w")
        upper = tk.BooleanVar(value=True); ttk.Checkbutton(frm, text="Upper", variable=upper).grid(row=1, column=0, sticky="w")
        digits = tk.BooleanVar(value=True); ttk.Checkbutton(frm, text="Digits", variable=digits).grid(row=1, column=1, sticky="w")
        punct = tk.BooleanVar(value=True); ttk.Checkbutton(frm, text="Symbols", variable=punct).grid(row=2, column=0, sticky="w")
        out = tk.StringVar(); ttk.Entry(frm, textvariable=out, width=48).grid(row=3, column=0, columnspan=2, pady=6)
        def gen():
            ln = max(4, min(64, int(length.get())))
            out.set(generate_password(length=ln, use_upper=upper.get(), use_digits=digits.get(), use_punct=punct.get()))
        def copy_close():
            txt = out.get()
            if txt:
                try:
                    self.root.clipboard_clear(); self.root.clipboard_append(txt)
                except Exception:
                    pass
            d.destroy()
        ttk.Button(frm, text="Generate", command=gen).grid(row=4, column=0, sticky="w", pady=6)
        ttk.Button(frm, text="Copy & Close", command=copy_close).grid(row=4, column=1, sticky="e", pady=6)

    # ---- CSV import/export ----
    def export_csv(self):
        fpath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not fpath:
            return
        self.curs.execute("SELECT site, username, password, notes, date_added FROM passwords ORDER BY site COLLATE NOCASE")
        rows = self.curs.fetchall()
        try:
            with open(fpath, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["site","username","password","notes","date_added"])
                w.writerows(rows)
            messagebox.showinfo("Exported", f"Exported {len(rows)} rows to {fpath}")
        except Exception as e:
            messagebox.showerror("Export failed", f"Could not write CSV: {e}")

    def import_csv(self):
        fpath = filedialog.askopenfilename(title="Import CSV", filetypes=[("CSV","*.csv")])
        if not fpath:
            return
        added = 0
        try:
            with open(fpath, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    site = row.get("site") or row.get("Site") or ""
                    user = row.get("username") or row.get("Username") or ""
                    pw = row.get("password") or row.get("Password") or ""
                    notes = row.get("notes") or row.get("Notes") or None
                    if not site or not user or not pw:
                        continue
                    self.curs.execute("INSERT INTO passwords (site, username, password, notes, date_added) VALUES (?, ?, ?, ?, ?)",
                                      (site.strip(), user.strip(), pw.strip(), notes.strip() if notes else None, now_iso()))
                    added += 1
            self.conn.commit()
            messagebox.showinfo("Imported", f"Imported {added} questions.")
            self.refresh_table()
        except Exception as e:
            messagebox.showerror("Import failed", f"Error importing CSV: {e}")

    def stop(self):
        try:
            self.conn.close()
        except Exception:
            pass

# ---------------- Run ----------------
def main():
    root = tk.Tk()
    app = PasswordManagerMasterApp(root)
    # If master auth failed the app instance will have been created but root destroyed.
    if not hasattr(app, "tree"):
        return
    def on_close():
        if messagebox.askokcancel("Quit", "Quit Password Manager?"):
            app.stop()
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.geometry("980x640")
    root.mainloop()

if __name__ == "__main__":
    main()
