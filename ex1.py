import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import sqlite3
import random
import os
import string
import pyperclip  # 用于复制密码到剪贴板
import ttkbootstrap as tb  # 使用ttkbootstrap库

def del_space(res:str):
    res = res.strip(" ")
    res = res.replace("\n","")
    res = res.replace("\t",'')
    res = res.replace("\r",'')


    return res


# 生成或加载加密密钥
def load_or_generate_key():
    key_file = 'encryption_key.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as key_file:
            key_file.write(key)
    return key

# 加密数据
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

# 解密数据
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# 初始化数据库
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 保存数据到数据库
def save_to_db(website, username, password, key):
    encrypted_password = encrypt_data(password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO passwords (website, username, password)
        VALUES (?, ?, ?)
    ''', (website, username, encrypted_password))
    conn.commit()
    conn.close()

# 从数据库加载数据
def load_from_db(key):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT website, username, password FROM passwords')
    rows = cursor.fetchall()
    conn.close()
    data = []
    for row in rows:
        decrypted_password = decrypt_data(row[2], key)
        data.append({"website": row[0], "username": row[1], "password": decrypted_password})
    return data

# 更新数据库中的数据
def update_in_db(website, username, password, key, original_website, original_username):
    encrypted_password = encrypt_data(password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE passwords
        SET website = ?, username = ?, password = ?
        WHERE website = ? AND username = ?
    ''', (website, username, encrypted_password, original_website, original_username))
    conn.commit()
    conn.close()

# 从数据库删除数据
def delete_from_db(website, username):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE website = ? AND username = ?', (website, username))
    conn.commit()
    conn.close()

# 生成随机密码
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# 主应用程序
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("1000x600")
        self.key = load_or_generate_key()
        init_db()

        # 设置ttkbootstrap主题
        self.style = tb.Style(theme="cosmo")  # 使用ttkbootstrap的Style

        # 顶部工具栏
        self.toolbar = ttk.Frame(root)
        self.toolbar.pack(side=tk.TOP, fill=tk.X)

        self.add_button = tb.Button(self.toolbar, text="Add Entry", bootstyle="success", command=self.add_entry)
        self.add_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.refresh_button = tb.Button(self.toolbar, text="Refresh", bootstyle="info", command=self.refresh_list)
        self.refresh_button.pack(side=tk.LEFT, padx=5, pady=5)

        # 搜索框
        self.search_label = tb.Label(self.toolbar, text="Search:")
        self.search_label.pack(side=tk.LEFT, padx=5, pady=5)
        self.search_entry = tb.Entry(self.toolbar, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.search_button = tb.Button(self.toolbar, text="Search", bootstyle="primary", command=self.search_entries)
        self.search_button.pack(side=tk.LEFT, padx=5, pady=5)

        # 密码条目列表
        self.tree = ttk.Treeview(root, columns=("Website", "Username", "Password"), show="headings")
        self.tree.heading("Website", text="Website",anchor='w')
        self.tree.heading("Username", text="Username",anchor="w")
        self.tree.heading("Password", text="Password",anchor='w')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 右键菜单
        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(label="View Password", command=self.view_password)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Edit", command=self.edit_entry)
        self.context_menu.add_command(label="Delete", command=self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # 初始化列表
        self.refresh_list()

    def refresh_list(self):
        """刷新密码条目列表"""
        self.tree.delete(*self.tree.get_children())
        data = load_from_db(self.key)
        for entry in data:
            self.tree.insert("", tk.END, values=(entry["website"], entry["username"], "******"))

    def add_entry(self):
        """添加新条目"""
        def save():
            website = del_space(website_entry.get())
            print(website)
            username = del_space(username_entry.get())
            password = del_space(password_entry.get())
            if website and username and password:
                save_to_db(website, username, password, self.key)
                self.refresh_list()
                add_window.destroy()
            else:
                messagebox.showerror("Error", "All fields are required!")

        def generate():
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generate_password())

        add_window = tb.Toplevel(self.root)
        add_window.title("Add Entry")

        tb.Label(add_window, text="Website:",justify="left").grid(row=0, column=0, padx=5, pady=5)
        website_entry = tb.Entry(add_window)
        website_entry.grid(row=0, column=1, padx=5, pady=5)

        tb.Label(add_window, text="Username:",justify="left").grid(row=1, column=0, padx=5, pady=5)
        username_entry = tb.Entry(add_window)
        username_entry.grid(row=1, column=1, padx=5, pady=5)

        tb.Label(add_window, text="Password:",justify="left").grid(row=2, column=0, padx=5, pady=5)
        password_entry = tb.Entry(add_window, show="*")
        password_entry.grid(row=2, column=1, padx=5, pady=5)

        tb.Button(add_window, text="Generate Password", bootstyle="warning", command=generate).grid(row=3, column=1, padx=5, pady=5)
        tb.Button(add_window, text="Save", bootstyle="success", command=save).grid(row=4, column=1, padx=5, pady=5)

    def edit_entry(self):
        """编辑条目"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No entry selected!")
            return

        index = self.tree.index(selected_item)
        data = load_from_db(self.key)
        entry = data[index]

        def save():
            new_website = website_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            if new_website and new_username and new_password:
                update_in_db(new_website, new_username, new_password, self.key, entry["website"], entry["username"])
                self.refresh_list()
                edit_window.destroy()
            else:
                messagebox.showerror("Error", "All fields are required!")

        edit_window = tb.Toplevel(self.root)
        edit_window.title("Edit Entry")

        tb.Label(edit_window, text="Website:",justify="left").grid(row=0, column=0, padx=5, pady=5)
        website_entry = tb.Entry(edit_window)
        website_entry.insert(0, entry["website"])
        website_entry.grid(row=0, column=1, padx=5, pady=5)

        tb.Label(edit_window, text="Username:",justify="left").grid(row=1, column=0, padx=5, pady=5)
        username_entry = tb.Entry(edit_window)
        username_entry.insert(0, entry["username"])
        username_entry.grid(row=1, column=1, padx=5, pady=5)

        tb.Label(edit_window, text="Password:",justify="left").grid(row=2, column=0, padx=5, pady=5)
        password_entry = tb.Entry(edit_window, show="*")
        password_entry.insert(0, entry["password"])
        password_entry.grid(row=2, column=1, padx=5, pady=5)

        tb.Button(edit_window, text="Save", bootstyle="success", command=save).grid(row=3, column=1, padx=5, pady=5)

    def delete_entry(self):
        """删除条目"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No entry selected!")
            return

        index = self.tree.index(selected_item)
        data = load_from_db(self.key)
        entry = data[index]
        delete_from_db(entry["website"], entry["username"])
        self.refresh_list()

    def show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def view_password(self):
        """查看密码明文"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No entry selected!")
            return

        index = self.tree.index(selected_item)
        data = load_from_db(self.key)
        password = data[index]["password"]
        messagebox.showinfo("Password", f"Password: {password}")

    def copy_password(self):
        """复制密码到剪贴板"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No entry selected!")
            return

        index = self.tree.index(selected_item)
        data = load_from_db(self.key)
        password = data[index]["password"]
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard!")

    def search_entries(self):
        """搜索条目"""
        query = self.search_entry.get().lower()
        self.tree.delete(*self.tree.get_children())
        data = load_from_db(self.key)
        for entry in data:
            if query in entry["website"].lower() or query in entry["username"].lower():
                self.tree.insert("", tk.END, values=(entry["website"], entry["username"], "******"))

if __name__ == "__main__":
    root = tb.Window(themename="cosmo")  # 使用ttkbootstrap的Window
    app = PasswordManagerApp(root)
    root.mainloop()