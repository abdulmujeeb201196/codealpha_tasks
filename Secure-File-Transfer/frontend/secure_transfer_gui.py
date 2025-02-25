import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import requests
import pyperclip

# Backend URLs
BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = f"{BASE_URL}/auth/login"
UPLOAD_URL = f"{BASE_URL}/files/upload"
ENCRYPT_URL = f"{BASE_URL}/files/encrypt"
DOWNLOAD_URL = f"{BASE_URL}/files/download"
#DOWNLOAD_DECRYPTED_URL = f"{BASE_URL}/files/decrypted"
DECRYPT_URL = f"{BASE_URL}/files/decrypt"

token = ""
selected_file = ""
encrypted_file = ""


def show_start_window():
    start_frame.pack()
    login_frame.pack_forget()
    encrypt_frame.pack_forget()
    decrypt_frame.pack_forget()

def show_login_window():
    start_frame.pack_forget()
    login_frame.pack()

def show_encrypt_window():
    login_frame.pack_forget()
    encrypt_frame.pack()

def show_decrypt_window():
    start_frame.pack_forget()
    decrypt_frame.pack()

def login():
    """Handles user login and stores JWT token."""
    global token
    username = username_entry.get()
    password = password_entry.get()
    
    response = requests.post(LOGIN_URL, json={"username": username, "password": password})
    if response.status_code == 200:
        token = response.json().get("token")
        token_entry.delete(0, tk.END)
        token_entry.insert(0, token)
        messagebox.showinfo("Success", "Login Successful! Token Generated.")
        show_encrypt_window()
    else:
        messagebox.showerror("Error", "Login Failed! Check your credentials.")

def copy_token():
    """Copies JWT token to clipboard."""
    pyperclip.copy(token)
    messagebox.showinfo("Copied", "Token copied to clipboard!")

def select_file():
    """Opens file dialog and selects a file."""
    global selected_file
    selected_file = filedialog.askopenfilename()
    file_label.config(text=f"Selected: {selected_file}")

def upload_file():
    """Uploads the selected file."""
    global selected_file
    if not selected_file:
        messagebox.showerror("Error", "Please select a file first!")
        return
    
    with open(selected_file, "rb") as f:
        files = {"file": f}
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(UPLOAD_URL, files=files, headers=headers)
    
    if response.status_code == 200:
        messagebox.showinfo("Success", "File Uploaded Successfully!")
    else:
        messagebox.showerror("Error", "File Upload Failed!")

def encrypt_file():
    """Requests the backend to encrypt the uploaded file."""
    if not selected_file:
        messagebox.showerror("Error", "Please upload a file first!")
        return
    
    filename = selected_file.split("/")[-1]  # Extract filename
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{ENCRYPT_URL}?filename={filename}", headers=headers)  # FIX: Use JSON payload
    
    if response.status_code == 200:
        messagebox.showinfo("Success", "File Encrypted Successfully!")
    else:
        messagebox.showerror("Error", f"File Encryption Failed! {response.json()}")

def download_file():
    """Requests the backend to download the encrypted file."""
    if not selected_file:
        messagebox.showerror("Error", "Please upload and encrypt a file first!")
        return
    
    filename = selected_file.split("/")[-1] + ".enc"  # Get encrypted filename
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{DOWNLOAD_URL}/{filename}", headers=headers)
    
    if response.status_code == 200:
        file_path = filedialog.asksaveasfilename(defaultextension=".enc")
        with open(file_path, "wb") as f:
            f.write(response.content)
        messagebox.showinfo("Success", "File Downloaded Successfully!")
    else:
        messagebox.showerror("Error", "File Download Failed!")

#  Select Encrypted File
def select_encrypted_file():
    global encrypted_file
    encrypted_file = filedialog.askopenfilename(title="Select Encrypted File")
    enc_file_label.config(text=f"Selected: {encrypted_file}")

#  Decrypt File
def decrypt_file():
    if not encrypted_file:
        messagebox.showerror("Error", "Please select an encrypted file!")
        return
    
    with open(encrypted_file, "rb") as f:
        files = {"file": f}
        response = requests.post(DECRYPT_URL, files=files)

    if response.status_code == 200:
        file_ext = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_ext:
            with open(file_ext, "wb") as f:
                f.write(response.content)
            messagebox.showinfo("Success", "File Decrypted and Downloaded Successfully!")
    else:
        messagebox.showerror("Error", f"File Decryption Failed! {response.text}")


# Tkinter GUI Setup
root = tk.Tk()
root.title("Secure File Transfer")
root.geometry("500x400")

# Start Frame (Choose Encrypt or Decrypt)
start_frame = tk.Frame(root)
ttk.Label(start_frame, text="Secure File Transfer", font=("Helvetica", 16), bootstyle=PRIMARY).pack(pady=20)
ttk.Button(start_frame, text="Encrypt", command=show_login_window).pack(pady=10)
ttk.Button(start_frame, text="Decrypt", command=show_decrypt_window).pack(pady=10)

encrypt_frame = tk.Frame(root)
# Login Frame
login_frame = tk.Frame(root)
ttk.Label(login_frame, text="Login Screen", font=("Helvetica", 16), bootstyle=PRIMARY).pack(pady=10)
ttk.Label(login_frame, text="Login to Generate Token", font=("Helvetica", 14), bootstyle=INFO).pack(pady=10)

ttk.Label(login_frame, text="Username:", font=("Helvetica", 12), bootstyle=PRIMARY).pack(pady=5)
username_entry = tk.Entry(login_frame)
username_entry.pack()
ttk.Label(login_frame, text="Password:", font=("Helvetica", 12), bootstyle=PRIMARY).pack(pady=5)
password_entry = tk.Entry(login_frame, show="*")
password_entry.pack()
ttk.Button(login_frame, text="Login", command=login, bootstyle=SCROLL).pack(pady=10)
show_encrypt_window()
ttk.Label(login_frame, text="Token", font=("Helvetica", 12), bootstyle=INFO).pack(pady=5)
token_entry = tk.Entry(login_frame, width=30)
token_entry.pack()
ttk.Button(login_frame, text="Back", command=show_start_window, bootstyle=DANGER).pack(pady=10)

# tk.Button(login_frame, text="Back", command=show_start_window).pack()

# Encryption Frame
encrypt_frame = tk.Frame(root)
ttk.Label(encrypt_frame, text="Encryption Panel", font=("Helvetica", 14), bootstyle=PRIMARY).pack(pady=20)
ttk.Label(encrypt_frame, text="Upload and Encrypt File", font=("Helvetica", 12), bootstyle=INFO).pack(pady=15)
ttk.Button(encrypt_frame, text="Select File", command=select_file, bootstyle=SECONDARY).pack(pady=15)
file_label = tk.Label(encrypt_frame, text="No file selected")
file_label.pack()
ttk.Button(encrypt_frame, text="Encrypt", command=encrypt_file, bootstyle=SUCCESS).pack(pady=15)
ttk.Button(encrypt_frame, text="Download Encrypted File", command=download_file, bootstyle=INFO).pack(pady=15)
ttk.Button(encrypt_frame, text="Back", command=show_start_window, bootstyle=DANGER).pack(pady=10)

# Decryption Frame
decrypt_frame = tk.Frame(root)
ttk.Label(decrypt_frame, text="Decryption Panel", font=("Helvetica", 14), bootstyle=PRIMARY).pack(pady=20)
ttk.Label(decrypt_frame, text="Decrypt and Download File", font=("Helvetica", 12), bootstyle=INFO).pack(pady=15)
ttk.Button(decrypt_frame, text="Select Encrypted File", command=select_encrypted_file, bootstyle=SECONDARY).pack(pady=15)
enc_file_label = tk.Label(decrypt_frame, text="No encrypted file selected")
enc_file_label.pack()
ttk.Button(decrypt_frame, text="Decrypt & Download", command=decrypt_file, bootstyle=SUCCESS).pack(pady=15)
ttk.Button(decrypt_frame, text="Back", command=show_start_window, bootstyle=DANGER).pack(pady=10)

# Show Start Frame Initially
show_start_window()
root.mainloop()

