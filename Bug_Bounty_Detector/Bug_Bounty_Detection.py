import subprocess
import time

# Start the Flask backend
backend_process = subprocess.Popen(["python", "bug.py"])
time.sleep(2)  # Wait for the backend to start

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import requests

API_URL = "http://127.0.0.1:5000/scan"

# Allowed file types based on language
FILE_TYPES = {
    "Python": [("Python Files", "*.py")],
    "Java": [("Java Files", "*.java")],
    "C#": [("C# Files", "*.cs")],
    "JavaScript": [("JavaScript Files", "*.js")]
}


# Function to upload and scan file
def upload_file():
    selected_language = file_type_var.get()
    if selected_language not in FILE_TYPES:
        messagebox.showerror("Error", "Please select a valid file type!")
        return
    
    file_path = filedialog.askopenfilename(filetypes=FILE_TYPES[selected_language])
    if not file_path:
        return

    with open(file_path, "rb") as file:
        response = requests.post(API_URL, files={"file": file})

    if response.status_code == 200:
        results = response.json()
        if results:
            output_text.insert(tk.END, "⚠️ Issues Found:\n", "warning")
            for bug in results:
                output_text.insert(tk.END, f"{bug['issue']} at Line {bug['line_number']}: {bug['line']}\n", "error")
        else:
            output_text.insert(tk.END, "✅ No security issues found!\n", "success")
    else:
        messagebox.showerror("Error", "Failed to scan file")
    
    output_text.config(state=tk.DISABLED)

# GUI Setup
root = tk.Tk()
root.title("Bug Scanner")
root.geometry("600x400")
root.configure(bg="#121212")  # Dark Background

frame = tk.Frame(root, bg="#121212")
frame.pack(pady=20)

# Title Label
title_label = tk.Label(frame, text="Bug Scanner Tool", font=("Arial", 16, "bold"), fg="#00FFD1", bg="#121212")
title_label.pack()

# Dropdown Menu (Combobox)
tk.Label(frame, text="Select File Type:", fg="white", bg="#121212", font=("Arial", 12)).pack(pady=5)
file_type_var = tk.StringVar()
file_type_dropdown = ttk.Combobox(frame, textvariable=file_type_var, values=list(FILE_TYPES.keys()), state="readonly")
file_type_dropdown.pack()
# file_type_dropdown.bind("<<ComboboxSelected>>", show_file_button)
file_type_dropdown.current(0)
# File selection button (hidden initially)
btn_upload = tk.Button(frame, text="📂 Select File & Scan", command=upload_file, font=("Arial", 12), fg="white", bg="#1E88E5", padx=10, pady=5, bd=0, relief="flat")
btn_upload.pack(pady=10)
# btn_upload.pack_forget()

# Output Text Box
output_text = tk.Text(root, height=10, width=60, bg="#1E1E1E", fg="white", font=("Arial", 10))
output_text.tag_config("success", foreground="green")
output_text.tag_config("error", foreground="red")
output_text.tag_config("warning", foreground="yellow")
output_text.pack(pady=10)

root.mainloop()
