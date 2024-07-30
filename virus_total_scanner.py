import hashlib
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, Canvas, Toplevel
import os

VIRUSTOTAL_FILE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
API_KEY_FILE = "api_key.txt"

def calculate_hash(file_path, hash_type='sha256'):
    hash_func = getattr(hashlib, hash_type)()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def check_virus_total(api_key, resource, scan_type):
    url = VIRUSTOTAL_FILE_SCAN_URL if scan_type == 'file' else VIRUSTOTAL_URL_SCAN_URL
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        return {"error": "Invalid JSON response", "content": response.text}

def select_file(api_key):
    file_path = filedialog.askopenfilename()
    if file_path:
        file_hash = calculate_hash(file_path)
        result = check_virus_total(api_key, file_hash, 'file')
        display_result(result)

def scan_url(api_key, url_entry):
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL to scan.")
        return
    result = check_virus_total(api_key, url, 'url')
    display_result(result)

def display_result(result):
    if "error" in result:
        messagebox.showerror("Error", f"Error: {result['error']}\nContent: {result['content']}")
    elif result['response_code'] == 1:
        positives = result['positives']
        total = result['total']
        detection_ratio = positives / total if total > 0 else 0
        result_canvas.itemconfig(result_arc, extent=detection_ratio * 360)
        result_canvas.itemconfig(result_text, text=f"{positives}/{total}", fill="red" if detection_ratio > 0.1 else "green")
        show_detections(result['scans'])
    else:
        messagebox.showinfo("Scan Result", "Resource not found in VirusTotal database.")

def show_detections(scans):
    detections_window = Toplevel()
    detections_window.title("Antivirus Detections")
    detections_window.configure(bg="#34495e")  # Background color

    frame = tk.Frame(detections_window, bg="#34495e")
    frame.pack(pady=10, padx=10)

    row = 0
    col = 0

    for av_name, result in scans.items():
        detection_status = "Undetected" if not result['detected'] else result['result']
        status_color = "green" if not result['detected'] else "red"
        detection_label = tk.Label(frame, text=f"{av_name}: {detection_status}", bg="#34495e", fg=status_color)
        detection_label.grid(row=row, column=col, padx=5, pady=2, sticky="w")

        row += 1
        if row == 20:
            row = 0
            col += 1

def save_api_key(api_key_entry):
    global api_key
    api_key = api_key_entry.get()
    if not api_key:
        messagebox.showerror("Error", "Please enter your VirusTotal API key.")
        return
    with open(API_KEY_FILE, 'w') as f:
        f.write(api_key)
    api_key_entry.pack_forget()
    save_button.pack_forget()
    api_key_label.config(text="API Key saved and hidden.", fg="white")

def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, 'r') as f:
            return f.read().strip()
    return None

def create_gui():
    global result_canvas, result_arc, result_text, api_key_label, save_button
    root = tk.Tk()
    root.title("VirusTotal File Scanner")
    root.configure(bg="#6275a3")

    api_key_label = tk.Label(root, text="Enter your VirusTotal API Key:", bg="#6275a3", fg="white")
    api_key_label.pack(pady=10)
    api_key_entry = tk.Entry(root, width=50)
    api_key_entry.pack(pady=5)

    save_button = tk.Button(root, text="Save API Key", command=lambda: save_api_key(api_key_entry))
    save_button.pack(pady=5)

    select_file_button = tk.Button(root, text="Select File", command=lambda: select_file(api_key))
    select_file_button.pack(pady=20)

    url_label = tk.Label(root, text="Enter URL to scan:", bg="#6275a3", fg="white")
    url_label.pack(pady=10)
    url_entry = tk.Entry(root, width=50)
    url_entry.pack(pady=5)

    scan_url_button = tk.Button(root, text="Scan URL", command=lambda: scan_url(api_key, url_entry))
    scan_url_button.pack(pady=20)

    result_canvas = Canvas(root, width=200, height=200, bg="#6275a3", highlightthickness=0)
    result_canvas.pack(pady=10)
    result_arc = result_canvas.create_arc(10, 10, 190, 190, start=90, extent=0, fill="red")
    result_canvas.create_oval(50, 50, 150, 150, fill="#6275a3", outline="#6275a3")
    result_text = result_canvas.create_text(100, 100, text="0/0", font=("Helvetica", 16), fill="white")

    existing_api_key = load_api_key()
    if existing_api_key:
        global api_key
        api_key = existing_api_key
        api_key_label.config(text="API Key loaded and hidden.", fg="white")
        api_key_entry.pack_forget()
        save_button.pack_forget()
    
    root.mainloop()

if __name__ == "__main__":
    api_key = ""
    create_gui()
