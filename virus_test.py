import os
import threading
import subprocess
import psutil
from queue import Queue
import customtkinter as ctk
from tkinter import messagebox
from tkinter import scrolledtext

# Paths
CLAMAV_PATH = r"C:\Users\DeLL 6440\Downloads\clamav-1.4.2-r1-winxp-x64\clamscan.exe"
CLAMAV_DB = os.path.join(os.path.dirname(CLAMAV_PATH), "database")
LOG_FILE = "scan_log.txt"

# Globals
log_queue = Queue()
detected_usb_drives = []

# Logging

def log_message(msg):
    log_queue.put(msg)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"[Log Error] {e}")

def update_log():
    while not log_queue.empty():
        msg = log_queue.get()
        log_box.configure(state="normal")
        log_box.insert("end", msg + "\n")
        log_box.see("end")
        log_box.configure(state="disabled")
    app.after(100, update_log)

# Drive Detection

def get_usb_drives():
    drives = []
    for part in psutil.disk_partitions(all=False):
        if 'removable' in part.opts.lower():
            drives.append(part.device)
    return drives

def refresh_usb_list():
    global detected_usb_drives
    detected_usb_drives = get_usb_drives()
    drive_combo.configure(values=detected_usb_drives)
    if detected_usb_drives:
        drive_combo.set(detected_usb_drives[0])
    else:
        drive_combo.set("")

# Scan Logic

def scan_usb(path):
    if not os.path.exists(CLAMAV_PATH):
        log_message("[ERROR] clamscan.exe not found.")
        messagebox.showerror("Error", "ClamAV tool not found.")
        return

    try:
        log_message(f"[SCAN] Scanning: {path}")
        progress_bar.start()

        result = subprocess.run(
            [
                CLAMAV_PATH,
                "--infected",
                "--remove",
                f"--database={CLAMAV_DB}",
                "--max-filesize=50M",
                "--max-scansize=300M",
                path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        progress_bar.stop()

        if "Malformed database" in result.stderr or "Can't load" in result.stderr:
            log_message("[ERROR] Malformed ClamAV database.")
            messagebox.showerror("ClamAV Error", "Virus database is corrupted.")
            return

        log_message("[CLAMAV] Output:\n" + result.stdout)
        log_message("[CLAMAV] Errors:\n" + result.stderr)

        infected_files = []
        infected_count = 0

        if "Infected files:" in result.stdout:
            try:
                infected_count = int(result.stdout.split("Infected files: ")[1].split("\n")[0].strip())
            except ValueError:
                infected_count = 0

        if infected_count > 0:
            lines = result.stdout.split("\n")
            for line in lines:
                if ":" in line and "FOUND" in line:
                    infected_files.append(line.split(":")[0].strip())
            infected_files_str = "\n".join(infected_files)
            messagebox.showwarning("Threat Detected", f"Malware Found!\n\n{infected_files_str}")
            log_message(f"[ALERT] {infected_count} infected file(s) found and removed.")
        else:
            messagebox.showinfo("Scan Complete", "No threats found.")
            log_message("[SAFE] No threats found.")

    except Exception as e:
        progress_bar.stop()
        log_message(f"[ERROR] Scan failed: {e}")
        messagebox.showerror("Scan Error", str(e))

def start_scan_thread():
    selected_drive = drive_combo.get()
    if selected_drive and os.path.exists(selected_drive):
        threading.Thread(target=scan_usb, args=(selected_drive,), daemon=True).start()
    else:
        messagebox.showwarning("No USB", "Please select a valid USB drive.")

# File Explorer

def show_usb_contents():
    selected_drive = drive_combo.get()
    if selected_drive and os.path.exists(selected_drive):
        content_window = ctk.CTkToplevel(app)
        content_window.title(f"Contents of {selected_drive}")
        content_window.geometry("700x500")

        file_list_box = scrolledtext.ScrolledText(content_window, wrap="none")
        file_list_box.pack(expand=True, fill="both", padx=10, pady=10)

        files = []
        for root_dir, dirs, file_names in os.walk(selected_drive):
            for file in file_names:
                full_path = os.path.join(root_dir, file)
                rel_path = os.path.relpath(full_path, selected_drive)
                files.append(rel_path)

        file_list_box.insert("end", "\n".join(files))
    else:
        messagebox.showwarning("USB Not Found", "USB is not inserted or invalid.")

# GUI Setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("USB Malware Scanner - ClamAV Edition")
app.geometry("850x600")

header = ctk.CTkLabel(app, text="USB Malware Scanner", font=("Arial", 24, "bold"), text_color="lime")
header.pack(pady=15)

frame = ctk.CTkFrame(app)
frame.pack(pady=10)

drive_label = ctk.CTkLabel(frame, text="Select USB Drive:", font=("Arial", 14))
drive_label.grid(row=0, column=0, padx=10, pady=10)

drive_combo = ctk.CTkComboBox(frame, width=200, values=[])
drive_combo.grid(row=0, column=1, padx=10, pady=10)

refresh_btn = ctk.CTkButton(frame, text="🔄 Refresh", command=refresh_usb_list)
refresh_btn.grid(row=0, column=2, padx=10)

btn_frame = ctk.CTkFrame(app)
btn_frame.pack(pady=15)

scan_btn = ctk.CTkButton(btn_frame, text="🛡 Scan USB", command=start_scan_thread, width=150)
scan_btn.grid(row=0, column=0, padx=20)

view_btn = ctk.CTkButton(btn_frame, text="📁 View Files", command=show_usb_contents, width=150)
view_btn.grid(row=0, column=1, padx=20)

progress_bar = ctk.CTkProgressBar(app, orientation="horizontal", width=400)
progress_bar.pack(pady=10)
progress_bar.set(0)

log_label = ctk.CTkLabel(app, text="Scan Log:", font=("Arial", 14))
log_label.pack(pady=5)

log_box = scrolledtext.ScrolledText(app, width=100, height=18, font=("Consolas", 10))
log_box.pack(pady=10)
log_box.configure(state="disabled")

refresh_usb_list()
app.after(100, update_log)
app.mainloop()