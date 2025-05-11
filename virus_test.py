import os
import threading
import subprocess
import psutil
from tkinter import *
from tkinter import messagebox, scrolledtext
from tkinter import ttk
from queue import Queue

CLAMAV_PATH = r"C:\Users\DeLL 6440\Downloads\clamav-1.4.2-r1-winxp-x64\clamscan.exe"
CLAMAV_DB = os.path.join(os.path.dirname(CLAMAV_PATH), "database")
LOG_FILE = "scan_log.txt"

log_queue = Queue()
detected_usb_drives = []

def get_usb_drives():
    """ Return a list of all removable USB drives """
    drives = []
    for part in psutil.disk_partitions(all=False):
        if 'removable' in part.opts.lower():
            drives.append(part.device)
    return drives

def log_message(msg):
    log_queue.put(msg)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def update_log():
    while not log_queue.empty():
        msg = log_queue.get()
        log_box.insert(END, msg + "\n")
        log_box.see(END)
    root.after(100, update_log)

def scan_usb(path):
    if not os.path.exists(CLAMAV_PATH):
        log_message("[ERROR] clamscan.exe not found.")
        messagebox.showerror("Error", "ClamAV tool not found.")
        return

    try:
        log_message(f"[SCAN] Scanning: {path}")
        progress.start()

        result = subprocess.run(
            [
                CLAMAV_PATH,
                "--infected",
                "--remove",
                "--max-filesize=50M",
                "--max-scansize=300M",
                path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        progress.stop()

        if "Malformed database" in result.stderr or "Can't load" in result.stderr:
            log_message("[ERROR] Malformed or corrupted ClamAV database.")
            messagebox.showerror("ClamAV Error", "Virus database is corrupted or incomplete.")
            return

        log_message(f"[DEBUG] ClamAV Output:\n{result.stdout}")
        log_message(f"[DEBUG] ClamAV Error:\n{result.stderr}")

        infected_files = []
        infected_count = 0

        if "Infected files" in result.stdout:
            try:
                infected_count = int(result.stdout.split("Infected files: ")[1].split("\n")[0].strip())
            except ValueError:
                infected_count = 0

        if infected_count > 0:
            lines = result.stdout.split("\n")
            for line in lines:
                if ":" in line and "FOUND" in line:
                    infected_files.append(line.split(":")[0].strip())
            if infected_files:
                infected_files_str = "\n".join(infected_files)
                messagebox.showwarning("Threat Detected", f"Potential malware found!\nInfected Files:\n{infected_files_str}")
                log_message(f"[INFECTED] {infected_count} infected file(s) found and removed.")
            else:
                messagebox.showinfo("Scan Complete", "No threats found.")
                log_message("[OK] No threats found.")
        else:
            messagebox.showinfo("Scan Complete", "No threats found.")
            log_message("[OK] No threats found.")

    except Exception as e:
        progress.stop()
        log_message(f"[ERROR] Scan failed: {e}")
        messagebox.showerror("Scan Error", str(e))

def start_scan_thread():
    selected_drive = drive_combo.get()
    if selected_drive and os.path.exists(selected_drive):
        threading.Thread(target=scan_usb, args=(selected_drive,), daemon=True).start()
    else:
        messagebox.showwarning("No USB", "Please select a valid USB drive.")

def refresh_usb_list():
    global detected_usb_drives
    detected_usb_drives = get_usb_drives()
    drive_combo['values'] = detected_usb_drives
    if detected_usb_drives:
        drive_combo.set(detected_usb_drives[0])
    else:
        drive_combo.set('')

def show_usb_contents():
    selected_drive = drive_combo.get()
    if selected_drive and os.path.exists(selected_drive):
        file_list = []
        for root_dir, dirs, files in os.walk(selected_drive):
            for name in files:
                full_path = os.path.join(root_dir, name)
                rel_path = os.path.relpath(full_path, selected_drive)
                file_list.append(rel_path)
        if file_list:
            content_window = Toplevel(root)
            content_window.title(f"Contents of {selected_drive}")
            text = scrolledtext.ScrolledText(content_window, width=80, height=30)
            text.pack()
            text.insert(END, "\n".join(file_list))
        else:
            messagebox.showinfo("USB Empty", "No files found.")
    else:
        messagebox.showwarning("USB Not Found", "USB is not inserted or invalid.")

# GUI Setup
root = Tk()
root.title("USB Malware Scanner ")
root.geometry("750x550")

Label(root, text="USB Scanner", font=("Arial", 16, "bold"), fg="darkgreen").pack(pady=10)

frame = Frame(root)
frame.pack(pady=5)

Label(frame, text="Select USB Drive:", font=("Arial", 12)).grid(row=0, column=0, padx=5)
drive_combo = ttk.Combobox(frame, width=20, state="readonly")
drive_combo.grid(row=0, column=1, padx=5)

Button(frame, text="Refresh List", command=refresh_usb_list, bg="orange", fg="black").grid(row=0, column=2, padx=5)

btn_frame = Frame(root)
btn_frame.pack(pady=10)

Button(btn_frame, text="Scan Selected USB", command=start_scan_thread, width=18, bg="darkblue", fg="white").grid(row=0, column=0, padx=10)
Button(btn_frame, text="Show USB Files", command=show_usb_contents, width=18, bg="gray", fg="white").grid(row=0, column=1, padx=10)

progress = ttk.Progressbar(root, orient=HORIZONTAL, length=400, mode='indeterminate')
progress.pack(pady=5)

log_box = scrolledtext.ScrolledText(root, width=90, height=20, font=("Consolas", 10))
log_box.pack(pady=10)

refresh_usb_list()
root.after(100, update_log)
root.mainloop()
