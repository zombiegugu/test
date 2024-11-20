import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import time  # Import time module


# Known malicious file hashes
known_malware_hashes = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Example malicious file hash
]


def calculate_file_hash(file_path):
    """Calculate the hash of a file"""
    hash_func = hashlib.sha256()  # Default to SHA-256
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def scan_directory(file_or_dir):
    """Scan the selected directory"""
    result_text.delete(1.0, tk.END)  # Clear previous results
    total_files = 0  # Total number of files
    scanned_files = 0  # Number of scanned files
    start_time = time.time()  # Record the start time of the scan

    if os.path.isdir(file_or_dir):
        # If it's a directory, scan all files in the directory
        files_to_scan = []
        for root, _, files in os.walk(file_or_dir):
            for file in files:
                files_to_scan.append(os.path.join(root, file))
        total_files = len(files_to_scan)

        # Start scanning the files in the directory
        for file_path in files_to_scan:
            file_hash = calculate_file_hash(file_path)
            scanned_files += 1  # Increase the scanned files count

            # Calculate scan speed
            elapsed_time = time.time() - start_time
            if elapsed_time > 0:  # Prevent division by zero
                scan_speed = scanned_files / elapsed_time  # Files per second
            else:
                scan_speed = 0

            if file_hash in known_malware_hashes:
                result_text.insert(tk.END, f"Malware found: {file_path}\n")
                result_text.yview(tk.END)  # Auto-scroll to the bottom
                if messagebox.askyesno("Delete Confirmation", f"Malware found: {file_path}. Do you want to delete this file?"):
                    try:
                        os.remove(file_path)
                        result_text.insert(tk.END, f"Malicious file deleted: {file_path}\n")
                    except Exception as e:
                        result_text.insert(tk.END, f"Failed to delete: {file_path} - Error: {e}\n")
                        messagebox.showerror("Delete Failed", f"Failed to delete file: {e}")

            # Update the scan status
            result_text.insert(tk.END, f"Scanned {scanned_files}/{total_files} files, scan speed: {scan_speed:.2f} files/sec\n")
            result_text.yview(tk.END)  # Auto-scroll to the bottom

        # After completing the scan, show the total time and scan speed
        elapsed_time = time.time() - start_time
        result_text.insert(tk.END, f"Scan complete! A total of {total_files} files were scanned in {elapsed_time:.2f} seconds.\n")
        result_text.insert(tk.END, f"Average scan speed: {total_files / elapsed_time:.2f} files/sec\n")
        messagebox.showinfo("Scan Complete", "Scan complete!")


def select_directory():
    """Open file dialog to select a directory and start scanning"""
    folder_selected = filedialog.askdirectory(title="Select Directory")
    if folder_selected:
        scan_directory(folder_selected)


def create_gui():
    """Create the graphical user interface"""
    window = tk.Tk()
    window.title("Malicious File Scanner")

    label = tk.Label(window, text="Select a folder to scan", font=("Arial", 14))
    label.pack(pady=20)

    global result_text
    result_text = scrolledtext.ScrolledText(window, width=70, height=15)
    result_text.pack(pady=10)

    scan_button = tk.Button(window, text="Start Scan", font=("Arial", 12), command=select_directory)
    scan_button.pack(pady=10)

    window.mainloop()


if __name__ == '__main__':
    create_gui()
