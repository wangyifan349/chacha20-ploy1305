import os
import shutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Supported media file extensions
IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
VIDEO_EXT = {'.mp4', '.avi', '.mkv', '.mov', '.wmv'}
AUDIO_EXT = {'.mp3', '.wav', '.aac', '.flac', '.ogg'}
ALLOWED_EXT = IMAGE_EXT | VIDEO_EXT | AUDIO_EXT

def get_unique_filename(dest_dir, filename):
    """
    Generate a unique filename in the destination directory to avoid overwriting.
    
    Parameters:
    - dest_dir: The directory where the file will be saved.
    - filename: The original filename.
    
    Returns:
    - A unique filename that does not exist in the destination directory.
    """
    base, ext = os.path.splitext(filename)
    candidate = filename
    counter = 1
    while os.path.exists(os.path.join(dest_dir, candidate)):
        candidate = f"{base}_{counter}{ext}"
        counter += 1
    return candidate

class MediaMigratorApp(tk.Tk):
    def __init__(self):
        """
        Initialize the main application window and its components.
        """
        super().__init__()
        self.title("Media File Migrator")
        self.minsize(800, 600)
        self.configure(bg="#f7f7f7")

        # Initialize variables
        self.source_dirs = []  # List to store source directories
        self.target_dir = tk.StringVar()  # Variable to store target directory path

        # Create and configure widgets
        self.create_widgets()
        self.create_grid_config()

    def create_widgets(self):
        """
        Create and configure all the widgets in the application.
        """
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("TButton", font=("Helvetica", 12), padding=6)
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("Header.TLabel", font=("Helvetica", 16, "bold"))

        # Header label
        header = ttk.Label(self, text="Media File Migrator", style="Header.TLabel", background="#f7f7f7")
        header.grid(row=0, column=0, columnspan=3, pady=(15, 10), sticky="n")

        # Create frames for different sections
        self.create_source_frame()
        self.create_target_frame()
        self.create_action_frame()
        self.create_status_frame()

    def create_source_frame(self):
        """
        Create the source directory selection frame.
        """
        src_frame = ttk.LabelFrame(self, text="Source Directories (Multiple Allowed)", padding=10)
        src_frame.grid(row=1, column=0, padx=15, pady=10, sticky="nsew")
        src_frame.grid_rowconfigure(0, weight=1)
        src_frame.grid_columnconfigure(0, weight=1)

        # Listbox to display added source directories
        self.src_listbox = tk.Listbox(src_frame, font=("Helvetica", 11))
        self.src_listbox.grid(row=0, column=0, rowspan=4, sticky="nsew", padx=(0, 5))
        src_scrollbar = ttk.Scrollbar(src_frame, orient="vertical", command=self.src_listbox.yview)
        src_scrollbar.grid(row=0, column=1, rowspan=4, sticky="ns")
        self.src_listbox.configure(yscrollcommand=src_scrollbar.set)

        # Buttons for adding and removing source directories
        btn_add = ttk.Button(src_frame, text="Add Source", command=self.add_source_dir)
        btn_add.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        btn_del = ttk.Button(src_frame, text="Remove Selected", command=self.delete_selected_source)
        btn_del.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        btn_count = ttk.Button(src_frame, text="Count Files", command=self.count_files)
        btn_count.grid(row=2, column=2, padx=5, pady=5, sticky="ew")
        self.count_label = ttk.Label(src_frame, text="Files to Process: 0", foreground="#006400")
        self.count_label.grid(row=3, column=2, padx=5, pady=5, sticky="ew")

    def create_target_frame(self):
        """
        Create the target directory selection frame.
        """
        target_frame = ttk.LabelFrame(self, text="Target Directory", padding=10)
        target_frame.grid(row=1, column=1, padx=15, pady=10, sticky="nsew")
        target_frame.grid_columnconfigure(1, weight=1)

        # Button and entry for selecting target directory
        btn_target = ttk.Button(target_frame, text="Select Target", command=self.select_target_dir)
        btn_target.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(target_frame, textvariable=self.target_dir, font=("Helvetica", 11))
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    def create_action_frame(self):
        """
        Create the action frame containing the start button and progress bar.
        """
        action_frame = ttk.Frame(self, padding=10)
        action_frame.grid(row=2, column=0, columnspan=3, padx=15, pady=10, sticky="nsew")

        # Start migration button
        self.btn_start = ttk.Button(action_frame, text="Start Migration", command=self.start_migration)
        self.btn_start.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # Progress bar to show migration progress
        self.progress = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.progress.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

    def create_status_frame(self):
        """
        Create the status frame to display log messages.
        """
        status_frame = ttk.LabelFrame(self, text="Status", padding=10)
        status_frame.grid(row=3, column=0, columnspan=3, padx=15, pady=10, sticky="nsew")
        status_frame.grid_rowconfigure(0, weight=1)
        status_frame.grid_columnconfigure(0, weight=1)

        # Text widget to display status messages
        self.status_text = tk.Text(status_frame, font=("Helvetica", 11), state="disabled", wrap="word")
        self.status_text.grid(row=0, column=0, sticky="nsew")
        status_scroll = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_text.yview)
        status_scroll.grid(row=0, column=1, sticky="ns")
        self.status_text.configure(yscrollcommand=status_scroll.set)

    def create_grid_config(self):
        """
        Configure the grid layout for the main window.
        """
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=2)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0)

    def add_source_dir(self):
        """
        Add a new source directory to the list.
        """
        dir_path = filedialog.askdirectory(title="Select Source Directory")
        if dir_path and dir_path not in self.source_dirs:
            self.source_dirs.append(dir_path)
            self.src_listbox.insert("end", dir_path)
            self.log_status(f"Added source directory: {dir_path}")
        elif dir_path in self.source_dirs:
            messagebox.showinfo("Info", "Directory already added.")

    def delete_selected_source(self):
        """
        Remove the selected source directory from the list.
        """
        selected = list(self.src_listbox.curselection())
        if not selected:
            messagebox.showwarning("Warning", "Select a directory to remove.")
            return
        for index in reversed(selected):
            removed = self.source_dirs.pop(index)
            self.src_listbox.delete(index)
            self.log_status(f"Removed source directory: {removed}")
        self.count_files()

    def select_target_dir(self):
        """
        Select the target directory for file migration.
        """
        dir_path = filedialog.askdirectory(title="Select Target Directory")
        if dir_path:
            self.target_dir.set(dir_path)
            self.log_status(f"Set target directory: {dir_path}")

    def count_files(self):
        """
        Count the number of files to be processed in the source directories.
        
        Returns:
        - The total number of files to be processed.
        """
        total = 0
        for dir_path in self.source_dirs:
            for current_root, dirs, files in os.walk(dir_path):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ALLOWED_EXT:
                        total += 1
        self.count_label.config(text=f"Files to Process: {total}")
        self.log_status(f"Count complete: {total} files to process")
        return total

    def log_status(self, msg):
        """
        Log a status message to the status text widget.
        
        Parameters:
        - msg: The message to log.
        """
        self.status_text.config(state="normal")
        self.status_text.insert("end", msg + "\n")
        self.status_text.see("end")
        self.status_text.config(state="disabled")

    def start_migration(self):
        """
        Start the file migration process.
        """
        if not self.source_dirs:
            messagebox.showerror("Error", "Add at least one source directory!")
            return
        if not self.target_dir.get():
            messagebox.showerror("Error", "Select a target directory!")
            return

        total_files = self.count_files()
        if total_files == 0:
            messagebox.showinfo("Info", "No files to move!")
            return

        confirm = messagebox.askyesno("Confirm", f"{total_files} files will be moved to:\n{self.target_dir.get()}\nProceed?")
        if not confirm:
            return

        self.disable_buttons()
        self.progress["maximum"] = total_files
        self.log_status("Starting file migration...")

        # Start migration in a separate thread
        threading.Thread(target=self.migrate_files, daemon=True).start()

    def disable_buttons(self):
        """
        Disable all buttons to prevent user interaction during migration.
        """
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state="disabled")
            elif isinstance(widget, (ttk.LabelFrame, ttk.Frame)):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        child.config(state="disabled")

    def enable_buttons(self):
        """
        Enable all buttons after migration is complete.
        """
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state="normal")
            elif isinstance(widget, (ttk.LabelFrame, ttk.Frame)):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        child.config(state="normal")

    def migrate_files(self):
        """
        Migrate files from source directories to the target directory.
        """
        target_dir = self.target_dir.get()

        if not os.access(target_dir, os.W_OK):
            self.log_status(f"Target directory {target_dir} is not writable. Aborting.")
            self.enable_buttons()
            return

        total_scanned = 0
        total_moved = 0

        for dir_path in self.source_dirs:
            self.log_status(f"Processing source directory: {dir_path}")
            for current_root, directories, files in os.walk(dir_path):
                for file in files:
                    total_scanned += 1
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ALLOWED_EXT:
                        src_file = os.path.join(current_root, file)
                        if not os.access(src_file, os.R_OK):
                            self.log_status(f"Skipping (no read permission): {src_file}")
                            continue
                        unique_name = get_unique_filename(target_dir, file)
                        dest_file = os.path.join(target_dir, unique_name)
                        try:
                            shutil.move(src_file, dest_file)
                            self.log_status(f"Moved: {src_file} -> {dest_file}")
                            total_moved += 1
                        except Exception as e:
                            self.log_status(f"Error moving {src_file} -> {dest_file}\nError: {e}")

                    # Update progress bar
                    self.progress["value"] = total_moved
                    self.update_idletasks()

        summary = (f"\nTotal files scanned: {total_scanned}\n"
                   f"Files successfully moved: {total_moved}\n"
                   "Migration complete.")
        self.log_status(summary)
        messagebox.showinfo("Migration Complete", summary)
        self.enable_buttons()

if __name__ == "__main__":
    app = MediaMigratorApp()
    app.mainloop()
