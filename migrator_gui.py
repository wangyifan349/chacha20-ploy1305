#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import shutil
import threading
import time
import queue
from pathlib import Path
import tkinter as tk
from tkinter import ttk, font, filedialog, messagebox
# =============================================================================
# Configuration: Categories and Extensions
# =============================================================================
CATEGORY_TO_EXTENSIONS = {
    "Images":     [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"],
    "Videos":     [".mp4", ".avi", ".mkv", ".mov", ".flv"],
    "Audio":      [".mp3", ".wav", ".aac", ".flac"],
    "Text Files": [".txt", ".md", ".rst"],
    "Documents":  [".doc", ".docx", ".odt", ".pdf"]
}
# Build reverse mapping: extension → category name
EXTENSION_TO_CATEGORY = {}
for category, exts in CATEGORY_TO_EXTENSIONS.items():
    for e in exts:
        EXTENSION_TO_CATEGORY[e] = category
# =============================================================================
# Main Application Class
# =============================================================================
class BulkFileMigrator(ttk.Frame):
    # Filenames for saving state and log
    STATE_FILE = "migration_state.json"
    LOG_FILE   = "migration_log.txt"
    def __init__(self, master):
        super().__init__(master, padding=12)
        self.master = master
        self.master.title("Bulk File Migrator")
        self.master.geometry("820x620")
        self.master.resizable(True, True)
        # Define a default font for widgets
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=10)
        self.master.option_add("*Font", default_font)
        # ----------------------------------------------------------------------------
        # Runtime data
        # ----------------------------------------------------------------------------
        self.source_dirs = []            # list of source directory paths
        self.destination_dir = ""        # single destination path
        self.selected_categories = {}    # category_name → BooleanVar
        self.operation_mode = tk.StringVar(value="move")  # "move" or "copy"
        self.log_queue = queue.Queue()   # thread → GUI log messages
        self.pause_event = threading.Event()
        self.pause_event.set()           # allow migration to run
        # Load previously processed files for resume support
        self.processed_set = set()
        self._load_state()
        # Build the user interface
        self._build_ui()
        # Schedule periodic log flushing from queue into text widget
        self.after(100, self._flush_log_to_text)

        # If there was an unfinished migration, prompt to resume or reset
        if self.processed_set:
            answer = messagebox.askyesno(
                "Unfinished Task Detected",
                "A previous migration was not completed. Do you want to resume?"
            )
            if answer:
                self._log("Resuming previous task...")
            else:
                self.processed_set.clear()
                self._save_state()
                self._clear_log_file()
                self._log("Previous state cleared. Starting new task.")

    # ----------------------------------------------------------------------------
    # UI Construction
    # ----------------------------------------------------------------------------
    def _build_ui(self):
        # -------- Paths Frame --------
        frm_paths = ttk.Labelframe(self, text="Source and Destination Paths", padding=8)
        frm_paths.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        frm_paths.columnconfigure(1, weight=1)

        # Button to add source directory
        btn_add_source = ttk.Button(
            frm_paths, text="Add Source Directory", command=self._add_source
        )
        btn_add_source.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        # Listbox to display added source directories
        self.lst_sources = tk.Listbox(frm_paths, height=5, selectmode=tk.EXTENDED)
        self.lst_sources.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Button to remove selected source directories
        btn_remove_source = ttk.Button(
            frm_paths, text="Remove Selected Source(s)", command=self._remove_selected_sources
        )
        btn_remove_source.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        # Label for destination path
        btn_set_destination = ttk.Button(
            frm_paths, text="Set Destination Directory",
            command=self._set_destination
        )
        btn_set_destination.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.lbl_destination = ttk.Label(
            frm_paths, text="Not set", foreground="gray"
        )
        self.lbl_destination.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # -------- Options Frame --------
        frm_options = ttk.Labelframe(self, text="Migration Options", padding=8)
        frm_options.grid(row=1, column=0, sticky="nsew", padx=10, pady=8)
        frm_options.columnconfigure(1, weight=1)

        # File category checkboxes
        ttk.Label(frm_options, text="File Categories:").grid(
            row=0, column=0, sticky="nw"
        )
        category_container = ttk.Frame(frm_options)
        category_container.grid(row=0, column=1, sticky="w")
        idx = 0
        for name in CATEGORY_TO_EXTENSIONS:
            var = tk.BooleanVar(value=False)
            self.selected_categories[name] = var
            cb = ttk.Checkbutton(
                category_container, text=name, variable=var
            )
            cb.grid(row=idx//2, column=idx%2, padx=5, pady=3, sticky="w")
            idx += 1

        # Operation mode radio buttons
        ttk.Label(frm_options, text="Operation Mode:").grid(
            row=1, column=0, sticky="w", pady=10
        )
        mode_container = ttk.Frame(frm_options)
        mode_container.grid(row=1, column=1, sticky="w", pady=10)
        ttk.Radiobutton(
            mode_container, text="Move", variable=self.operation_mode, value="move"
        ).pack(side="left", padx=5)
        ttk.Radiobutton(
            mode_container, text="Copy", variable=self.operation_mode, value="copy"
        ).pack(side="left", padx=5)

        # -------- Control Frame --------
        frm_controls = ttk.Frame(self)
        frm_controls.grid(row=2, column=0, sticky="nsew", padx=10, pady=8)
        frm_controls.columnconfigure(1, weight=1)
        frm_controls.rowconfigure(1, weight=1)

        # Start and Pause buttons
        self.btn_start = ttk.Button(
            frm_controls, text="Start Migration", command=self._on_start
        )
        self.btn_start.grid(row=0, column=0, sticky="w", padx=5)

        self.btn_pause = ttk.Button(
            frm_controls, text="Pause",
            command=self._toggle_pause, state=tk.DISABLED
        )
        self.btn_pause.grid(row=0, column=2, sticky="e", padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(
            frm_controls, orient="horizontal", mode="determinate"
        )
        self.progress.grid(row=0, column=1, sticky="ew", padx=5)

        # Log text area
        self.txt_log = tk.Text(frm_controls, height=12, state=tk.DISABLED)
        self.txt_log.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=5)

        # Pack the main frame
        self.pack(fill="both", expand=True)

    # ----------------------------------------------------------------------------
    # UI Callbacks
    # ----------------------------------------------------------------------------
    def _add_source(self):
        """Open a folder dialog and add the selected folder to the source list."""
        directory = filedialog.askdirectory(title="Select Source Directory")
        if directory and directory not in self.source_dirs:
            self.source_dirs.append(directory)
            self.lst_sources.insert(tk.END, directory)

    def _remove_selected_sources(self):
        """Remove the selected source directories after user confirmation."""
        selection = list(self.lst_sources.curselection())
        if not selection:
            return
        count = len(selection)
        answer = messagebox.askyesno(
            "Confirm Remove",
            f"Are you sure you want to remove {count} selected source directory(ies)?"
        )
        if not answer:
            return
        # Remove from back to front so indices do not shift under us
        for idx in reversed(selection):
            path = self.lst_sources.get(idx)
            self.source_dirs.remove(path)
            self.lst_sources.delete(idx)

    def _set_destination(self):
        """Open a folder dialog and set the destination directory."""
        directory = filedialog.askdirectory(title="Select Destination Directory")
        if directory:
            self.destination_dir = directory
            self.lbl_destination.config(text=directory, foreground="green")

    def _on_start(self):
        """Handle Start Migration click: validate, confirm, then launch thread."""
        # Parameter validation
        if not self.source_dirs:
            messagebox.showwarning("Warning", "Please add at least one source directory.")
            return
        if not self.destination_dir:
            messagebox.showwarning("Warning", "Please set the destination directory.")
            return
        # Gather selected extensions
        chosen_exts = []
        for name, var in self.selected_categories.items():
            if var.get():
                chosen_exts.extend(CATEGORY_TO_EXTENSIONS[name])
        if not chosen_exts:
            messagebox.showwarning("Warning", "Please select at least one file category.")
            return

        # Confirm with user
        proceed = messagebox.askyesno(
            "Confirm Migration",
            "Are you sure you want to start the migration now?"
        )
        if not proceed:
            return

        # Disable Start, enable Pause
        self.btn_start.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL, text="Pause")
        self.pause_event.set()  # make sure not paused

        # Reset progress and clear log area
        self.progress["value"] = 0
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.configure(state=tk.DISABLED)

        # If brand-new run, clear log file
        if not self.processed_set:
            self._clear_log_file()

        # Launch background thread
        thread = threading.Thread(
            target=self._worker_task,
            args=(chosen_exts, self.operation_mode.get()),
            daemon=True
        )
        thread.start()

    def _toggle_pause(self):
        """Pause or resume the background migration thread."""
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="Resume")
            self._log("Migration paused by user.")
        else:
            self.pause_event.set()
            self.btn_pause.config(text="Pause")
            self._log("Migration resumed by user.")

    # ----------------------------------------------------------------------------
    # Background Worker Thread
    # ----------------------------------------------------------------------------
    def _worker_task(self, exts, mode):
        """Perform the file walk, copy/move, logging, resume logic."""
        # 1) Count total matching files for progress bar maximum
        total = 0
        for src in self.source_dirs:
            for root, _, files in os.walk(src):
                total += sum(1 for fn in files if Path(fn).suffix.lower() in exts)
        self.progress["maximum"] = total
        processed_count = 0

        self._log(f"Migration started. Total files to process: {total}")

        # 2) Walk each source
        for src in self.source_dirs:
            for root, _, files in os.walk(src):
                for fn in files:
                    ext = Path(fn).suffix.lower()
                    if ext not in exts:
                        continue

                    # Compute relative path for resume check
                    rel = str(Path(root).relative_to(src) / fn)
                    if rel in self.processed_set:
                        processed_count += 1
                        self.progress["value"] = processed_count
                        continue

                    # Pause support
                    self.pause_event.wait()

                    # Determine target directory under type folder
                    category = EXTENSION_TO_CATEGORY.get(ext, "Others")
                    target_dir = (
                        Path(self.destination_dir)
                        / category
                        / Path(rel).parent
                    )
                    target_dir.mkdir(parents=True, exist_ok=True)

                    # Resolve name collisions
                    target_path = self._find_unique_name(target_dir / fn)

                    source_path = Path(root) / fn
                    try:
                        if mode == "move":
                            shutil.move(str(source_path), str(target_path))
                            action = "MOVED"
                        else:
                            shutil.copy2(str(source_path), str(target_path))
                            action = "COPIED"
                        self._log(f"{action}: {source_path}  →  {target_path}")
                    except Exception as err:
                        self._log(f"ERROR: {source_path} -> {target_path}  ({err})")

                    # Update progress, save resume state
                    processed_count += 1
                    self.progress["value"] = processed_count
                    self.processed_set.add(rel)
                    self._save_state()

        # 3) Completed
        self._log(f"Migration complete. {processed_count} files processed.")
        # remove state file so next run is fresh
        try:
            os.remove(self.STATE_FILE)
        except Exception:
            pass

        # Restore button states on the GUI thread
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED)

    def _find_unique_name(self, path: Path) -> Path:
        """
        If path exists, append _1, _2, ... until a free name is found.
        """
        if not path.exists():
            return path
        base = path.stem
        ext = path.suffix
        index = 1
        while True:
            candidate = path.parent / f"{base}_{index}{ext}"
            if not candidate.exists():
                return candidate
            index += 1

    # ----------------------------------------------------------------------------
    # Logging and State Persistence
    # ----------------------------------------------------------------------------
    def _log(self, message: str):
        """
        Timestamp a message, write to disk log file, and enqueue for GUI display.
        """
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}"
        # Append to log file
        try:
            with open(self.LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
        # Enqueue for GUI flush
        self.log_queue.put(line)

    def _flush_log_to_text(self):
        """
        Periodically move queued log lines into the text widget.
        """
        while not self.log_queue.empty():
            line = self.log_queue.get()
            self.txt_log.configure(state=tk.NORMAL)
            self.txt_log.insert(tk.END, line + "\n")
            self.txt_log.see(tk.END)
            self.txt_log.configure(state=tk.DISABLED)
        self.after(100, self._flush_log_to_text)

    def _load_state(self):
        """Load the set of already processed relative paths from disk."""
        if not os.path.exists(self.STATE_FILE):
            self.processed_set = set()
            return
        try:
            with open(self.STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.processed_set = set(data)
        except Exception:
            self.processed_set = set()

    def _save_state(self):
        """Save the processed_set to disk for resume support."""
        try:
            with open(self.STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self.processed_set), f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _clear_log_file(self):
        """Clear the on-disk log file at the start of a fresh run."""
        try:
            open(self.LOG_FILE, "w", encoding="utf-8").close()
        except Exception:
            pass
# =============================================================================
# Application Entry Point
# =============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    app = BulkFileMigrator(root)
    root.mainloop()
"""
Bulk File Migrator is a desktop application built with Python 3 and Tkinter that allows users to select multiple source directories and one destination directory, then move or copy files of specified categories—such as images, videos, audio, text files, and common office documents—into organized subfolders.
Key Features:
1. Multiple Source Selection and Management  
   - Users can add as many source folders as needed via a folder-browse dialog.  
   - Any selected source can be removed with a single click, and the application will confirm before deletion.
2. Single Destination Directory  
   - Files will be consolidated under one chosen destination folder.  
   - Within that folder, subdirectories are created for each file category (for instance “Images”, “Videos”, etc.), ensuring a clean, high-level classification.
3. File Type Filtering  
   - Checkboxes let the user specify exactly which file types to include in the migration.  
   - Under the hood, each category maps to a list of common extensions (e.g., “.jpg”, “.mp4”, “.docx”).
4. Move or Copy Mode  
   - A pair of radio buttons toggle between moving files from source to destination or making a copy while leaving the originals intact.
5. Preservation of Relative Folder Structure  
   - Inside each category folder, the original directory structure (relative to its source root) is recreated to maintain context and avoid naming conflicts.
6. Automatic Collision Handling  
   - When two files from different locations share the same name, the application appends an index suffix (e.g., `_1`, `_2`) to ensure no data is overwritten.
7. Pause and Resume Support  
   - A background thread carries out all file operations so the user interface remains fully responsive.  
   - A Pause/Resume button lets the user temporarily halt the migration.  
   - If the application is closed or crashes, it records its progress in a JSON file and offers to resume on next start.
8. Progress Reporting and Logging  
   - A progress bar displays the count of processed files versus the total.  
   - All actions and errors are timestamped and shown in a scrolling text area, and they are also appended to a local log file for audit or debugging.
9. User Confirmations
   - The application asks for confirmation before removing sources and again before starting any migration, preventing accidental operations.
10. Clear, Customizable UI
    - The window initializes at 820×620 pixels with a clean “clam” theme.  
    - Fonts, labels, and button sizes have been explicitly set for readability.  
Bulk File Migrator streamlines large-scale file reorganization tasks by combining flexible filtering, reliable background execution, and robust resume capabilities into a single, easy-to-use interface.
"""
