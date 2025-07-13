import os                                # Operating system interfaces
import shutil                            # High-level file operations
import threading                         # Thread-based parallelism
import tkinter as tk                     # Core Tk GUI toolkit
from tkinter import ttk                  # Themed Tk widgets
from tkinter import messagebox           # Standard message dialogs
from tkinter import filedialog           # File/directory selection dialogs

# Supported media file extensions
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
VIDEO_EXTENSIONS = {'.mp4', '.avi', '.mkv', '.mov', '.wmv'}
AUDIO_EXTENSIONS = {'.mp3', '.wav', '.aac', '.flac', '.ogg'}
ALLOWED_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS | AUDIO_EXTENSIONS


def generate_unique_filename(destination_directory, original_filename):
    """
    Generate a unique filename within the destination directory to avoid overwriting.

    Args:
        destination_directory (str): Path to the destination folder.
        original_filename (str): Original file name with extension.

    Returns:
        str: A unique file name that does not exist in the destination directory.
    """
    name_base, extension = os.path.splitext(original_filename)                   # Split name and extension
    candidate_name = original_filename                                           # Initial candidate
    counter = 1                                                                   # Suffix counter

    # Loop until a non-existing filename is found
    while os.path.exists(os.path.join(destination_directory, candidate_name)):
        candidate_name = f"{name_base}_{counter}{extension}"                     # Append suffix
        counter += 1                                                              # Increment counter

    return candidate_name                                                         # Return unique filename


class MediaFileMigratorApplication(ttk.Frame):
    """
    Main application frame for the media file migrator.
    Hosts GUI components and migration logic.
    """

    def __init__(self, master=None):
        """
        Initialize the application frame, setup styles, variables, and layout.

        Args:
            master: The parent tk.Tk instance.
        """
        super().__init__(master, padding=10)                                     # Initialize parent frame
        master.title("Media File Migrator")                                      # Set window title
        master.minsize(800, 600)                                                  # Set minimum window size

        self.source_directories = []                                              # List[str]: source folders
        self.target_directory_path = tk.StringVar()                               # StringVar: target folder path

        self.initialize_styles()                                                  # Configure ttk styles
        self.create_widgets()                                                     # Instantiate widgets
        self.layout_widgets()                                                     # Position widgets in grid

    def initialize_styles(self):
        """
        Define and configure ttk styles for consistent look & feel.
        """
        style = ttk.Style()                                                       # Style manager
        style.theme_use('clam')                                                   # Use the 'clam' theme

        style.configure('HeaderLabel.TLabel',
                        font=('Segoe UI', 18, 'bold'),
                        foreground='#333333')                                     # Header label style

        style.configure('ActionButton.TButton',
                        font=('Segoe UI', 11),
                        padding=6)                                                # Standard button style

        style.map('ActionButton.TButton',
                  foreground=[('disabled', '#AAAAAA'), ('!disabled', '#000000')],
                  background=[('pressed', '#DDDDDD'), ('!pressed', '#F0F0F0')])   # Button state mapping

        style.configure('BodyLabel.TLabel',
                        font=('Segoe UI', 11),
                        foreground='#333333')                                     # Body label style

        style.configure('MediaProgress.TProgressbar',
                        thickness=20)                                             # Progressbar thickness

    def create_widgets(self):
        """
        Instantiate all GUI widgets (labels, buttons, text areas, etc.).
        """
        # Header label
        self.header_label = ttk.Label(self,
                                      text="Media File Migrator",
                                      style='HeaderLabel.TLabel')               # Big title label

        # Source directories group
        self.source_frame = ttk.Labelframe(self,
                                           text="Source Directories",
                                           padding=10)                             # Frame for sources
        self.source_listbox = tk.Listbox(self.source_frame,
                                         font=('Segoe UI', 11))                 # Shows added dirs
        self.source_scrollbar = ttk.Scrollbar(self.source_frame,
                                              orient='vertical',
                                              command=self.source_listbox.yview)   # Scrollbar for listbox
        self.source_listbox.configure(yscrollcommand=self.source_scrollbar.set)   # Link scrollbar

        self.button_add_source = ttk.Button(self.source_frame,
                                            text="Add Source",
                                            style='ActionButton.TButton',
                                            command=self.add_source_directory)     # Add directory button
        self.button_remove_source = ttk.Button(self.source_frame,
                                               text="Remove Selected",
                                               style='ActionButton.TButton',
                                               command=self.remove_selected_source_directory) # Remove button
        self.button_count_files = ttk.Button(self.source_frame,
                                             text="Count Files",
                                             style='ActionButton.TButton',
                                             command=self.count_media_files)        # Count files button
        self.label_file_count = ttk.Label(self.source_frame,
                                          text="Files to Process: 0",
                                          style='BodyLabel.TLabel')                # Displays file count

        # Target directory group
        self.target_frame = ttk.Labelframe(self,
                                           text="Target Directory",
                                           padding=10)                             # Frame for target
        self.button_select_target = ttk.Button(self.target_frame,
                                               text="Select Target",
                                               style='ActionButton.TButton',
                                               command=self.select_target_directory) # Select target button
        self.entry_target = ttk.Entry(self.target_frame,
                                      textvariable=self.target_directory_path,
                                      font=('Segoe UI', 11))                    # Shows target path

        # Action buttons and progress bar
        self.action_frame = ttk.Frame(self, padding=10)                            # Container for action row
        self.button_start_migration = ttk.Button(self.action_frame,
                                                 text="Start Migration",
                                                 style='ActionButton.TButton',
                                                 command=self.start_migration_process) # Start migration
        self.button_clear_log = ttk.Button(self.action_frame,
                                           text="Clear Log",
                                           style='ActionButton.TButton',
                                           command=self.clear_log_text)         # Clear log area
        self.progress_bar = ttk.Progressbar(self.action_frame,
                                            orient='horizontal',
                                            mode='determinate',
                                            style='MediaProgress.TProgressbar')  # Progress bar

        # Logging text area
        self.log_frame = ttk.Labelframe(self,
                                        text="Status Log",
                                        padding=10)                                # Frame for log
        self.log_text = tk.Text(self.log_frame,
                                height=10,
                                state='disabled',
                                wrap='word',                                    # Multi-line log
                                font=('Segoe UI', 11))
        self.log_scrollbar = ttk.Scrollbar(self.log_frame,
                                           orient='vertical',
                                           command=self.log_text.yview)          # Scrollbar for log
        self.log_text.configure(yscrollcommand=self.log_scrollbar.set)            # Link scrollbar

        # About button
        self.button_about = ttk.Button(self,
                                       text="About",
                                       style='ActionButton.TButton',
                                       command=self.show_about_dialog)          # About dialog

    def layout_widgets(self):
        """
        Arrange all widgets using grid geometry for responsive layout.
        """
        self.grid(sticky='nsew')                                                 # Fill parent
        self.master.rowconfigure(3, weight=1)                                     # Make log area expand
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)

        # Place header label
        self.header_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))

        # Layout source frame and its contents
        self.source_frame.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
        self.source_frame.rowconfigure(0, weight=1)
        self.source_frame.columnconfigure(0, weight=1)

        self.source_listbox.grid(row=0, column=0, rowspan=4, sticky='nsew', padx=(0, 5))
        self.source_scrollbar.grid(row=0, column=1, rowspan=4, sticky='ns')

        self.button_add_source.grid(row=0, column=2, padx=5, pady=2, sticky='ew')
        self.button_remove_source.grid(row=1, column=2, padx=5, pady=2, sticky='ew')
        self.button_count_files.grid(row=2, column=2, padx=5, pady=2, sticky='ew')
        self.label_file_count.grid(row=3, column=2, padx=5, pady=2)

        # Layout target frame and its widgets
        self.target_frame.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        self.target_frame.columnconfigure(1, weight=1)

        self.button_select_target.grid(row=0, column=0, padx=5, pady=5)
        self.entry_target.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Layout action frame
        self.action_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=10)
        self.action_frame.columnconfigure(0, weight=1)

        self.button_start_migration.grid(row=0, column=0, padx=5)
        self.button_clear_log.grid(row=0, column=1, padx=5)
        self.progress_bar.grid(row=1, column=0, columnspan=2, padx=5, pady=(10, 0), sticky='ew')

        # Layout log frame
        self.log_frame.grid(row=3, column=0, columnspan=2, sticky='nsew', pady=5)
        self.log_frame.rowconfigure(0, weight=1)
        self.log_frame.columnconfigure(0, weight=1)

        self.log_text.grid(row=0, column=0, sticky='nsew')
        self.log_scrollbar.grid(row=0, column=1, sticky='ns')

        # Place about button
        self.button_about.grid(row=4, column=1, sticky='e', padx=5, pady=5)

    def log_message(self, message_text):
        """
        Append a line of text to the status log.

        Args:
            message_text (str): The message to append.
        """
        self.log_text.configure(state='normal')                                 # Enable editing
        self.log_text.insert('end', message_text + '\n')                         # Insert new line
        self.log_text.see('end')                                                 # Scroll to bottom
        self.log_text.configure(state='disabled')                                # Disable editing

    def clear_log_text(self):
        """
        Clear all contents from the status log.
        """
        self.log_text.configure(state='normal')                                 # Enable editing
        self.log_text.delete('1.0', 'end')                                       # Delete all text
        self.log_text.configure(state='disabled')                                # Disable editing

    def add_source_directory(self):
        """
        Open a directory chooser and add selected directory to the source list.
        """
        selected_directory = filedialog.askdirectory(title="Select Source Directory")  # Show dialog
        if not selected_directory:                                               # If user canceled
            return
        if selected_directory in self.source_directories:                        # Duplicate check
            messagebox.showinfo("Information", "Directory already added.")       # Inform user
            return

        self.source_directories.append(selected_directory)                       # Add to list
        self.source_listbox.insert('end', selected_directory)                    # Show in listbox
        self.log_message(f"Added source directory: {selected_directory}")        # Log action

    def remove_selected_source_directory(self):
        """
        Remove selected entries from the source listbox and internal list.
        """
        selected_indices = list(self.source_listbox.curselection())              # Get all selected rows
        if not selected_indices:                                                 # If none selected
            messagebox.showwarning("Warning", "Please select at least one directory to remove.")  # Warn
            return

        for index in reversed(selected_indices):                                 # Remove in reverse order
            removed_path = self.source_directories.pop(index)                    # Remove from list
            self.source_listbox.delete(index)                                    # Remove from UI
            self.log_message(f"Removed source directory: {removed_path}")        # Log removal

        self.count_media_files()                                                 # Update file count

    def select_target_directory(self):
        """
        Open a directory chooser and set the selected path as target.
        """
        selected_directory = filedialog.askdirectory(title="Select Target Directory")  # Show dialog
        if selected_directory:                                                    # If user chose
            self.target_directory_path.set(selected_directory)                    # Update StringVar
            self.log_message(f"Set target directory: {selected_directory}")       # Log action

    def count_media_files(self):
        """
        Walk through all source directories and count files matching allowed extensions.

        Returns:
            int: Total count of files that can be processed.
        """
        total_file_count = 0                                                      # Initialize counter
        for source_path in self.source_directories:                               # For each source dir
            for root_path, _, file_list in os.walk(source_path):                  # Recursively walk
                for file_name in file_list:                                       # For each file
                    if os.path.splitext(file_name)[1].lower() in ALLOWED_EXTENSIONS:  # Extension check
                        total_file_count += 1                                     # Increment counter

        self.label_file_count.configure(text=f"Files to Process: {total_file_count}")  # Update label
        self.log_message(f"Count complete: {total_file_count} files found.")       # Log result
        return total_file_count                                                   # Return value

    def start_migration_process(self):
        """
        Validate inputs and launch the migration process in a separate thread.
        """
        if not self.source_directories:                                          # No source dirs
            messagebox.showerror("Error", "Please add at least one source directory.")  # Show error
            return
        if not self.target_directory_path.get():                                 # No target dir
            messagebox.showerror("Error", "Please select a target directory.")   # Show error
            return

        total_files = self.count_media_files()                                   # Count files
        if total_files == 0:                                                     # Nothing to do
            messagebox.showinfo("Information", "No files to move.")             # Inform user
            return

        confirmation = messagebox.askyesno("Confirm",                             
                                           f"About to move {total_files} files to:\n"
                                           f"{self.target_directory_path.get()}\nProceed?")
        if not confirmation:                                                     # User canceled
            return

        # Disable all action buttons during migration
        for button in (self.button_add_source,
                       self.button_remove_source,
                       self.button_count_files,
                       self.button_select_target,
                       self.button_start_migration):
            button.configure(state='disabled')                                   # Disable each

        # Initialize progress bar
        self.progress_bar.configure(value=0, maximum=total_files)               # Set range

        self.log_message("Starting migration...")                                # Log start

        # Launch migration in background thread
        thread = threading.Thread(target=self.execute_migration, daemon=True)
        thread.start()                                                           # Start thread

    def execute_migration(self):
        """
        Perform the actual file scanning and moving. Runs in a separate thread.
        """
        target_path = self.target_directory_path.get()                           # Get target path

        # Check writability
        if not os.access(target_path, os.W_OK):
            self.log_message(f"Target directory not writable: {target_path}. Aborting.")
            self.finish_migration()                                             # Re-enable buttons
            return

        files_scanned = 0                                                        # Counter for scanned files
        files_moved = 0                                                          # Counter for moved files

        # Traverse each source directory
        for source_path in self.source_directories:
            self.log_message(f"Processing source directory: {source_path}")      # Log progress
            for root_path, _, file_list in os.walk(source_path):                 # Walk tree
                for file_name in file_list:                                      # Each file
                    files_scanned += 1                                           # Increment scanned
                    extension_lower = os.path.splitext(file_name)[1].lower()     # Get extension

                    if extension_lower not in ALLOWED_EXTENSIONS:                # Skip unwanted
                        continue

                    source_file_path = os.path.join(root_path, file_name)        # Full source path
                    if not os.access(source_file_path, os.R_OK):                # Check read permission
                        self.log_message(f"Skipping (no read permission): {source_file_path}")
                        continue

                    # Generate a unique name and move
                    unique_name = generate_unique_filename(target_path, file_name)
                    destination_file_path = os.path.join(target_path, unique_name)

                    try:
                        shutil.move(source_file_path, destination_file_path)    # Move file
                        files_moved += 1                                        # Increment moved
                        self.log_message(f"Moved: {source_file_path} -> {destination_file_path}")
                    except Exception as error_instance:
                        self.log_message(f"Error moving {source_file_path} -> {destination_file_path}\nError: {error_instance}")

                    # Update progress bar
                    self.progress_bar.configure(value=files_moved)
                    self.progress_bar.update_idletasks()                       # Refresh UI

        # Summary log
        summary_text = (
            f"\nTotal files scanned: {files_scanned}\n"
            f"Files successfully moved: {files_moved}\n"
            "Migration complete."
        )
        self.log_message(summary_text)                                           # Log summary
        messagebox.showinfo("Migration Complete", summary_text)                  # Show dialog
        self.finish_migration()                                                  # Re-enable buttons

    def finish_migration(self):
        """
        Re-enable all action buttons after migration is complete or aborted.
        """
        for button in (self.button_add_source,
                       self.button_remove_source,
                       self.button_count_files,
                       self.button_select_target,
                       self.button_start_migration):
            button.configure(state='normal')                                     # Enable each

    def show_about_dialog(self):
        """
        Display the About dialog with application information.
        """
        messagebox.showinfo(
            "About Media File Migrator",
            "Media File Migrator v1.0\n"
            "Author: Your Name\n\n"
            "Bulk move supported image, video, and audio files."
        )


if __name__ == "__main__":
    root_window = tk.Tk()                                                      # Create main window
    app_frame = MediaFileMigratorApplication(master=root_window)               # Instantiate app
    app_frame.pack(fill='both', expand=True)                                   # Pack frame
    root_window.mainloop()                                                     # Enter event loop
