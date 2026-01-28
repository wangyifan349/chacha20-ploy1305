"""
chacha20poly1305_batch_crypto_gui.py
A user-friendly PyQt5 and pycryptodome-based batch file encryptor/decryptor using Chacha20-Poly1305.
- Modern gold/red theme UI, large font for clarity.
- Recursively process all files in a directory (encrypt: only non-.enc files; decrypt: only .enc files).
- Multi-threaded fast processing; UI never hangs.
- Uses atomic file replacement (write to temp file, then rename), preserves original modification time.
- Checks for write permission and alerts user if access is denied.
- Password must be 32 characters, key derived via sha512.
IMPORTANT:
1. Please back up your data before using!
2. Original files are directly overwritten (decryption deletes .enc).
3. Reliable for large files, high safety.
Dependencies:
    pip install pyqt5 pycryptodome
"""

import sys
import os
import hashlib
import tempfile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QLineEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar, QRadioButton
)
from PyQt5.QtCore import Qt, QThreadPool, QRunnable, pyqtSignal, QObject, QMutex, QSize
from PyQt5.QtGui import QFont
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# Gold and red theme QSS for PyQt5
GOLD_RED_QSS = '''
QWidget {
    background-color: #2b0000;
}
QPushButton {
    color: #FFD700;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                               stop:0 #c04000, stop:1 #FFD700);
    border: 2px solid #FFD700;
    border-radius: 8px;
    font-weight: bold;
    font-size: 24px;
    padding: 12px 20px;
}
QLabel, QRadioButton {
    color: #FFD700;
    font-size: 24px;
    font-weight: bold;
}
QLineEdit {
    color: #c04000;
    background: #fff8e1;
    border: 2px solid #FFD700;
    border-radius: 8px;
    font-size: 24px;
    padding: 8px;
}
QProgressBar {
    border: 2px solid #FFD700;
    border-radius: 8px;
    text-align: center;
    font-size: 24px;
    color: #FFD700;
    background: #fff8e1;
}
QProgressBar::chunk {
    background-color: #ff0000;
}
'''

def derive_chacha_key(password_string):
    """Derive 32-byte key for Chacha20-Poly1305."""
    assert len(password_string) == 32
    return hashlib.sha512(password_string.encode("utf-8")).digest()[:32]

def collect_target_files(root_folder_path, operation_mode):
    """Collect all files to be encrypted or decrypted."""
    collected_files = []
    for directory_path, _, filenames in os.walk(root_folder_path):
        for filename in filenames:
            file_absolute_path = os.path.join(directory_path, filename)
            if operation_mode == "encrypt" and not filename.endswith(".enc"):
                collected_files.append(file_absolute_path)
            elif operation_mode == "decrypt" and filename.endswith(".enc"):
                collected_files.append(file_absolute_path)
    return collected_files

def check_path_writable(target_path):
    """
    Check if the given file path is writable.
    - If file exists: must be writable.
    - Directory must be writable and executable.
    """
    if os.path.exists(target_path) and not os.access(target_path, os.W_OK):
        return False
    parent_directory = os.path.dirname(target_path) or "."
    return os.access(parent_directory, os.W_OK | os.X_OK)

class GuiSignalProxy(QObject):
    """Signal proxy for inter-thread communications with the UI."""
    signal_update_progress = pyqtSignal(int, int)
    signal_work_finished = pyqtSignal(int, int)

class FileCryptoWorker(QRunnable):
    """
    File encryption/decryption worker for QThreadPool (runs in parallel).
    """
    completed_count = 0
    total_count = 0

    def __init__(self, file_path, chacha_key, operation_mode, gui_signal_proxy, count_mutex):
        super().__init__()
        self.file_path = file_path
        self.chacha_key = chacha_key
        self.operation_mode = operation_mode
        self.gui_signal_proxy = gui_signal_proxy
        self.count_mutex = count_mutex

    def run(self):
        try:
            if self.operation_mode == 'encrypt':
                self.encrypt_file_atomically()
            else:
                self.decrypt_file_atomically()
        except Exception:
            pass  # Skip failed files, proceed with the rest

        with QMutexLocker(self.count_mutex):
            FileCryptoWorker.completed_count += 1
            self.gui_signal_proxy.signal_update_progress.emit(
                FileCryptoWorker.completed_count, FileCryptoWorker.total_count
            )
            if FileCryptoWorker.completed_count == FileCryptoWorker.total_count:
                self.gui_signal_proxy.signal_work_finished.emit(
                    FileCryptoWorker.completed_count, FileCryptoWorker.total_count
                )

    def encrypt_file_atomically(self):
        """Encrypt and atomically replace the file, preserving mtime."""
        source_path = self.file_path
        encrypted_path = self.file_path + ".enc"

        with open(source_path, "rb") as source_file:
            file_data = source_file.read()
        nonce_bytes = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=self.chacha_key, nonce=nonce_bytes)
        encrypted_data, tag_bytes = cipher.encrypt_and_digest(file_data)
        raw_content = nonce_bytes + tag_bytes + encrypted_data

        parent_directory = os.path.dirname(source_path)
        with tempfile.NamedTemporaryFile(delete=False, dir=parent_directory) as temp_file:
            temp_file.write(raw_content)
            temp_output_path = temp_file.name

        os.replace(temp_output_path, encrypted_path)       # Atomic file replacement
        file_stat = os.stat(source_path)
        os.utime(encrypted_path, (file_stat.st_atime, file_stat.st_mtime))  # Restore original times
        os.remove(source_path)                             # Remove original

    def decrypt_file_atomically(self):
        """Decrypt and atomically replace the file, preserving mtime."""
        encrypted_path = self.file_path
        if not encrypted_path.endswith('.enc'):
            return
        decrypted_path = encrypted_path[:-4]

        with open(encrypted_path, "rb") as encrypted_file:
            nonce_bytes = encrypted_file.read(12)
            tag_bytes = encrypted_file.read(16)
            ciphertext_bytes = encrypted_file.read()
        cipher = ChaCha20_Poly1305.new(key=self.chacha_key, nonce=nonce_bytes)
        decrypted_data = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)

        parent_directory = os.path.dirname(encrypted_path)
        with tempfile.NamedTemporaryFile(delete=False, dir=parent_directory) as temp_file:
            temp_file.write(decrypted_data)
            temp_output_path = temp_file.name

        os.replace(temp_output_path, decrypted_path)       # Atomic file replacement
        file_stat = os.stat(encrypted_path)
        os.utime(decrypted_path, (file_stat.st_atime, file_stat.st_mtime))  # Restore original times
        os.remove(encrypted_path)                          # Remove encrypted

from PyQt5.QtCore import QMutex, QMutexLocker

class MainCryptoWindow(QWidget):
    """Main PyQt5 Window for the Batch Encrypt/Decrypt Tool."""
    def __init__(self):
        super().__init__()
        self.setFont(QFont("Arial", 24))
        self.setStyleSheet(GOLD_RED_QSS)
        self.setWindowTitle("Chacha20-Poly1305 Batch Crypto")
        self.setFixedSize(QSize(720, 520))

        main_layout = QVBoxLayout()
        main_layout.setSpacing(22)

        label_main_title = QLabel("Chacha20-Poly1305 Batch File Encrypt/Decrypt")
        label_main_title.setAlignment(Qt.AlignCenter)
        label_main_title.setStyleSheet("font-size:44px; color:#FFD700; font-weight:bold;")
        main_layout.addWidget(label_main_title)

        layout_mode_select = QHBoxLayout()
        self.radio_encrypt = QRadioButton("Encrypt")
        self.radio_decrypt = QRadioButton("Decrypt")
        self.radio_encrypt.setChecked(True)
        layout_mode_select.addWidget(self.radio_encrypt)
        layout_mode_select.addWidget(self.radio_decrypt)
        main_layout.addLayout(layout_mode_select)

        layout_folder_select = QHBoxLayout()
        self.label_selected_folder = QLabel("No directory selected")
        self.label_selected_folder.setMinimumWidth(400)
        button_choose_folder = QPushButton("Choose Directory")
        button_choose_folder.clicked.connect(self.select_working_folder)
        layout_folder_select.addWidget(self.label_selected_folder)
        layout_folder_select.addWidget(button_choose_folder)
        main_layout.addLayout(layout_folder_select)

        self.input_password = QLineEdit()
        self.input_password.setPlaceholderText("Enter 32-character password")
        self.input_password.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(self.input_password)

        self.button_start_work = QPushButton("Start!")
        self.button_start_work.clicked.connect(self.launch_crypto_job)
        main_layout.addWidget(self.button_start_work)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(40)
        main_layout.addWidget(self.progress_bar)

        self.setLayout(main_layout)
        self.working_folder_path = None
        self.thread_pool = QThreadPool.globalInstance()

    def select_working_folder(self):
        """Pop up to select folder, update the label."""
        folder_path = QFileDialog.getExistingDirectory(self, "Select directory for batch operation")
        if folder_path:
            self.working_folder_path = folder_path
            self.label_selected_folder.setText(folder_path)

    def launch_crypto_job(self):
        """Main entry: parameter check and thread start."""
        input_password_str = self.input_password.text()
        if not self.working_folder_path:
            QMessageBox.warning(self, "Error", "Please select a directory first!")
            return
        if len(input_password_str) != 32:
            QMessageBox.warning(self, "Error", "Password must be exactly 32 characters!")
            return
        work_mode = "encrypt" if self.radio_encrypt.isChecked() else "decrypt"
        list_target_files = collect_target_files(self.working_folder_path, work_mode)
        if not list_target_files:
            QMessageBox.information(self, "No Files", "No files to process in this directory!")
            return

        # Check permissions in advance
        files_no_permission = []
        for source_file_path in list_target_files:
            if work_mode == 'encrypt':
                target_path = source_file_path + '.enc'
            else:
                target_path = source_file_path[:-4]
            if not check_path_writable(target_path):
                files_no_permission.append(target_path)
        if files_no_permission:
            QMessageBox.critical(
                self, "Insufficient Permission",
                "No write access to the following files or directories:\n" +
                "\n".join(files_no_permission[:5]) +
                ("\n..." if len(files_no_permission) > 5 else "")
            )
            return

        self.progress_bar.setMaximum(len(list_target_files))
        self.progress_bar.setValue(0)
        self.button_start_work.setEnabled(False)
        self.input_password.setEnabled(False)
        self.radio_encrypt.setEnabled(False)
        self.radio_decrypt.setEnabled(False)

        # Set up progress count and signals
        FileCryptoWorker.completed_count = 0
        FileCryptoWorker.total_count = len(list_target_files)
        count_mutex = QMutex()
        gui_signal_proxy = GuiSignalProxy()
        gui_signal_proxy.signal_update_progress.connect(self._on_progress_update)
        gui_signal_proxy.signal_work_finished.connect(self._on_work_finished)

        # Key derivation
        try:
            chacha20_key = derive_chacha_key(input_password_str)
        except Exception:
            QMessageBox.warning(self, "Password Error", "Password must be exactly 32 ASCII characters!")
            return

        # Launch worker threads
        for each_file_path in list_target_files:
            crypto_task = FileCryptoWorker(each_file_path, chacha20_key, work_mode, gui_signal_proxy, count_mutex)
            self.thread_pool.start(crypto_task)

    def _on_progress_update(self, current_count, total_count):
        self.progress_bar.setValue(current_count)  # Progress bar update

    def _on_work_finished(self, completed_count, total_count):
        self.button_start_work.setEnabled(True)
        self.input_password.setEnabled(True)
        self.radio_encrypt.setEnabled(True)
        self.radio_decrypt.setEnabled(True)
        QMessageBox.information(self, "Done", f"Processed {completed_count} / {total_count} files!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainCryptoWindow()
    main_window.show()
    sys.exit(app.exec_())
