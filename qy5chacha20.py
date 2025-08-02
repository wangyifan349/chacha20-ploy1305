import sys
import os
import tempfile
from pathlib import Path
from functools import partial

from PyQt5.QtWidgets import (
    QApplication, QWidget, QFileDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit, QSpinBox,
    QMessageBox, QFrame, QScrollBar
)
from PyQt5.QtCore import Qt, QRunnable, QThreadPool, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor, QFont

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


# --- Encryption/decryption and key functions ---

def generate_key(path):
    key = get_random_bytes(32)
    with open(path, 'wb') as f:
        f.write(key)
    return f"[INFO] ✔ Generated new key file: {path}"

def load_key(path):
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != 32:
        raise ValueError("Key file length must be 32 bytes")
    return data

def encrypt_file_in_place(key, filepath):
    try:
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        temp_file = tempfile.NamedTemporaryFile(dir=filepath.parent, delete=False)
        with open(temp_file.name, 'wb') as f:
            f.write(nonce + tag + ciphertext)
        os.replace(temp_file.name, str(filepath))
        return f"[ENC] {filepath.name}"
    except Exception as e:
        return f"[ERR] Encrypt failed: {filepath.name} -> {e}"

def decrypt_file_in_place(key, filepath):
    if not filepath.name.endswith(".enc"):
        return f"[SKIP] Not .enc file: {filepath.name}"
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if len(data) < 28:
            return f"[ERR] File too short: {filepath.name}"
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        new_file = filepath.with_name(filepath.stem)
        temp_file = tempfile.NamedTemporaryFile(dir=filepath.parent, delete=False)
        with open(temp_file.name, 'wb') as f:
            f.write(plaintext)
        os.replace(temp_file.name, str(new_file))
        os.remove(str(filepath))
        return f"[DEC] {filepath.name} -> {new_file.name}"
    except Exception as e:
        return f"[FAIL] Decrypt failed: {filepath.name} -> {e}"

def walk_files(root_path):
    if root_path.is_file():
        yield root_path
    else:
        for dirpath, _, filenames in os.walk(root_path):
            for filename in filenames:
                yield Path(dirpath) / filename


# --- Signals for threading ---

class WorkerSignals(QObject):
    result = pyqtSignal(str)
    finished = pyqtSignal()


# --- Worker runnable ---

class EncryptDecryptRunnable(QRunnable):
    def __init__(self, mode, keyfile, rootpath, workers, signals):
        super().__init__()
        self.mode = mode
        self.keyfile = Path(keyfile)
        self.rootpath = Path(rootpath) if rootpath else None
        self.workers = workers
        self.signals = signals

    def run(self):
        import concurrent.futures
        try:
            if self.mode == "genkey":
                msg = generate_key(self.keyfile)
                self.signals.result.emit(msg)
                self.signals.finished.emit()
                return

            if not self.rootpath or not self.rootpath.exists():
                self.signals.result.emit(f"[ERR] Target path does not exist: {self.rootpath}")
                self.signals.finished.emit()
                return

            key = load_key(self.keyfile)

            if self.mode == "enc":
                worker_func = encrypt_file_in_place
            else:
                worker_func = decrypt_file_in_place

            files_list = []
            for f in walk_files(self.rootpath):
                files_list.append(f)

            total_files = len(files_list)
            self.signals.result.emit(f"[INFO] Mode={self.mode} Target={self.rootpath} Files={total_files} Threads={self.workers}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = {executor.submit(worker_func, key, f): f for f in files_list}
                index = 0
                for future in concurrent.futures.as_completed(futures):
                    index += 1
                    try:
                        result_message = future.result()
                    except Exception as e:
                        result_message = f"[ERR] Exception: {e}"
                    self.signals.result.emit(f"[{index}/{total_files}] {result_message}")

            self.signals.finished.emit()

        except Exception as e:
            self.signals.result.emit(f"[ERR] Task failure: {e}")
            self.signals.finished.emit()


# --- UI and app functions ---

def main_qss():
    return """
    QWidget {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 #e0f2e9, stop:1 #b1d8b7);
        color: #2c3e26;
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    }
    #title_label {
        font-size: 22px;
        font-weight: bold;
        color: #2a5d34;
        margin-bottom: 10px;
        text-shadow: 1px 1px 3px rgba(0,0,0,0.1);
    }
    #operation_frame {
        background: #dff1dcaa;
        border-radius: 12px;
        padding: 15px;
        border: 1.5px solid #a2c3a0;
        box-shadow: 0 4px 10px rgba(100, 130, 110, 0.3);
    }
    QLabel {
        font-weight: 600;
        font-size: 14px;
    }
    QLineEdit {
        border: 2px solid #a9c9a4;
        border-radius: 7px;
        padding: 7px 10px;
        background: #ecf7ed;
        selection-background-color: #88c17e;
        font-size: 14px;
    }
    QLineEdit:focus {
        border-color: #7bc867;
        background: #e4fcdd;
    }
    QComboBox {
        border: 2px solid #a9c9a4;
        border-radius: 7px;
        padding: 5px 10px;
        background: #e0f2e9;
        font-size: 14px;
        min-width: 100px;
    }
    QComboBox:hover {
        border-color: #7bc867;
    }
    QSpinBox {
        border: 2px solid #a9c9a4;
        border-radius: 7px;
        padding: 4px 10px;
        background: #e0f2e9;
        font-size: 14px;
        min-width: 60px;
    }
    QSpinBox:hover {
        border-color: #7bc867;
    }
    QPushButton {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 #8bca52, stop:1 #5a9a1d);
        border: none;
        color: white;
        font-weight: 700;
        font-size: 16px;
        border-radius: 10px;
        padding: 10px 28px;
        box-shadow: 0 4px 10px rgba(56,100,20,0.35);
    }
    QPushButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 #a4d16c, stop:1 #6fac29);
        box-shadow: 0 6px 12px rgba(88,130,28,0.5);
    }
    QPushButton:pressed {
        background: qlineargradient(x1:0, y1:1, x2:0, y2:0,
                                    stop:0 #609a15, stop:1 #9ec54a);
        box-shadow: inset 0 2px 6px rgba(56,100,20,0.8);
    }
    QPushButton:disabled {
        background-color: #a9c9a480;
        color: #e0e0e0;
        box-shadow: none;
        cursor: not-allowed;
    }
    #log_text_edit {
        border: 2px solid #a9c9a4;
        border-radius: 10px;
        background: #f5f9f5;
        padding: 8px;
        font-family: Consolas, monospace;
        font-size: 13px;
    }
    """


def animate_button_click(button):
    from PyQt5.QtCore import QPropertyAnimation, QEasingCurve
    geometry = button.geometry()
    animation = QPropertyAnimation(button, b"geometry")
    animation.setDuration(180)
    animation.setEasingCurve(QEasingCurve.InOutQuad)
    animation.setStartValue(geometry)
    animation.setKeyValueAt(0.5, geometry.adjusted(-4, -2, 4, 2))
    animation.setEndValue(geometry)
    animation.start()
    # To keep reference so garbage collection doesn't stop animation early
    button._animation = animation


def append_log(text_edit, text):
    cursor = text_edit.textCursor()
    cursor.movePosition(QTextCursor.End)
    fmt = QTextCharFormat()
    lower_text = text.lower()

    if "[err]" in lower_text or "[fail]" in lower_text or "[skip]" in lower_text:
        fmt.setForeground(QColor(230, 60, 60))  # Red
        fmt.setFontWeight(QFont.Bold)
    elif "[info]" in lower_text or "[*]" in lower_text or "[enc]" in lower_text or "[dec]" in lower_text or "[+]" in lower_text or "[✔]" in lower_text:
        fmt.setForeground(QColor(26, 115, 40))  # Dark green
    else:
        fmt.setForeground(QColor(40, 40, 40))  # Normal text color
    cursor.insertText(text + "\n", fmt)
    scroll_bar = text_edit.verticalScrollBar()
    scroll_bar.setValue(scroll_bar.maximum())


def on_mode_changed(combo_mode, line_root):
    mode = combo_mode.currentText()
    if mode == "genkey":
        line_root.setEnabled(False)
        line_root.clear()
        line_root.setPlaceholderText("No target path needed")
    else:
        line_root.setEnabled(True)
        line_root.setPlaceholderText("Select target directory or file")


def select_keyfile(edit_keyfile, combo_mode, parent_widget):
    mode = combo_mode.currentText()
    options = QFileDialog.Options()
    if mode == "genkey":
        path, _ = QFileDialog.getSaveFileName(parent_widget, "Save key file", "", "Key Files (*.key);;All Files (*)", options=options)
    else:
        path, _ = QFileDialog.getOpenFileName(parent_widget, "Select key file", "", "Key Files (*.key);;All Files (*)", options=options)
    if path:
        edit_keyfile.setText(path)


def select_root(edit_root, combo_mode, parent_widget):
    mode = combo_mode.currentText()
    options = QFileDialog.Options()
    if mode == "genkey":
        return  # no target required

    dlg = QMessageBox(parent_widget)
    dlg.setWindowTitle("Select target type")
    dlg.setText("Select target type: Directory or File?")
    button_dir = dlg.addButton("Directory", QMessageBox.AcceptRole)
    button_file = dlg.addButton("File", QMessageBox.AcceptRole)
    dlg.addButton("Cancel", QMessageBox.RejectRole)
    dlg.exec_()

    if dlg.clickedButton() == button_dir:
        path = QFileDialog.getExistingDirectory(parent_widget, "Select directory", options=options)
        if path:
            edit_root.setText(path)
    elif dlg.clickedButton() == button_file:
        path, _ = QFileDialog.getOpenFileName(parent_widget, "Select file", "", "All Files (*)", options=options)
        if path:
            edit_root.setText(path)


def start_operation(combo_mode, edit_keyfile, edit_root, spin_workers, button_start, combo_mode_widget, spin_workers_widget, edit_keyfile_widget, edit_root_widget, text_log, thread_pool):

    animate_button_click(button_start)

    mode = combo_mode.currentText()
    keyfile = edit_keyfile.text().strip()
    root = edit_root.text().strip()
    workers = spin_workers.value()

    if not keyfile:
        QMessageBox.warning(button_start.parentWidget(), "Parameter error", "Please specify key file path")
        return

    if mode != "genkey" and not root:
        QMessageBox.warning(button_start.parentWidget(), "Parameter error", "Please select target directory or file path")
        return

    # Disable controls
    button_start.setEnabled(False)
    combo_mode_widget.setEnabled(False)
    spin_workers_widget.setEnabled(False)
    edit_keyfile_widget.setEnabled(False)
    edit_root_widget.setEnabled(False)

    text_log.clear()
    append_log(text_log, "[*] Task started...")

    signals = WorkerSignals()
    signals.result.connect(partial(append_log, text_log))

    def on_finish():
        append_log(text_log, "[*] Task completed ✅")
        button_start.setEnabled(True)
        combo_mode_widget.setEnabled(True)
        spin_workers_widget.setEnabled(True)
        edit_keyfile_widget.setEnabled(True)
        edit_root_widget.setEnabled(True)

    signals.finished.connect(on_finish)

    runnable = EncryptDecryptRunnable(mode, keyfile, root, workers, signals)
    thread_pool.start(runnable)


def main():
    app = QApplication(sys.argv)

    window = QWidget()
    window.setWindowTitle("ChaCha20-Poly1305 Multithreaded Encrypt/Decrypt Tool")
    window.resize(760, 560)
    window.setStyleSheet(main_qss())

    thread_pool = QThreadPool.globalInstance()

    main_layout = QVBoxLayout()
    main_layout.setContentsMargins(15,15,15,15)
    main_layout.setSpacing(12)

    title_label = QLabel("🔐 ChaCha20-Poly1305 Multithreaded Encrypt/Decrypt Tool")
    title_label.setObjectName("title_label")
    title_label.setAlignment(Qt.AlignCenter)
    main_layout.addWidget(title_label)

    operation_frame = QFrame()
    operation_frame.setObjectName("operation_frame")
    operation_layout = QVBoxLayout()
    operation_layout.setSpacing(10)

    mode_workers_layout = QHBoxLayout()
    mode_workers_layout.setSpacing(15)

    label_mode = QLabel("Mode:")
    label_mode.setFixedWidth(60)
    combo_mode = QComboBox()
    combo_mode.addItems(["genkey", "enc", "dec"])
    combo_mode.setFixedWidth(120)
    mode_workers_layout.addWidget(label_mode)
    mode_workers_layout.addWidget(combo_mode)

    label_workers = QLabel("Threads:")
    label_workers.setFixedWidth(60)
    spin_workers = QSpinBox()
    spin_workers.setRange(1, 32)
    spin_workers.setValue(6)
    spin_workers.setFixedWidth(70)
    mode_workers_layout.addStretch()
    mode_workers_layout.addWidget(label_workers)
    mode_workers_layout.addWidget(spin_workers)

    operation_layout.addLayout(mode_workers_layout)

    label_key = QLabel("Key file:")
    edit_keyfile = QLineEdit()
    edit_keyfile.setPlaceholderText("Select or enter key file path")
    btn_keyfile = QPushButton("Browse")
    btn_keyfile.setFixedWidth(80)

    keyfile_layout = QHBoxLayout()
    keyfile_layout.setSpacing(10)
    keyfile_layout.addWidget(label_key)
    keyfile_layout.addWidget(edit_keyfile)
    keyfile_layout.addWidget(btn_keyfile)

    operation_layout.addLayout(keyfile_layout)

    label_root = QLabel("Directory/File:")
    edit_root = QLineEdit()
    edit_root.setPlaceholderText("Select target directory or file")
    btn_root = QPushButton("Browse")
    btn_root.setFixedWidth(80)

    root_layout = QHBoxLayout()
    root_layout.setSpacing(10)
    root_layout.addWidget(label_root)
    root_layout.addWidget(edit_root)
    root_layout.addWidget(btn_root)

    operation_layout.addLayout(root_layout)

    btn_start = QPushButton("Start")
    btn_start.setFixedHeight(42)

    operation_layout.addWidget(btn_start, alignment=Qt.AlignCenter)

    operation_frame.setLayout(operation_layout)
    main_layout.addWidget(operation_frame)

    text_log = QTextEdit()
    text_log.setReadOnly(True)
    text_log.setObjectName("log_text_edit")
    text_log.setMinimumHeight(240)
    main_layout.addWidget(text_log)

    window.setLayout(main_layout)

    # Connections
    combo_mode.currentTextChanged.connect(partial(on_mode_changed, combo_mode, edit_root))
    btn_keyfile.clicked.connect(partial(select_keyfile, edit_keyfile, combo_mode, window))
    btn_root.clicked.connect(partial(select_root, edit_root, combo_mode, window))
    btn_start.clicked.connect(
        partial(start_operation, combo_mode, edit_keyfile, edit_root, spin_workers,
                btn_start, combo_mode, spin_workers, edit_keyfile, edit_root, text_log, thread_pool)
    )

    on_mode_changed(combo_mode, edit_root)  # Init mode state

    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
