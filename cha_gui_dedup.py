#!/usr/bin/env python3
# coding: utf-8

import sys, os, hashlib
from functools import partial
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit, QListWidget,
    QMessageBox, QRadioButton, QButtonGroup, QSpinBox, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# —— 常量 —— #
SALT_LEN = 16
KEY_LEN = 32
NONCE_LEN = 8
DEFAULT_ITERS = 200000

# —— 后台线程：加解密任务 —— #
class CryptoThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, src, dst, pwd, salt, iters, mode):
        super().__init__()
        self.src = src
        self.dst = dst
        self.pwd = pwd
        self.salt = salt
        self.iters = iters
        self.mode = mode  # 'encrypt' or 'decrypt'

    def run(self):
        # 派生 key 和 nonce
        dk = PBKDF2(self.pwd, self.salt, dkLen=KEY_LEN+NONCE_LEN,
                    count=self.iters, hmac_hash_module=SHA256)
        key, nonce = dk[:KEY_LEN], dk[KEY_LEN:]
        # 处理路径
        if os.path.isfile(self.src):
            self._process_file(self.src, self.dst, key, nonce)
        else:
            for root, _, files in os.walk(self.src):
                rel = os.path.relpath(root, self.src)
                for fn in files:
                    inp = os.path.join(root, fn)
                    out_root = self.dst if rel == '.' else os.path.join(self.dst, rel)
                    os.makedirs(out_root, exist_ok=True)
                    outp = os.path.join(out_root, fn)
                    self._process_file(inp, outp, key, nonce)
        self.finished_signal.emit()

    def _process_file(self, infile, outfile, key, nonce):
        tag = 'ENC' if self.mode=='encrypt' else 'DEC'
        try:
            data = open(infile, 'rb').read()
            if self.mode=='encrypt':
                out = ChaCha20.new(key=key, nonce=nonce).encrypt(data)
            else:
                out = ChaCha20.new(key=key, nonce=nonce).decrypt(data)
            os.makedirs(os.path.dirname(outfile), exist_ok=True)
            open(outfile, 'wb').write(out)
            self.log_signal.emit(f"[OK] {tag} {infile} → {outfile}\n")
        except Exception as e:
            self.log_signal.emit(f"[ERR] {tag} {infile} : {e}\n")

# —— 后台线程：重复文件扫描任务 —— #
class DedupThread(QThread):
    progress_signal = pyqtSignal(int,int)  # current, total
    result_signal   = pyqtSignal(dict)
    finished_signal = pyqtSignal()

    def __init__(self, root_path):
        super().__init__()
        self.root_path = root_path

    def run(self):
        size_map = {}
        # 第一步：按大小分组
        for dirpath, _, filenames in os.walk(self.root_path):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(fp)
                    size_map.setdefault(sz, []).append(fp)
                except:
                    continue
        groups = list(size_map.items())
        total = len(groups)
        duplicates = {}
        for idx, (sz, fps) in enumerate(groups, start=1):
            self.progress_signal.emit(idx, total)
            if len(fps) < 2:
                continue
            hash_map = {}
            for f in fps:
                try:
                    h = hashlib.sha256(open(f,'rb').read()).hexdigest()
                    hash_map.setdefault(h, []).append(f)
                except:
                    pass
            for h, lst in hash_map.items():
                if len(lst) > 1:
                    duplicates[h] = lst
        self.result_signal.emit(duplicates)
        self.finished_signal.emit()

# —— 主界面 —— #
class MainApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChaCha20 & 重复文件清理")
        self.resize(800, 600)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        tabs   = QTabWidget()
        tabs.addTab(self._crypto_tab(), "加密/解密")
        tabs.addTab(self._dedup_tab(), "重复文件清理")
        layout.addWidget(tabs)

    # ——— 加密/解密 选项卡 ——— #
    def _crypto_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        # 路径选择
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("源：")); self.src_edit = QLineEdit()
        h1.addWidget(self.src_edit)
        h1.addWidget(QPushButton("…", clicked=self._pick_src))
        v.addLayout(h1)
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("目标：")); self.dst_edit = QLineEdit()
        h2.addWidget(self.dst_edit)
        h2.addWidget(QPushButton("…", clicked=self._pick_dst))
        v.addLayout(h2)
        # 密码 / 迭代 / salt
        h3 = QHBoxLayout()
        h3.addWidget(QLabel("密码：")); self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.Password)
        h3.addWidget(self.pwd_edit)
        h3.addWidget(QLabel("迭代：")); self.iters_spin = QSpinBox()
        self.iters_spin.setRange(1, 10_000_000)
        self.iters_spin.setValue(DEFAULT_ITERS)
        h3.addWidget(self.iters_spin)
        v.addLayout(h3)
        h4 = QHBoxLayout()
        h4.addWidget(QLabel("Salt (Hex)：")); self.salt_edit = QLineEdit()
        h4.addWidget(QPushButton("生成", clicked=self._gen_salt))
        v.addLayout(h4)
        # 加密/解密 单选
        h5 = QHBoxLayout()
        self.mode_group = QButtonGroup()
        r1 = QRadioButton("加密"); r2 = QRadioButton("解密")
        r1.setChecked(True)
        self.mode_group.addButton(r1); self.mode_group.addButton(r2)
        h5.addWidget(r1); h5.addWidget(r2)
        h5.addStretch()
        v.addLayout(h5)
        # 日志区
        self.log_crypto = QTextEdit()
        self.log_crypto.setReadOnly(True)
        v.addWidget(self.log_crypto)
        # 按钮
        h6 = QHBoxLayout()
        run_btn = QPushButton("开始", clicked=self._start_crypto)
        exit_btn= QPushButton("退出", clicked=self.close)
        h6.addStretch(); h6.addWidget(run_btn); h6.addWidget(exit_btn)
        v.addLayout(h6)
        return w

    def _pick_src(self):
        f = QFileDialog.getOpenFileName(self, "选择文件")[0]
        if not f:
            d = QFileDialog.getExistingDirectory(self, "选择目录")
            f = d or ''
        if f: self.src_edit.setText(f)

    def _pick_dst(self):
        d = QFileDialog.getExistingDirectory(self, "选择目标目录")
        if d:
            self.dst_edit.setText(d)

    def _gen_salt(self):
        s = get_random_bytes(SALT_LEN).hex()
        self.salt_edit.setText(s)

    def _start_crypto(self):
        src   = self.src_edit.text().strip()
        dst   = self.dst_edit.text().strip()
        pwd   = self.pwd_edit.text()
        salth = self.salt_edit.text().strip()
        iters = self.iters_spin.value()
        mode  = 'encrypt' if self.mode_group.buttons()[0].isChecked() else 'decrypt'
        if not (src and dst and pwd):
            QMessageBox.warning(self, "提示", "请填写源、目标和密码")
            return
        if mode=='encrypt':
            try:
                salt = bytes.fromhex(salth) if salth else get_random_bytes(SALT_LEN)
            except:
                salt = get_random_bytes(SALT_LEN)
                self.salt_edit.setText(salt.hex())
        else:
            try:
                salt = bytes.fromhex(salth)
            except:
                QMessageBox.warning(self, "Salt 错误", "请填入正确的 Hex Salt")
                return
        # 禁用按钮
        self.log_crypto.clear()
        th = CryptoThread(src, dst, pwd, salt, iters, mode)
        th.log_signal.connect(self.log_crypto.append)
        th.finished_signal.connect(lambda: self.log_crypto.append("[INFO] 完成。\n"))
        th.start()

    # ——— 重复文件清理 选项卡 ——— #
    def _dedup_tab(self):
        w = QWidget(); v = QVBoxLayout(w)
        # 目录选择
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("目录：")); self.dedup_edit = QLineEdit()
        h1.addWidget(self.dedup_edit)
        h1.addWidget(QPushButton("…", clicked=self._pick_dedup))
        v.addLayout(h1)
        # 进度条
        self.pb = QProgressBar(); self.pb.setValue(0)
        v.addWidget(self.pb)
        # 重复组列表
        self.list_dup = QListWidget()
        v.addWidget(self.list_dup)
        # 日志
        self.log_dup = QTextEdit(); self.log_dup.setReadOnly(True)
        v.addWidget(self.log_dup)
        # 按钮
        h2 = QHBoxLayout()
        scan_btn  = QPushButton("扫描重复", clicked=self._start_scan)
        delete_btn= QPushButton("删除重复", clicked=self._delete_dup)
        h2.addStretch(); h2.addWidget(scan_btn); h2.addWidget(delete_btn)
        v.addLayout(h2)
        return w

    def _pick_dedup(self):
        d = QFileDialog.getExistingDirectory(self, "选择目录")
        if d: self.dedup_edit.setText(d)

    def _start_scan(self):
        path = self.dedup_edit.text().strip()
        if not os.path.isdir(path):
            QMessageBox.warning(self, "路径错误", "请选择一个有效目录")
            return
        self.list_dup.clear()
        self.log_dup.clear()
        self.pb.setValue(0)
        self.dups = {}
        th = DedupThread(path)
        th.progress_signal.connect(lambda c,t: self.pb.setValue(int(c/t*100)))
        th.result_signal.connect(self._show_dups)
        th.finished_signal.connect(lambda: self.log_dup.append("[INFO] 扫描完成。\n"))
        th.start()

    def _show_dups(self, dups):
        self.dups = dups
        for h, lst in dups.items():
            self.list_dup.addItem(f"{len(lst)} 个重复 => Hash:{h}")

    def _delete_dup(self):
        if not getattr(self, 'dups', None):
            QMessageBox.information(self, "无重复", "当前没有可删除的重复文件")
            return
        reply = QMessageBox.question(
            self, "确认删除", "是否删除所有重复文件？（每组仅保留第一个）",
            QMessageBox.Yes|QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        for h, lst in self.dups.items():
            keep = lst[0]
            for fp in lst[1:]:
                try:
                    os.remove(fp)
                    self.log_dup.append(f"[DEL] {fp}")
                except Exception as e:
                    self.log_dup.append(f"[ERR] {fp}: {e}")
            self.log_dup.append(f"[KEEP] {keep}\n")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainApp()
    win.show()
    sys.exit(app.exec_())
