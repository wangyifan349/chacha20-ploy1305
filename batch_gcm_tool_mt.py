#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
batch_gcm_tool_mt.py

交互式批量对目录下所有文件进行 AES-256-GCM 加密/解密，就地覆盖，
支持多线程加速，并对失败的文件进行统计和日志输出，保持原文件的 access/modify 时间不变。

依赖:
    pip install pycryptodome

运行:
    python batch_gcm_tool_mt.py
"""

import os
import sys
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# 常量定义
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERS = 100_000
BUFFER_SIZE = 64 * 1024

# 全局用于收集失败文件信息
failure_lock = threading.Lock()
failures = []  # list of tuples (file_path, error_message)


def derive_key(password: str, salt: bytes) -> bytes:
    """用 PBKDF2 从口令派生 AES-256 密钥"""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS)


def encrypt_single(path: str, password: str) -> None:
    """对单个文件执行 AES-GCM 加密，就地覆盖，并保持 atime/mtime"""
    stat = os.stat(path)
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    tmp_path = path + ".tmp"
    with open(path, "rb") as f_in, open(tmp_path, "wb") as f_out:
        # 写入 salt | nonce | 占位 tag
        f_out.write(salt)
        f_out.write(nonce)
        f_out.write(b"\x00" * TAG_SIZE)

        # 分块加密并写入
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if not chunk:
                break
            f_out.write(cipher.encrypt(chunk))

        # 写入真正的 tag
        tag = cipher.digest()
        f_out.seek(SALT_SIZE + NONCE_SIZE)
        f_out.write(tag)

    os.replace(tmp_path, path)
    os.utime(path, (stat.st_atime, stat.st_mtime))
    print(f"[Encrypted] {path}")


def decrypt_single(path: str, password: str) -> None:
    """对单个文件执行 AES-GCM 解密，就地覆盖，并保持 atime/mtime"""
    stat = os.stat(path)
    tmp_path = path + ".tmp"
    with open(path, "rb") as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(NONCE_SIZE)
        tag = f_in.read(TAG_SIZE)
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
            raise ValueError("invalid header (salt/nonce/tag)")

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        with open(tmp_path, "wb") as f_out:
            while True:
                chunk = f_in.read(BUFFER_SIZE)
                if not chunk:
                    break
                f_out.write(cipher.decrypt(chunk))

        cipher.verify(tag)

    os.replace(tmp_path, path)
    os.utime(path, (stat.st_atime, stat.st_mtime))
    print(f"[Decrypted] {path}")


def worker(task: tuple):
    """线程执行函数"""
    path, mode, password = task
    try:
        if mode == "encrypt":
            encrypt_single(path, password)
        else:
            decrypt_single(path, password)
    except Exception as ex:
        with failure_lock:
            failures.append((path, str(ex)))


def collect_tasks(root_dir: str, mode: str, password: str):
    """收集所有待处理文件任务"""
    tasks = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            tasks.append((os.path.join(dirpath, fname), mode, password))
    return tasks


def write_log(entries, log_path):
    """将失败信息写入日志文件"""
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"Batch GCM Tool Log - {datetime.now().isoformat()}\n")
        f.write("-" * 60 + "\n")
        for path, err in entries:
            f.write(f"{path} : {err}\n")


def main():
    print("=== Batch AES-256-GCM Multi-threaded Tool ===")
    choice = ""
    while choice not in ("1", "2"):
        print("1) Encrypt")
        print("2) Decrypt")
        choice = input("Select 1 or 2: ").strip()
    mode = "encrypt" if choice == "1" else "decrypt"

    directory = ""
    while not os.path.isdir(directory := input("Directory to process: ").strip()):
        print("Invalid directory, try again.")

    password = ""
    while not password:
        password = input("Password: ").strip()

    max_workers = min(32, (os.cpu_count() or 1) * 2)
    tasks = collect_tasks(directory, mode, password)
    print(f"Found {len(tasks)} files, starting with {max_workers} threads...")

    start = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, t) for t in tasks]
        for _ in as_completed(futures):  # 这里的下划线 '_' 也是英文字符
            pass
    elapsed = time.time() - start

    print(f"\nCompleted in {elapsed:.2f}s")
    if failures:
        print(f"{len(failures)} file(s) failed:")
        for p, e in failures:
            print(f"  {p} -> {e}")
        log_file = os.path.join(os.getcwd(),
                                f"batch_gcm_errors_{mode}_{datetime.now():%Y%m%d_%H%M%S}.log")
        write_log(failures, log_file)
        print(f"See log: {log_file}")
    else:
        print("All done successfully.")


if __name__ == "__main__":
    main()
