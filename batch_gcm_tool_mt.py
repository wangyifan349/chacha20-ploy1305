#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
batch_gcm_tool_mt.py

AES-256-GCM encrypt/decrypt utility for a single file or all files in a folder (recursively).
In-place processing with preserved access/modify timestamps and permissions.
Multi-threaded for speed.
No compression/archiving.
Dependencies: pip install pycryptodome
"""

import os
import sys
import threading
import time
import getpass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# CONSTANTS
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERS = 100_000
BUFFER_SIZE = 64 * 1024  # 64 KB

failure_lock = threading.Lock()
failure_records = []

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS)

def encrypt_file(file_path: str, password: str) -> None:
    """Encrypt a file in-place with AES-GCM, preserving permissions/atime/mtime."""
    file_stat = os.stat(file_path)
    original_mode = file_stat.st_mode  # Save original permissions
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    tmp_path = file_path + ".tmp"
    with open(file_path, "rb") as file_in, open(tmp_path, "wb") as file_out:
        file_out.write(salt)
        file_out.write(nonce)
        file_out.write(b'\x00' * TAG_SIZE)  # Placeholder for tag
        while True:
            chunk = file_in.read(BUFFER_SIZE)
            if not chunk:
                break
            file_out.write(cipher.encrypt(chunk))
        tag = cipher.digest()
        file_out.seek(SALT_SIZE + NONCE_SIZE)
        file_out.write(tag)
    os.replace(tmp_path, file_path)
    os.utime(file_path, (file_stat.st_atime, file_stat.st_mtime))
    os.chmod(file_path, original_mode)
    print(f"[Encrypted] {file_path}")

def decrypt_file(file_path: str, password: str) -> None:
    """Decrypt a file in-place with AES-GCM, preserving permissions/atime/mtime."""
    file_stat = os.stat(file_path)
    original_mode = file_stat.st_mode
    tmp_path = file_path + ".tmp"
    with open(file_path, "rb") as file_in:
        salt = file_in.read(SALT_SIZE)
        nonce = file_in.read(NONCE_SIZE)
        tag = file_in.read(TAG_SIZE)
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
            raise ValueError("Invalid salt/nonce/tag header")
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        with open(tmp_path, "wb") as file_out:
            while True:
                chunk = file_in.read(BUFFER_SIZE)
                if not chunk:
                    break
                file_out.write(cipher.decrypt(chunk))
        cipher.verify(tag)
    os.replace(tmp_path, file_path)
    os.utime(file_path, (file_stat.st_atime, file_stat.st_mtime))
    os.chmod(file_path, original_mode)
    print(f"[Decrypted] {file_path}")

def process_worker(task):
    """Worker function for ThreadPoolExecutor."""
    file_path, mode, password = task
    try:
        if mode == "encrypt":
            encrypt_file(file_path, password)
        else:
            decrypt_file(file_path, password)
    except Exception as ex:
        with failure_lock:
            failure_records.append((file_path, str(ex)))

def collect_target_files(target_path):
    """
    Return a list of file paths to process.
    Accepts single file or directory (recursively collects all files).
    """
    file_list = []
    if os.path.isfile(target_path):
        file_list.append(target_path)
    elif os.path.isdir(target_path):
        for dirpath, _, filenames in os.walk(target_path):
            for filename in filenames:
                file_list.append(os.path.join(dirpath, filename))
    return file_list

def write_failure_log(records, log_path):
    """Write failures to log file."""
    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"Batch GCM Tool Log - {datetime.now().isoformat()}\n")
        log_file.write("-" * 60 + "\n")
        for file_path, err_msg in records:
            log_file.write(f"{file_path} : {err_msg}\n")

def main():
    print("=== AES-256-GCM Multi-threaded Encrypt/Decrypt Tool ===")
    print("Supports single file or directory (recursive). No compression.")

    while True:
        mode_choice = input("1) Encrypt  2) Decrypt   Choose 1 or 2: ").strip()
        if mode_choice in ("1", "2"):
            break
    operation_mode = "encrypt" if mode_choice == "1" else "decrypt"

    # Ask user for file or directory
    while True:
        target_input = input("Enter file or directory path to process: ").strip()
        if os.path.exists(target_input):
            break
        print("Path does not exist. Try again.")

    # Hide password input
    password = ""
    while not password:
        password = getpass.getpass("Enter password: ").strip()

    # Gather file list
    files_to_process = collect_target_files(target_input)
    if not files_to_process:
        print("No files found to process.")
        sys.exit(1)
    max_threads = min(32, (os.cpu_count() or 1) * 2)
    print(f"{len(files_to_process)} files to process ({max_threads} threads).")

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(process_worker, (fp, operation_mode, password)) for fp in files_to_process]
        for _ in as_completed(futures):
            pass
    elapsed = time.time() - start_time

    print(f"\nDone in {elapsed:.2f} seconds.")
    if failure_records:
        print(f"{len(failure_records)} files failed:")
        for file_path, err_msg in failure_records:
            print(f"  {file_path} -> {err_msg}")
        log_path = os.path.abspath(
            f"batch_gcm_errors_{operation_mode}_{datetime.now():%Y%m%d_%H%M%S}.log")
        write_failure_log(failure_records, log_path)
        print(f"See log: {log_path}")
    else:
        print("All files processed successfully.")

if __name__ == "__main__":
    main()
