#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os  # 操作系统接口
import sys  # 系统相关
import hashlib  # 哈希计算
import tempfile  # 临时文件
import getpass  # 密码输入
from functools import partial  # 函数柯里化
from concurrent.futures import ThreadPoolExecutor, as_completed  # 多线程
from Crypto.Cipher import AES  # AES 算法
from Crypto.Protocol.KDF import PBKDF2  # PBKDF2 密钥派生
from Crypto.Random import get_random_bytes  # 随机字节

PBKDF2_SALT = b"static_salt_for_demo"  # 固定盐值，仅作演示
PBKDF2_ITERATIONS = 1000  # PBKDF2 迭代次数
KEY_LENGTH = 32  # 密钥长度（字节）
GCM_NONCE_SIZE = 12  # GCM 随机数长度
GCM_TAG_SIZE = 16  # GCM 验证标签长度
MAX_WORKERS = 4  # 最大线程数

def compute_file_sha256(file_path: str) -> str:  # 计算文件 SHA256
    hash_object = hashlib.sha256()  # 创建 SHA256 对象
    with open(file_path, 'rb') as file_stream:
        for data_chunk in iter(lambda: file_stream.read(8192), b''):
            hash_object.update(data_chunk)  # 更新哈希
    return hash_object.hexdigest()  # 返回十六进制摘要

def remove_duplicate_files(base_directory: str) -> int:  # 删除重复文件
    seen_hash_map = {}  # 已见文件哈希映射
    duplicates_removed = 0  # 计数
    for directory_path, subdirectory_list, file_list in os.walk(base_directory):  # 遍历目录
        for filename in file_list:
            full_path = os.path.join(directory_path, filename)  # 完整路径
            try:
                file_hash = compute_file_sha256(full_path)  # 计算哈希
            except Exception as error:
                print(f"[WARN] Cannot hash {full_path}: {error}")  # 哈希失败
                continue
            if file_hash in seen_hash_map:
                try:
                    os.remove(full_path)  # 删除重复文件
                    duplicates_removed += 1
                    print(f"[DUP] Removed {full_path}")  # 日志
                except Exception as error:
                    print(f"[ERR] Failed to remove {full_path}: {error}")  # 删除失败
            else:
                seen_hash_map[file_hash] = full_path  # 记录新文件
    print(f"[INFO] Removed {duplicates_removed} duplicate files.")  # 完成
    return duplicates_removed

def derive_key_from_password(password_text: str) -> bytes:  # 密钥派生
    return PBKDF2(password_text, PBKDF2_SALT, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS, hmac_hash_module=hashlib.sha256)

def atomic_replace_file(target_path: str, data_bytes: bytes):  # 原子替换文件
    directory_name = os.path.dirname(target_path) or '.'
    file_descriptor, temp_path = tempfile.mkstemp(dir=directory_name)  # 临时文件
    try:
        with os.fdopen(file_descriptor, 'wb') as temp_file:
            temp_file.write(data_bytes)  # 写入新数据
        os.replace(temp_path, target_path)  # 原子性替换
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)  # 清理

def encrypt_file_in_place(file_path: str, encryption_key: bytes):  # 加密文件
    try:
        with open(file_path, 'rb') as input_file:
            plaintext_bytes = input_file.read()  # 读取明文
        nonce_bytes = get_random_bytes(GCM_NONCE_SIZE)  # 随机数
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce_bytes, mac_len=GCM_TAG_SIZE)
        ciphertext_bytes, tag_bytes = cipher.encrypt_and_digest(plaintext_bytes)  # 加密并获取标签
        blob = nonce_bytes + ciphertext_bytes + tag_bytes  # 合并
        atomic_replace_file(file_path, blob)  # 原子写入
        print(f"[ENC] {file_path}")  # 日志
    except Exception as error:
        print(f"[ERR] Encryption failed for {file_path}: {error}")  # 错误

def decrypt_file_in_place(file_path: str, decryption_key: bytes):  # 解密文件
    try:
        with open(file_path, 'rb') as input_file:
            file_data = input_file.read()  # 读取密文
        if len(file_data) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
            raise ValueError("File too short")  # 数据异常
        nonce_bytes = file_data[:GCM_NONCE_SIZE]  # 提取随机数
        tag_bytes = file_data[-GCM_TAG_SIZE:]  # 提取标签
        ciphertext_bytes = file_data[GCM_NONCE_SIZE:-GCM_TAG_SIZE]  # 提取密文
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=nonce_bytes, mac_len=GCM_TAG_SIZE)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)  # 解密并验证
        atomic_replace_file(file_path, plaintext_bytes)  # 原子写入
        print(f"[DEC] {file_path}")  # 日志
    except Exception as error:
        print(f"[ERR] Decryption failed for {file_path}: {error}")  # 错误

def process_directory_contents(base_directory: str, password_text: str, operation_mode: str):  # 批量处理
    remove_duplicate_files(base_directory)  # 先去重
    derived_key = derive_key_from_password(password_text)  # 派生密钥
    path_list = []  # 文件路径列表
    for directory_path, subdirectory_list, file_list in os.walk(base_directory):
        for filename in file_list:
            path_list.append(os.path.join(directory_path, filename))  # 收集路径
    if not path_list:
        print("[INFO] No files to process.")  # 无文件
        return
    if operation_mode == 'encrypt':
        worker_function = partial(encrypt_file_in_place, encryption_key=derived_key)
    else:
        worker_function = partial(decrypt_file_in_place, decryption_key=derived_key)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures_map = {executor.submit(worker_function, path_item): path_item for path_item in path_list}
        for future in as_completed(futures_map):
            _ = future.result()  # 等待结果
    print(f"[INFO] {operation_mode.capitalize()}ion complete for {len(path_list)} files.")  # 完成

def main():  # 主函数
    print("====== Batch Dedup + AES-GCM Encrypt/Decrypt ======")
    target_directory = input("Enter target directory path: ").strip()  # 目标目录
    if not os.path.isdir(target_directory):
        print("[ERROR] Invalid directory.")  # 错误退出
        sys.exit(1)
    print("Select mode:")
    print("  [1] Remove duplicates")
    print("  [2] Encrypt files")
    print("  [3] Decrypt files")
    mode_choice = input("Enter choice (1/2/3): ").strip()  # 模式选择
    mode_map = {'1': 'dedup', '2': 'encrypt', '3': 'decrypt'}
    if mode_choice not in mode_map:
        print("[ERROR] Invalid choice.")  # 错误退出
        sys.exit(1)
    selected_mode = mode_map[mode_choice]
    input_password = ""
    if selected_mode in ('encrypt', 'decrypt'):
        input_password = getpass.getpass("Enter password: ")  # 密码输入
        if not input_password:
            print("[ERROR] Password cannot be empty.")  # 错误退出
            sys.exit(1)
    if selected_mode == 'dedup':
        remove_duplicate_files(target_directory)  # 仅去重
    else:
        process_directory_contents(target_directory, input_password, selected_mode)  # 加密/解密

if __name__ == '__main__':
    main()  # 运行
