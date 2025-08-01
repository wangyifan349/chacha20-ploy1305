#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
import getpass
import base58
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# ---- 常量配置 ----
PBKDF2_ITER = 1000   # PBKDF2 迭代次数
KEY_LEN     = 32     # 派生密钥长度（字节），32 对应 AES-256
SALT_LEN    = 16     # 随机 salt 长度（字节）
NONCE_LEN   = 12     # AES-GCM nonce 长度（字节）
TAG_LEN     = 16     # GCM tag 长度（字节）

def encode_b58(b: bytes) -> str:
    """将 bytes 编码为 Base58 字符串"""
    return base58.b58encode(b).decode('ascii')

def decode_b58(s: str) -> bytes:
    """将 Base58 字符串解码回 bytes"""
    return base58.b58decode(s.encode('ascii'))

def derive_key(password: str, salt: bytes) -> bytes:
    """
    从密码 + salt 派生出 32 字节的 AES 密钥
    使用 PBKDF2，迭代 PBKDF2_ITER 次
    """
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=PBKDF2_ITER)

def is_encrypted_file(path: Path) -> bool:
    """
    判断一个文件是否已经被我们的工具加密过
    简单方法：文件内容是否是合法 JSON 且含有特定字段
    """
    try:
        txt = path.read_text(encoding='utf-8')
        obj = json.loads(txt)
        # 只要含有这四个字段就视为已加密
        return all(k in obj for k in ("salt", "nonce", "ciphertext", "tag"))
    except Exception:
        return False

def encrypt_file_inplace(file_path: Path, password: str) -> None:
    """
    就地覆盖方式加密单个文件：
    1) 读原始二进制
    2) 随机 salt，PBKDF2 派生 key
    3) AES-GCM 加密，得 nonce/ciphertext/tag
    4) 构造 JSON 字符串，Base58 编码所有二进制字段
    5) 覆盖写回原文件
    """
    # 读取原始内容
    data = file_path.read_bytes()
    # 随机 salt -> 派生 key
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    # 随机 nonce -> 加密
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # 构造 JSON 对象
    record = {
        "salt":       encode_b58(salt),
        "nonce":      encode_b58(nonce),
        "ciphertext": encode_b58(ciphertext),
        "tag":        encode_b58(tag)
    }
    json_txt = json.dumps(record, ensure_ascii=False)
    # 就地覆盖写回
    file_path.write_text(json_txt, encoding='utf-8')
    # 打印线程和文件信息
    print(f"[{threading.current_thread().name}] Encrypted {file_path}")

def decrypt_file_inplace(file_path: Path, password: str) -> None:
    """
    就地覆盖方式解密单个文件：
    1) 读文件 JSON
    2) Base58 解码出 salt/nonce/ciphertext/tag
    3) PBKDF2 根据 salt + 密码派生 key
    4) AES-GCM 解密并验证 tag
    5) 覆盖写回原始二进制
    """
    # 读取并解析 JSON
    txt = file_path.read_text(encoding='utf-8')
    rec = json.loads(txt)
    # Base58 解码
    salt       = decode_b58(rec["salt"])
    nonce      = decode_b58(rec["nonce"])
    ciphertext = decode_b58(rec["ciphertext"])
    tag        = decode_b58(rec["tag"])
    # 派生 key -> 解密
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    # 就地覆盖写回明文
    file_path.write_bytes(plaintext)
    print(f"[{threading.current_thread().name}] Decrypted {file_path}")

def walk_and_process(root: Path, password: str, mode: str, workers: int) -> None:
    """
    遍历目录，对每个文件并行做加密或解密
    mode: "encrypt" or "decrypt"
    """
    # 收集待处理文件列表（排除已加密/未加密文件）
    file_list = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            path = Path(dirpath) / fname
            if mode == "encrypt":
                # 只加密还未被加密过的文件
                if not is_encrypted_file(path):
                    file_list.append(path)
            else:
                # 只解密被加密过的文件
                if     is_encrypted_file(path):
                    file_list.append(path)
    print(f"Mode={mode}, found {len(file_list)} files, workers={workers}")
    # 并行执行
    prefix = "EncWorker" if mode=="encrypt" else "DecWorker"
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=prefix) as pool:
        futures = []
        for fp in file_list:
            if mode == "encrypt":
                fut = pool.submit(encrypt_file_inplace, fp, password)
            else:
                fut = pool.submit(decrypt_file_inplace, fp, password)
            futures.append(fut)
        # 等待所有任务完成
        for fut in as_completed(futures):
            fut.result()  # 如有异常会抛出
    print(f"{mode.capitalize()} complete.")

def main() -> None:
    print("=== AES-GCM 就地覆盖 加/解密工具 ===")
    # 1) 询问目录
    dir_input = input("请输入要处理的目录路径: ").strip()
    root = Path(dir_input)
    if not root.is_dir():
        print("错误：目录不存在，退出。")
        return
    # 2) 询问模式
    mode = input("请选择操作 (encrypt/decrypt): ").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        print("错误：操作必须是 encrypt 或 decrypt，退出。")
        return
    # 3) 密码输入（PBKDF2 迭代 1000 次）
    password = getpass.getpass("请输入密码（不会回显）: ")
    if not password:
        print("错误：密码不能为空，退出。")
        return
    # 4) 并行线程数
    try:
        workers = int(input("请输入并行线程数 (默认 4): ").strip() or "4")
    except ValueError:
        workers = 4
    # 5) 遍历并处理
    walk_and_process(root, password, mode, workers)
if __name__ == "__main__":
    main()
