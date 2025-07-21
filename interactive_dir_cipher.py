#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======= ChaCha20-Poly1305 零依赖实现 =======

def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d

def chacha20_block(key, counter, nonce):
    const = b"expa" b"nd 3" b"2-by" b"te k"
    s0, s1, s2, s3 = struct.unpack("<4I", const)
    k0, k1, k2, k3, k4, k5, k6, k7 = struct.unpack("<8I", key)
    n0, n1, n2 = struct.unpack("<3I", nonce)
    state = [s0, s1, s2, s3, k0, k1, k2, k3, k4, k5, k6, k7, counter, n0, n1, n2]
    w = state.copy()
    for _ in range(10):
        w[0], w[4], w[8],  w[12] = quarter_round(w[0], w[4], w[8],  w[12])
        w[1], w[5], w[9],  w[13] = quarter_round(w[1], w[5], w[9],  w[13])
        w[2], w[6], w[10], w[14] = quarter_round(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = quarter_round(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = quarter_round(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = quarter_round(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8],  w[13] = quarter_round(w[2], w[7], w[8],  w[13])
        w[3], w[4], w[9],  w[14] = quarter_round(w[3], w[4], w[9],  w[14])
    out = [(w[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

def chacha20_xor(key, nonce, counter, data):
    res = bytearray(len(data))
    i = 0
    while i < len(data):
        block = chacha20_block(key, counter, nonce)
        length = min(64, len(data) - i)
        for j in range(length):
            res[i + j] = data[i + j] ^ block[j]
        i += length
        counter += 1
    return bytes(res)

def poly1305_mac(one_time_key, msg):
    r = bytearray(one_time_key[:16])
    s = one_time_key[16:]
    r[3]  &= 15; r[7]  &= 15; r[11] &= 15; r[15] &= 15
    r[4]  &= 252; r[8]  &= 252; r[12] &= 252
    r_num = int.from_bytes(r, "little")
    s_num = int.from_bytes(s, "little")
    p = (1 << 130) - 5
    acc = 0
    i = 0
    while i < len(msg):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = (acc + n) * r_num % p
        i += 16
    tag = (acc + s_num) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")

def equal_ct(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0

def aead_encrypt(key, data):
    nonce = secrets.token_bytes(12)
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, nonce, 1, data)
    pad = (16 - (len(ct) % 16)) % 16
    mac_input = ct + b"\x00" * pad + (0).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    tag = poly1305_mac(otk, mac_input)
    return nonce + ct + tag

def aead_decrypt(key, blob):
    if len(blob) < 12 + 16:
        raise ValueError("文件过短，无法解密")
    nonce = blob[:12]
    tag = blob[-16:]
    ct = blob[12:-16]
    otk = chacha20_block(key, 0, nonce)[:32]
    pad = (16 - (len(ct) % 16)) % 16
    mac_input = ct + b"\x00" * pad + (0).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    expect = poly1305_mac(otk, mac_input)
    if not equal_ct(expect, tag):
        raise ValueError("Poly1305 Tag 校验失败")
    return chacha20_xor(key, nonce, 1, ct)

# ======= 文件遍历与多线程处理 =======

def process_file(path, key, mode):
    try:
        with open(path, "rb") as f:
            data = f.read()
        if mode == "enc":
            out = aead_encrypt(key, data)
        else:
            out = aead_decrypt(key, data)
        with open(path, "wb") as f:
            f.write(out)
        return None
    except Exception as e:
        return str(e)

def gather_files(root):
    result = []
    for base, _, files in os.walk(root):
        for fn in files:
            result.append(os.path.join(base, fn))
    return result

# ======= 主流程 =======

def main():
    mode = ""
    while mode not in ("enc", "dec"):
        mode = input("请选择模式 enc(加密) 或 dec(解密)：").strip().lower()
    root = input("请输入要处理的目录路径：").strip()
    if not os.path.isdir(root):
        print("目录不存在，退出。")
        return
    key_hex = input("请输入32字节十六进制密钥：").strip()
    try:
        key = bytes.fromhex(key_hex)
    except:
        print("密钥格式错误，退出。")
        return
    if len(key) != 32:
        print("密钥长度必须正好32字节（64个十六进制字符），退出。")
        return
    try:
        threads = int(input("请输入并发线程数（例如4）：").strip())
        if threads < 1:
            raise ValueError()
    except:
        print("线程数输入不合法，退出。")
        return

    files = gather_files(root)
    if not files:
        print("目录下没有任何文件，退出。")
        return

    errors = []
    print(f"开始{ '加密' if mode=='enc' else '解密' }，共发现{len(files)}个文件，使用{threads}线程并行处理。")

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {}
        for path in files:
            fut = exe.submit(process_file, path, key, mode)
            futures[fut] = path
        for fut in as_completed(futures):
            err = fut.result()
            if err:
                errors.append((futures[fut], err))

    if errors:
        print("\n以下文件处理失败：", file=sys.stderr)
        for pth, msg in errors:
            print(f"{pth} 失败原因：{msg}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"所有文件{ '加密' if mode=='enc' else '解密' }完成。")

if __name__ == "__main__":
    main()
