#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, base64, struct, stat, secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

# ——————————————————————————————————————————————————————————————————————
# 1) ChaCha20 基本函数
# ——————————————————————————————————————————————————————————————————————
def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))              # 32-bit 循环左移

def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d                                          # 返回更新后的四个状态字

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    const = b"expa" b"nd 3" b"2-by" b"te k"                     # ChaCha20 常量
    s0, s1, s2, s3 = struct.unpack("<4I", const)               # 解包成 4 个 32-bit
    k0, k1, k2, k3, k4, k5, k6, k7 = struct.unpack("<8I", key)  # 解包 8 个 key word
    n0, n1, n2 = struct.unpack("<3I", nonce)                   # 解包 3 个 nonce word
    state = [s0, s1, s2, s3, k0, k1, k2, k3, k4, k5, k6, k7, counter, n0, n1, n2]
    working = state.copy()
    for _ in range(10):                                         # 20 轮 (10 次 column+diagonal)
        # column rounds
        working[0], working[4], working[8],  working[12] = quarter_round(*[working[i] for i in (0,4,8,12)])
        working[1], working[5], working[9],  working[13] = quarter_round(*[working[i] for i in (1,5,9,13)])
        working[2], working[6], working[10], working[14] = quarter_round(*[working[i] for i in (2,6,10,14)])
        working[3], working[7], working[11], working[15] = quarter_round(*[working[i] for i in (3,7,11,15)])
        # diagonal rounds
        working[0], working[5], working[10], working[15] = quarter_round(*[working[i] for i in (0,5,10,15)])
        working[1], working[6], working[11], working[12] = quarter_round(*[working[i] for i in (1,6,11,12)])
        working[2], working[7], working[8],  working[13] = quarter_round(*[working[i] for i in (2,7,8,13)])
        working[3], working[4], working[9],  working[14] = quarter_round(*[working[i] for i in (3,4,9,14)])
    out = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)                            # 返回 64 字节的 keystream block

def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    buf = bytearray(len(data))
    i = 0
    while i < len(data):
        block = chacha20_block(key, counter, nonce)
        chunk = data[i:i+64]
        for j in range(len(chunk)):
            buf[i+j] = chunk[j] ^ block[j]
        i += 64
        counter += 1
    return bytes(buf)                                           # 对 data 做流式异或加解密

# ——————————————————————————————————————————————————————————————————————
# 2) Poly1305 基本函数
# ——————————————————————————————————————————————————————————————————————
def clamp_r(r: bytearray) -> bytearray:
    r[3]  &= 15; r[7]  &= 15; r[11] &= 15; r[15] &= 15
    r[4]  &= 252; r[8]  &= 252; r[12] &= 252
    return r                                                    # 对 r 做 bit 掩码 (clamp)

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    r = clamp_r(bytearray(key[:16]))                           # r 部分
    s = int.from_bytes(key[16:], "little")                      # s 部分
    r_num = int.from_bytes(r, "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = (acc + n) * r_num % p
    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")                           # 16 字节 Tag

def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + b"\x00" * (16-rem)     # 16 字节边界对齐

def make_poly_input(ct: bytes) -> bytes:
    return ct + pad16(ct) + struct.pack("<Q", 0) + struct.pack("<Q", len(ct))
                                                                # ciphertext || pad || AAD_len=0 || CT_len

# ——————————————————————————————————————————————————————————————————————
# 3) AEAD: ChaCha20-Poly1305 (No AAD)
# ——————————————————————————————————————————————————————————————————————
def aead_encrypt(key: bytes, data: bytes):
    nonce = secrets.token_bytes(12)                             # 随机 12 字节 Nonce
    otk = chacha20_block(key, 0, nonce)[:32]                    # Poly1305 一次性 key
    ct = chacha20_xor(key, nonce, 1, data)                      # 从 counter=1 开始加密
    tag = poly1305_mac(otk, make_poly_input(ct))                # 计算 Tag
    return nonce, ct, tag                                       # 返回三元组

def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    otk = chacha20_block(key, 0, nonce)[:32]
    if poly1305_mac(otk, make_poly_input(ct)) != tag:
        raise ValueError("Poly1305 tag 校验失败")
    return chacha20_xor(key, nonce, 1, ct)                      # 验证通过后解密

# ——————————————————————————————————————————————————————————————————————
# 4) 文件权限/时间备份 & JSON 尾部 编码/解码
# ——————————————————————————————————————————————————————————————————————
END_MARKER = b"###END###"

def backup_times(path):
    s = os.stat(path)
    return (s.st_atime, s.st_mtime)                             # 备份访问、修改时间

def restore_times(path, times):
    os.utime(path, times=times)                                 # 恢复时间

def backup_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)                  # 备份权限模式

def restore_mode(path, mode):
    os.chmod(path, mode)                                        # 恢复权限模式

def encode_tail(nonce: bytes, tag: bytes) -> bytes:
    payload = {
        "nonce": base64.b64encode(nonce).decode(),
        "tag":   base64.b64encode(tag).decode()
    }
    j = json.dumps(payload, separators=(",",":")).encode("utf-8")
    return j + END_MARKER                                       # JSON + 结束标记

def decode_tail(blob: bytes):
    idx = blob.rfind(END_MARKER)
    if idx < 0:
        raise ValueError("未找到 END_MARKER")
    # 从 idx-4096 到 idx 这段数据内搜索合法 JSON
    start = max(0, idx-4096)
    segment = blob[start:idx]
    for off in range(len(segment)):
        try:
            doc = segment[off:].decode("utf-8")
            payload = json.loads(doc)
            nonce = base64.b64decode(payload["nonce"])
            tag   = base64.b64decode(payload["tag"])
            return nonce, tag, start+off, idx+len(END_MARKER)
        except Exception:
            continue
    raise ValueError("JSON 尾部解析失败")

# ——————————————————————————————————————————————————————————————————————
# 5) 单文件 加密/解密 处理函数
# ——————————————————————————————————————————————————————————————————————
def process_enc(path: str, key: bytes) -> str:
    try:
        data = open(path,"rb").read()                           # 读文件
        nonce, ct, tag = aead_encrypt(key, data)                # 加密
        tail = encode_tail(nonce, tag)                          # 编码尾部
        times, mode = backup_times(path), backup_mode(path)     # 备份
        with open(path,"wb") as f:
            f.write(ct); f.write(tail)                          # 写入 ct + tail
        restore_times(path, times); restore_mode(path, mode)    # 恢复
        return None
    except Exception as e:
        return str(e)

def process_dec(path: str, key: bytes) -> str:
    try:
        blob = open(path,"rb").read()                           # 读文件
        nonce, tag, split, end = decode_tail(blob)             # 解尾部
        ct = blob[:split]
        pt = aead_decrypt(key, nonce, ct, tag)                  # 解密
        times, mode = backup_times(path), backup_mode(path)     # 备份
        with open(path,"wb") as f:
            f.write(pt)                                         # 写入明文
        restore_times(path, times); restore_mode(path, mode)    # 恢复
        return None
    except Exception as e:
        return str(e)

# ——————————————————————————————————————————————————————————————————————
# 6) 目录遍历 & 并发调度
# ——————————————————————————————————————————————————————————————————————
def gather_files(root: str):
    lst = []
    for base, _, files in os.walk(root):
        for fn in files:
            lst.append(os.path.join(base, fn))
    return lst

# ——————————————————————————————————————————————————————————————————————
# 7) 主程序入口
# ——————————————————————————————————————————————————————————————————————
def main():
    # 交互：enc / dec
    mode = ""
    while mode not in ("enc","dec"):
        mode = input("请选择模式 enc(加密) / dec(解密)：").strip().lower()
    # 交互：目录
    root = input("请输入要操作的目录：").strip()
    if not os.path.isdir(root):
        print("目录不存在，退出。"); sys.exit(1)
    # 交互：Hex Key
    key_hex = input("请输入 32 字节十六进制密钥：").strip()
    try:
        key = bytes.fromhex(key_hex)
    except:
        print("密钥格式错误，退出。"); sys.exit(1)
    if len(key) != 32:
        print("密钥长度非 32 字节，退出。"); sys.exit(1)
    # 交互：线程数
    try:
        threads = int(input("请输入并发线程数 (≥1)：").strip())
        if threads < 1: raise ValueError
    except:
        print("线程数错误，退出。"); sys.exit(1)

    files = gather_files(root)
    if not files:
        print("目录无文件，退出。"); sys.exit(0)

    print(f"开始 { '加密' if mode=='enc' else '解密' } {len(files)} 个文件，{threads} 线程并发…")
    errors = []

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {
            exe.submit(process_enc if mode=='enc' else process_dec, path, key): path 
            for path in files
        }
        for fut in as_completed(futures):
            err = fut.result()
            if err:
                errors.append((futures[fut], err))

    if errors:
        print("\n以下文件处理失败：", file=sys.stderr)
        for p, e in errors:
            print(f"{p} 失败原因：{e}", file=sys.stderr)
        sys.exit(1)
    else:
        print("全部处理完成。")

if __name__ == "__main__":
    main()
