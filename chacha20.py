import os
import json
import base64
import struct
import stat

# --- ChaCha20 Implementation (同前) ---

def rotate(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotate(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotate(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotate(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotate(state[b], 7)

def chacha20_block(key, counter, nonce):
    constants = b"expand 32-byte k"
    assert len(key) == 32
    assert len(nonce) == 12
    state = list(struct.unpack("<4I8I3I", constants + key + nonce))
    state[12] = counter
    working_state = state[:]
    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
    out = []
    for i in range(16):
        out.append((working_state[i] + state[i]) & 0xffffffff)
    return struct.pack("<16I", *out)

def chacha20_encrypt(key, nonce, counter, plaintext):
    encrypted = bytearray(len(plaintext))
    for i in range(0, len(plaintext), 64):
        block = chacha20_block(key, counter + (i // 64), nonce)
        block_bytes = block[:min(64, len(plaintext) - i)]
        for j in range(len(block_bytes)):
            encrypted[i + j] = plaintext[i + j] ^ block_bytes[j]
    return bytes(encrypted)

# --- Poly1305 Implementation (同前) ---

def le_bytes_to_num(b):
    return sum((b[i] << (8 * i)) for i in range(len(b)))

def num_to_16_le_bytes(n):
    return bytes((n >> (8 * i)) & 0xff for i in range(16))

def poly1305_clamp(r):
    r_list = list(r)
    r_list[3] &= 15
    r_list[7] &= 15
    r_list[11] &= 15
    r_list[15] &= 15
    r_list[4] &= 252
    r_list[8] &= 252
    r_list[12] &= 252
    return bytes(r_list)

def poly1305_mac(msg, key):
    r = key[:16]
    s = key[16:]
    r = poly1305_clamp(r)
    r_num = le_bytes_to_num(r)
    s_num = le_bytes_to_num(s)
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n = le_bytes_to_num(chunk + b'\x01')
        acc = (acc + n) % p
        acc = (acc * r_num) % p
    acc = (acc + s_num) % (1 << 128)
    return num_to_16_le_bytes(acc)

def pad16(data):
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - (len(data) % 16))

def poly1305_input(ciphertext):
    # 无aad，仅拼接 ciphertext + padding + 8字节0 + 8字节长度
    ct_padded = pad16(ciphertext)
    # 因无AAD，单8字节0代表空AAD长度，最后8字节是密文长度
    aad_len = struct.pack("<Q", 0)
    ct_len = struct.pack("<Q", len(ciphertext))
    return b'' + ct_padded + aad_len + ct_len

# --- ChaCha20-Poly1305 AEAD 简化版本，无AAD ---

def chacha20_poly1305_encrypt(key, nonce, plaintext):
    poly_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_encrypt(key, nonce, 1, plaintext)
    mac_data = poly1305_input(ciphertext)
    tag = poly1305_mac(mac_data, poly_key)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key, nonce, ciphertext, tag):
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = poly1305_input(ciphertext)
    calc_tag = poly1305_mac(mac_data, poly_key)
    if calc_tag != tag:
        raise ValueError("认证失败：Poly1305 tag 不匹配")
    plaintext = chacha20_encrypt(key, nonce, 1, ciphertext)
    return plaintext

# --- 文件时间戳和权限备份/恢复 ---

def backup_file_times(filepath):
    stat_res = os.stat(filepath)
    return (stat_res.st_atime, stat_res.st_mtime)

def restore_file_times(filepath, times):
    os.utime(filepath, times=times)

def backup_file_mode(filepath):
    return stat.S_IMODE(os.stat(filepath).st_mode)

def restore_file_mode(filepath, mode):
    os.chmod(filepath, mode)

# --- 结构化JSON写入尾部设计 ---

END_MARKER = b"###END###"

def encode_tail(nonce: bytes, tag: bytes) -> bytes:
    # base64编码nonce和tag
    payload = {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    }
    json_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    return json_bytes + END_MARKER

def decode_tail(data: bytes):
    # 从尾部找END_MARKER，取左侧JSON部分解析
    idx = data.rfind(END_MARKER)
    if idx == -1:
        raise ValueError("文件尾部找不到结束标志")
    json_bytes = data[idx - 1024 if idx >= 1024 else 0:idx]
    # 尝试向前扩展直到能成功json.loads
    # 因json大小不确定，向前逐步扩大查找合理json
    # 简单办法从较早位置开始尝试截断
    for start in range(max(0, idx-1024), -1, -1):
        try:
            cur_json = data[start:idx]
            payload = json.loads(cur_json.decode('utf-8'))
            nonce = base64.b64decode(payload["nonce"])
            tag = base64.b64decode(payload["tag"])
            return nonce, tag, start, idx + len(END_MARKER)
        except Exception:
            continue
    raise ValueError("解析JSON尾部失败")

# --- 加密 / 解密 主功能 ---

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    nonce = os.urandom(12)
    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    times = backup_file_times(filepath)
    mode = backup_file_mode(filepath)

    tail = encode_tail(nonce, tag)

    with open(filepath, 'wb') as f:
        f.write(ciphertext)
        f.write(tail)

    restore_file_times(filepath, times)
    restore_file_mode(filepath, mode)

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()

    nonce, tag, json_start, json_end = decode_tail(data)
    ciphertext = data[:json_start]

    times = backup_file_times(filepath)
    mode = backup_file_mode(filepath)

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(filepath, 'wb') as f:
        f.write(plaintext)

    restore_file_times(filepath, times)
    restore_file_mode(filepath, mode)

# --- 主交互 ---

def main():
    print("请输入操作模式：\n1. 加密\n2. 解密")
    mode = input("输入1或2：").strip()
    if mode not in ("1", "2"):
        print("无效输入，程序退出")
        return
    filepath = input("请输入文件路径：").strip()
    if not os.path.isfile(filepath):
        print("文件不存在")
        return

    key = b'\x01' * 32  # 请换成安全密钥

    try:
        if mode == "1":
            encrypt_file(filepath, key)
            print("加密完成，文件已原地替换。JSON尾部包含nonce和tag。")
        else:
            decrypt_file(filepath, key)
            print("解密完成，文件已原地替换。")
    except Exception as e:
        print("操作出错:", e)


if __name__ == "__main__":
    main()
