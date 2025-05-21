import os
import struct

def rotl(x: int, n: int) -> int:
    """循环左移32位整数x，左移n位"""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    计算ChaCha20单个64字节密钥流块
    """
    constants = b"expand 32-byte k"
    const_words = struct.unpack("<4I", constants)
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    state = list(const_words + key_words + (counter,) + nonce_words)
    working = state.copy()

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl(x[d], 16)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl(x[b], 12)

        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl(x[d], 8)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl(x[b], 7)

    iteration = 0
    while iteration < 10:
        # 列变换
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # 对角线变换
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        iteration += 1

    output_words = []
    idx = 0
    while idx < 16:
        output_words.append((working[idx] + state[idx]) & 0xffffffff)
        idx += 1

    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    ChaCha20加密/解密，数据与密钥流XOR
    """
    output = bytearray()
    data_length = len(data)
    block_count = (data_length + 63) // 64

    block_index = 0
    while block_index < block_count:
        block_start = block_index * 64
        block_end = block_start + 64
        block = data[block_start:block_end]
        keystream = chacha20_block(key, counter + block_index, nonce)

        byte_index = 0
        while byte_index < len(block):
            output.append(block[byte_index] ^ keystream[byte_index])
            byte_index += 1

        block_index += 1

    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    对Poly1305 r部分进行clamp并返回r, s整数
    """
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r_int = int.from_bytes(r_bytes, "little")
    s_int = int.from_bytes(s_bytes, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    计算Poly1305认证标签
    """
    r, s = poly1305_clamp_r_s(key)
    prime_p = (1 << 130) - 5
    accumulator = 0

    msg_idx = 0
    msg_len = len(msg)
    while msg_idx < msg_len:
        block = msg[msg_idx:msg_idx + 16]
        if len(block) < 16:
            block = block + (b"\x00" * (16 - len(block)))
        n = int.from_bytes(block, "little") + (1 << 128)
        accumulator = (accumulator + n) % prime_p
        accumulator = (accumulator * r) % prime_p
        msg_idx += 16

    tag_num = (accumulator + s) % (1 << 128)
    return tag_num.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    填充数据到16字节整数倍（0x00填充）
    """
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        return data
    else:
        return data + (b"\x00" * padding_len)

def u64_le(n: int) -> bytes:
    """将整数编码成8字节小端"""
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 AEAD加密"""
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly1305_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 AEAD解密并验证"""
    poly1305_key = chacha20_block(key, 0, nonce)[:32]

    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    calculated_tag = poly1305_mac(poly1305_key, mac_data)
    if calculated_tag != tag:
        raise ValueError("Poly1305 authentication failed!")

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(file_path: str, key: bytes):
    """加密单个文件，原地覆盖"""
    nonce = os.urandom(12)

    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as file:
        plaintext = file.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    with open(file_path, "wb") as file:
        file.write(nonce + tag + ciphertext)

    os.utime(file_path, (atime, mtime))

def decrypt_file(file_path: str, key: bytes):
    """解密单个文件，原地覆盖"""
    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as file:
        content = file.read()

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(file_path, "wb") as file:
        file.write(plaintext)

    os.utime(file_path, (atime, mtime))

def encrypt_directory(input_directory: str, key: bytes):
    """递归加密目录内所有文件，原地覆盖"""
    for current_root, directories, files in os.walk(input_directory):
        file_index = 0
        while file_index < len(files):
            filename = files[file_index]
            filepath = os.path.join(current_root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as exc:
                print(f"Encrypt failed: {filepath} - {exc}")
            file_index += 1

def decrypt_directory(input_directory: str, key: bytes):
    """递归解密目录内所有文件，原地覆盖"""
    for current_root, directories, files in os.walk(input_directory):
        file_index = 0
        while file_index < len(files):
            filename = files[file_index]
            filepath = os.path.join(current_root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as exc:
                print(f"Decrypt failed: {filepath} - {exc}")
            file_index += 1

key = b'\x18\xe7\xc6\x14\xf0\xc9\xd2a\x04\xd9\xcf3\xc6\xb5\x1c\xc1\nQ\xec\xdbhd\xbe\x12\xcb\x08\x86\x9a\x05\xe7\xedO'
#这里只是一个示例密码，请换成你自己的。
"""
# 生成随机密钥并打印hex字符串
key = os.urandom(32)
hex_key = key.hex()
print(f"生成的密钥（hex）：{hex_key}")
"""

if len(key) != 32:
    print("错误：密钥长度必须是32字节！")
    exit(1)

target_directory = input("请输入目标目录路径: ").strip()
if not os.path.isdir(target_directory):
    print(f"错误：目录不存在: {target_directory}")
    exit(1)

operation = input("请输入操作类型 (e: 加密, d: 解密): ").strip().lower()
if operation == "e":
    print(f"开始加密目录：{target_directory}")
    encrypt_directory(target_directory, key)
    print("加密完成")
elif operation == "d":
    print(f"开始解密目录：{target_directory}")
    decrypt_directory(target_directory, key)
    print("解密完成")
else:
    print("错误：操作类型仅支持 e (加密) 或 d (解密)")
    exit(1)
