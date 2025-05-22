import os
import struct

def rotl(x: int, n: int) -> int:
    """循环左移32位整数x，左移n位"""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    计算ChaCha20单个64字节密钥流块
    参数:
      key: 32字节
      counter: 32位整数
      nonce: 12字节
    返回:
      64字节的密钥流块
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

    # 执行10轮，每轮包含一轮“列变换”与“对角线变换”
    for _ in range(10):
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

    output_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    ChaCha20加密/解密：数据与密钥流XOR
    参数:
      key: 32字节
      nonce: 12字节
      counter: 初始计数器，一般从1开始（0用于生成Poly1305密钥流）
      data: 待加密或解密数据
    返回:
      处理后的数据
    """
    output = bytearray()
    data_length = len(data)
    block_count = (data_length + 63) // 64

    for block_index in range(block_count):
        block_start = block_index * 64
        block_end = block_start + 64
        block = data[block_start:block_end]
        keystream = chacha20_block(key, counter + block_index, nonce)

        for byte_index in range(len(block)):
            output.append(block[byte_index] ^ keystream[byte_index])

    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    对Poly1305 32字节密钥进行解析：
     - 前16字节作为 r 值，并按照标准进行clamp
     - 后16字节作为 s 值，保持不变
    返回:
      (r, s) 两个整数
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
        
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    # 清除字节索引3、7、11、15的高4位（仅保留低4位）
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    # 清除字节索引4、8、12的低2位（只保留高6位）
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r_int = int.from_bytes(r_bytes, "little")
    s_int = int.from_bytes(s_bytes, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    计算Poly1305认证标签 (MAC)
    参数:
      key: 32字节密钥，前16字节作为r（需要clamp），后16字节作为s
      msg: 待认证数据
    返回:
      16字节MAC
    """
    r, s = poly1305_clamp_r_s(key)
    prime_p = (1 << 130) - 5
    accumulator = 0

    msg_idx = 0
    msg_len = len(msg)
    while msg_idx < msg_len:
        block = msg[msg_idx:msg_idx + 16]
        block_length = len(block)
        # 补零只用于转换为整数，不影响隐含位的计算
        if block_length < 16:
            block = block + (b"\x00" * (16 - block_length))
        # 根据实际块长度添加隐含1（隐含的1位在块低位表示，即 1 << (8 * block_length)）
        n = int.from_bytes(block, "little") + (1 << (8 * block_length))
        accumulator = (accumulator + n) % prime_p
        accumulator = (accumulator * r) % prime_p
        msg_idx += 16

    tag_num = (accumulator + s) % (1 << 128)
    return tag_num.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    数据填充到16字节整数倍（使用0x00填充）
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
    """
    ChaCha20-Poly1305 AEAD 加密
    参数:
      key: 32字节主密钥
      nonce: 12字节随机数
      plaintext: 明文数据
      aad: 附加数据，可以为空（在计算MAC时加入，但不加密）
    返回:
      (ciphertext, tag)
    """
    # 使用ChaCha20的第0个块生成Poly1305密钥（仅前32字节）
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    # 从计数器1开始生成加密数据的密钥流
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    # 构造MAC数据：A || pad16(A) || C || pad16(C) || [len(A)]_8 || [len(C)]_8
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly1305_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """
    ChaCha20-Poly1305 AEAD 解密与认证验证
    参数:
      key: 32字节主密钥
      nonce: 12字节随机数
      ciphertext: 加密数据
      tag: 16字节认证标签
      aad: 附加数据
    返回:
      明文数据，如果验证失败，则抛出异常
    """
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))
    calculated_tag = poly1305_mac(poly1305_key, mac_data)
    if calculated_tag != tag:
        raise ValueError("Poly1305 authentication failed!")
    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(file_path: str, key: bytes):
    """
    加密单个文件，原地覆盖
    文件存储格式: nonce (12字节) || tag (16字节) || ciphertext
    """
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
    """
    解密单个文件，原地覆盖
    输入文件格式: nonce (12字节) || tag (16字节) || ciphertext
    """
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
        for filename in files:
            filepath = os.path.join(current_root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as exc:
                print(f"Encrypt failed: {filepath} - {exc}")

def decrypt_directory(input_directory: str, key: bytes):
    """递归解密目录内所有文件，原地覆盖"""
    for current_root, directories, files in os.walk(input_directory):
        for filename in files:
            filepath = os.path.join(current_root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as exc:
                print(f"Decrypt failed: {filepath} - {exc}")


# 示例密钥，32字节（请替换为你自己的密钥）
key = b'\x18\xe7\xc6\x14\xf0\xc9\xd2a\x04\xd9\xcf3\xc6\xb5\x1c\xc1\nQ\xec\xdbhd\xbe\x12\xcb\x08\x86\x9a\x05\xe7\xedO'
"""
# 或生成随机密钥并打印十六进制表示
key = os.urandom(32)
print(f"生成的密钥（hex）：{key.hex()}")
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
