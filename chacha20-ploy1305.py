import os
import struct

def rotl(x: int, n: int) -> int:
    """循环左移32位整数x，左移n位"""
    left = (x << n) & 0xffffffff
    right = x >> (32 - n)
    return left | right

def quarter_round(x, a, b, c, d):
    """ChaCha20四元轮函数"""
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
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")

    constants = b"expand 32-byte k"
    const_words = struct.unpack("<4I", constants)
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    # 初始化状态数组
    state = [0] * 16
    for i in range(4):
        state[i] = const_words[i]
    for i in range(8):
        state[4 + i] = key_words[i]
    state[12] = counter
    for i in range(3):
        state[13 + i] = nonce_words[i]

    # 复制状态到工作数组
    working = state.copy()

    # 执行20轮 ChaCha20（10次column round + diagonal round）
    round_count = 10
    for i in range(round_count):
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

    # 将工作状态和初始状态相加（模2^32）
    output_words = [0] * 16
    for i in range(16):
        output_words[i] = (working[i] + state[i]) & 0xffffffff

    # 打包成字节（小端）
    output = struct.pack("<16I", *output_words)
    return output

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    ChaCha20加密/解密，数据与密钥流异或
    """
    result = bytearray()
    data_length = len(data)
    block_num = data_length // 64
    if data_length % 64 != 0:
        block_num += 1

    for block_index in range(block_num):
        keystream = chacha20_block(key, counter + block_index, nonce)
        block_start = block_index * 64
        block_end = block_start + 64
        if block_end > data_length:
            block_end = data_length
        block = data[block_start:block_end]

        for i in range(len(block)):
            byte = block[i] ^ keystream[i]
            result.append(byte)

    return bytes(result)

def poly1305_clamp_r_s(key: bytes):
    """
    对Poly1305 32字节密钥进行解析：
    前16字节是r（需要clamp），后16字节是s
    返回两个整数r和s
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes.")

    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    # clamp操作，清除具体位防止非法值
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f

    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    return r, s

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    计算Poly1305消息认证码
    """
    r, s = poly1305_clamp_r_s(key)
    p = (1 << 130) - 5
    acc = 0

    msg_len = len(msg)
    offset = 0

    while offset < msg_len:
        block = msg[offset:offset+16]
        block_len = len(block)
        # 不足16字节补零
        if block_len < 16:
            padded = block + b"\x00" * (16 - block_len)
        else:
            padded = block

        n = int.from_bytes(padded, "little")
        # 添加隐含的1（左移8*block_len位）
        n += 1 << (8 * block_len)
        acc = (acc + n) % p
        acc = (acc * r) % p

        offset += 16

    acc = (acc + s) % (1 << 128)
    tag = acc.to_bytes(16, "little")
    return tag

def pad16(data: bytes) -> bytes:
    """
    计算填充0字节，使数据长度是16的倍数，不足时补0
    """
    length = len(data)
    remainder = length % 16
    if remainder == 0:
        # 已经是16的倍数，无需填充
        return data
    padding_size = 16 - remainder
    padded = data + (b'\x00' * padding_size)
    return padded

def u64_le(n: int) -> bytes:
    """
    将64位整数编码成8字节小端格式
    """
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> (bytes, bytes):
    """
    AEAD ChaCha20-Poly1305 加密函数（无AAD）
    输入:
      key - 32字节密钥
      nonce - 12字节随机数
      plaintext - 要加密的数据
    输出:
      密文，认证标签
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")

    # 用计数器0产生poly1305密钥（32字节）
    poly1305_key = chacha20_block(key, 0, nonce)[:32]

    # 用计数器1开始生成加密密钥流，异或明文得到密文
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    # 构造认证数据： pad16(空) || pad16(ciphertext) || len(empty) || len(ciphertext)
    # 这里无AAD，所以只有空的aad和密文部分
    aad = b""  # 无附加认证数据
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly1305_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    AEAD ChaCha20-Poly1305 解密函数（无AAD）
    输入:
      key - 32字节密钥
      nonce - 12字节随机数
      ciphertext - 加密数据
      tag - 16字节认证标签
    输出:
      明文数据
    如果认证失败抛出ValueError异常
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")
    if len(tag) != 16:
        raise ValueError("Tag length must be 16 bytes.")

    poly1305_key = chacha20_block(key, 0, nonce)[:32]

    aad = b""  # 无附加认证数据
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    calculated_tag = poly1305_mac(poly1305_key, mac_data)
    if calculated_tag != tag:
        raise ValueError("Poly1305 authentication failed!")

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(file_path: str, key: bytes):
    """
    加密单个文件，原地覆盖
    文件存储格式：nonce(12) || tag(16) || 密文
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    nonce = os.urandom(12)
    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    with open(file_path, "wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    os.utime(file_path, (atime, mtime))

def decrypt_file(file_path: str, key: bytes):
    """
    解密单个文件，原地覆盖
    输入文件格式：nonce(12) || tag(16) || 密文
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as f:
        content = f.read()

    if len(content) < 28:
        raise ValueError("File content too short to be valid encrypted file.")

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(file_path, "wb") as f:
        f.write(plaintext)

    os.utime(file_path, (atime, mtime))

def encrypt_directory(directory: str, key: bytes):
    """
    递归加密目录下所有文件，原地覆盖
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a valid directory: {directory}")

    for root, dirs, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as e:
                print(f"Encryption failed for {filepath}: {str(e)}")

def decrypt_directory(directory: str, key: bytes):
    """
    递归解密目录下所有文件，原地覆盖
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a valid directory: {directory}")

    for root, dirs, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as e:
                print(f"Decryption failed for {filepath}: {str(e)}")

if __name__ == "__main__":
    # 示例密钥，32字节，请替换成安全密钥
    key = b'\x18\xe7\xc6\x14\xf0\xc9\xd2a\x04\xd9\xcf3\xc6\xb5\x1c\xc1\nQ\xec\xdbhd\xbe\x12\xcb\x08\x86\x9a\x05\xe7\xedO'

    if len(key) != 32:
        print("错误：密钥长度必须是32字节！")
        exit(1)

    target_directory = input("请输入目标目录路径: ").strip()
    if not os.path.isdir(target_directory):
        print("错误：目录不存在:", target_directory)
        exit(1)

    operation = input("请输入操作类型 (e: 加密, d: 解密): ").strip().lower()
    if operation == "e":
        print("开始加密目录:", target_directory)
        encrypt_directory(target_directory, key)
        print("加密完成")
    elif operation == "d":
        print("开始解密目录:", target_directory)
        decrypt_directory(target_directory, key)
        print("解密完成")
    else:
        print("错误：操作类型仅支持 e (加密) 或 d (解密)")
        exit(1)
