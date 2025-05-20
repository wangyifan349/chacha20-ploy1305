import os
import struct

def rotl(x, n):
    """循环左移32位整数x，左移n位"""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    计算ChaCha20生成单个64字节密钥流块
    - key: 32字节对称密钥
    - counter: 32位块计数器
    - nonce: 12字节随机数
    返回生成的64字节密钥流块
    """
    constants = b"expand 32-byte k"
    # 解包为32位小端整数
    const_words = struct.unpack("<4I", constants)
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    # ChaCha20初始状态，16个32位字
    state = list(const_words + key_words + (counter,) + nonce_words)
    working = state.copy()

    def quarterround(x, a, b, c, d):
        """ChaCha20 quarter round操作，修改x数组中四个元素"""
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

    # 执行20轮，分10轮双轮（列变换 + 对角线变换）
    for _ in range(10):
        # 列变换
        quarterround(working, 0, 4, 8, 12)
        quarterround(working, 1, 5, 9, 13)
        quarterround(working, 2, 6, 10, 14)
        quarterround(working, 3, 7, 11, 15)
        # 对角线变换
        quarterround(working, 0, 5, 10, 15)
        quarterround(working, 1, 6, 11, 12)
        quarterround(working, 2, 7, 8, 13)
        quarterround(working, 3, 4, 9, 14)

    # 计算最终结果（working + 原始state）模2^32
    output_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    # 打包为64字节密钥流
    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    用ChaCha20对任意长度数据进行异或加密/解密（流式处理）
    - key: 32字节密钥
    - nonce: 12字节随机数
    - counter: 区块计数起点（一般从1开始）
    - data: 待加密/解密数据
    返回：加/解密结果，与输入长度相同
    """
    output = bytearray()
    n_blocks = (len(data) + 63) // 64  # 向上取整块数
    for block_idx in range(n_blocks):
        block = data[block_idx*64 : (block_idx+1)*64]
        keystream = chacha20_block(key, counter + block_idx, nonce)
        for i in range(len(block)):
            output.append(block[i] ^ keystream[i])
    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    根据Poly1305规范，对r部分执行clamp操作，拆分r和s为整数
    - key: 32字节子密钥，前16字节r，后16字节s
    返回 (r_int, s_int) 均为大整数
    """
    r = bytearray(key[:16])
    s = key[16:]

    # Poly1305 clamp规则限制r的位数，防止弱密钥
    r[3]  &= 0x0f
    r[7]  &= 0x0f
    r[11] &= 0x0f
    r[15] &= 0x0f
    r[4]  &= 0xfc
    r[8]  &= 0xfc
    r[12] &= 0xfc

    r_int = int.from_bytes(r, "little")
    s_int = int.from_bytes(s, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    计算Poly1305 MAC标签
    - key: 32字节验证码密钥（r和s）
    - msg: 待认证消息
    返回16字节认证标签
    """
    r, s = poly1305_clamp_r_s(key)
    p = (1 << 130) - 5  # Poly1305规格大素数
    acc = 0             # 累加器初始化为0

    # 分16字节块处理消息
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        # 不足16字节补零
        if len(block) < 16:
            block += b"\x00" * (16 - len(block))

        # 将当前块看作一个128位整数（小端）
        n = int.from_bytes(block, "little")
        # 加上高位设置的1 bit，即相当于 n + 2^128
        n += 1 << 128

        # 模素数 p 累加后乘以 r
        acc = (acc + n) % p
        acc = (acc * r) % p

    tag = (acc + s) % (1 << 128)
    # 结果取低128位转换为16字节小端输出
    return tag.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    将数据字节串填充到16字节的整数倍，填充0x00
    """
    pad_len = (16 - (len(data) % 16)) % 16
    if pad_len == 0:
        return data
    return data + (b"\x00" * pad_len)

def u64_le(n: int) -> bytes:
    """
    将整数n编码成8字节小端字节串
    """
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    """
    对明文使用ChaCha20-Poly1305加密（无AAD）
    流程：
    1. 用counter=0对nonce块计算poly_key（32字节）
    2. 用counter=1开始对plaintext加密
    3. 用poly_key计算Poly1305标签，消息由AAD+密文+长度构成
    返回：ciphertext和16字节tag
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]

    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    aad = b""
    poly_msg = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly_key, poly_msg)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    """
    ChaCha20-Poly1305解密并验证标签（无AAD）
    调用Poly1305验证标签，失败抛出异常
    如果验证成功，返回明文
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]

    aad = b""
    poly_msg = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    calc_tag = poly1305_mac(poly_key, poly_msg)
    if calc_tag != tag:
        raise ValueError("Poly1305 authentication failed!")

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(in_filepath: str, key: bytes):
    """
    加密单个文件，原地写入：
    - 头部写入随机12字节nonce + 16字节Poly1305 tag + ciphertext
    - 加密过程读取原文件访问和修改时间，写入后恢复文件时间戳
    """
    nonce = os.urandom(12)

    # 读取原文件访问和修改时间
    stat = os.stat(in_filepath)
    atime = stat.st_atime
    mtime = stat.st_mtime

    with open(in_filepath, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    # 覆盖写入文件（nonce + tag + ciphertext）
    with open(in_filepath, "wb") as f:
        f.write(nonce + tag + ciphertext)

    # 恢复文件时间戳
    os.utime(in_filepath, (atime, mtime))

def decrypt_file(in_filepath: str, key: bytes):
    """
    解密单个文件，原地写入明文：
    - 读取文件前12字节nonce，接16字节tag，剩余内容为ciphertext
    - 验证Poly1305标签，失败抛出异常
    - 解密成功覆盖写明文，恢复原文件时间戳
    """
    # 读取原文件访问和修改时间
    stat = os.stat(in_filepath)
    atime = stat.st_atime
    mtime = stat.st_mtime

    with open(in_filepath, "rb") as f:
        content = f.read()

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(in_filepath, "wb") as f:
        f.write(plaintext)

    os.utime(in_filepath, (atime, mtime))

def encrypt_directory(input_dir: str, key: bytes):
    """
    遍历目录递归加密所有文件，原地覆盖不修改文件名
    加密失败会打印错误信息继续
    """
    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as e:
                print(f"Encrypt failed: {filepath} - {e}")

def decrypt_directory(input_dir: str, key: bytes):
    """
    遍历目录递归解密所有文件，原地覆盖不修改文件名
    解密失败（一般是标签校验失败）打印错误信息继续
    """
    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as e:
                print(f"Decrypt failed: {filepath} - {e}")




key = b"your 32 bytes key here______________"  # 必须32字节，请自行确认长度
if len(key) != 32:
    print("错误：密钥长度必须是32字节！")
    exit(1)

input_dir = input("请输入目标目录路径: ").strip()
if not os.path.isdir(input_dir):
    print(f"错误：目录不存在: {input_dir}")
    exit(1)

op = input("请输入操作类型 (e: 加密, d: 解密): ").strip().lower()
if op == "e":
    print(f"开始加密目录：{input_dir}")
    encrypt_directory(input_dir, key)
    print("加密完成")
elif op == "d":
    print(f"开始解密目录：{input_dir}")
    decrypt_directory(input_dir, key)
    print("解密完成")
else:
    print("错误：操作类型仅支持 e (加密) 或 d (解密)")
    exit(1)


