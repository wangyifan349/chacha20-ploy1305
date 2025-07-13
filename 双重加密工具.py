import os                                           # 导入操作系统模块，处理文件和目录
import json                                         # 导入 JSON 模块，处理 JSON 数据
import base64                                       # 导入 Base64 编码模块
import struct                                       # 导入结构解析模块，用于处理二进制数据的打包与拆包
from getpass import getpass                         # 导入安全输入密码的函数
from Crypto.Cipher import AES, ChaCha20_Poly1305   # 导入加密模块，AES-GCM和ChaCha20-Poly1305算法
from Crypto.Protocol.KDF import PBKDF2              # 导入PBKDF2密钥派生函数
from Crypto.Random import get_random_bytes          # 导入生成随机字节函数
from Crypto.Hash import SHA256                       # 导入SHA256哈希算法
import concurrent.futures                            # 导入多线程执行模块
import threading                                    # 导入线程模块，处理线程安全
import traceback                                   # 导入traceback，用于捕获异常信息（此程序未使用，但常用）

PBKDF2_ITERATIONS = 100_000                        # PBKDF2迭代次数，增加密码推导强度
KEY_LENGTH = 32                                    # 密钥长度，32字节即256位
LOG_FILE = "decrypt_failures.log"                  # 解密失败日志文件名

# --- 线程安全计数器和列表 ---
_encrypt_success_count = 0                          # 成功加密文件计数器，初始为0
_decrypt_success_count = 0                          # 成功解密文件计数器，初始为0
_skip_list = []                                     # 跳过处理文件列表（权限不足或格式不符）
_fail_list = []                                     # 失败处理文件列表（异常等）
_lock = threading.Lock()                            # 线程锁，保证多线程时数据安全

def derive_key(password: str, salt: bytes, iterations=PBKDF2_ITERATIONS) -> bytes:     # 使用PBKDF2派生密钥函数
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=iterations, hmac_hash_module=SHA256)  # 返回PBKDF2派生的密钥

def encode_header(header_dict: dict) -> bytes:                      # JSON序列化字典为字节
    return json.dumps(header_dict).encode('utf-8')                  # 转换为utf-8字节

def decode_header(header_bytes: bytes) -> dict:                     # JSON字节反序列化为字典
    return json.loads(header_bytes.decode('utf-8'))                 # utf-8解码后加载为字典

def write_file_with_header(path: str, header: dict, nonce: bytes, tag: bytes, ciphertext: bytes):
    header_bytes = encode_header(header)                            # 先编码header为字节
    header_len = len(header_bytes)                                  # 计算header字节长度
    with open(path, 'wb') as f:                                    # 以写二进制模式打开文件
        f.write(struct.pack('>I', header_len))                     # 写4字节大端整数表示header长度
        f.write(header_bytes)                                       # 写入header字节
        f.write(nonce)                                              # 写入随机生成的nonce（初始化向量）
        f.write(tag)                                                # 写入认证标签tag
        f.write(ciphertext)                                         # 写入加密后的密文

def read_file_and_parse_header(path: str):
    with open(path, 'rb') as f:                                    # 以读二进制模式打开文件
        raw = f.read()                                             # 读取全部文件内容
    if len(raw) < 4:                                               # 文件内容不足4字节，不合法
        return None                                                # 返回None表示解析失败
    header_len = struct.unpack('>I', raw[:4])[0]                   # 读取前4字节大端整数为header长度
    if len(raw) < 4 + header_len + 12 + 16:                        # 检查是否足够读header + nonce + tag + ciphertext，nonce12字节，tag16字节
        return None                                                # 长度不够时返回None
    header_bytes = raw[4:4+header_len]                             # 获取header对应字节
    try:
        header = decode_header(header_bytes)                       # 解码header字节为字典
    except Exception:
        return None                                                # json解码失败返回None
    nonce_start = 4 + header_len                                   # nonce起始字节偏移
    nonce = raw[nonce_start:nonce_start+12]                        # 取12字节nonce
    tag = raw[nonce_start+12:nonce_start+28]                       # 取16字节tag
    ciphertext = raw[nonce_start+28:]                              # 其余为密文
    return header, nonce, tag, ciphertext                          # 返回解析出的结构

def aesgcm_encrypt(data: bytes, key: bytes):                      # AES-GCM加密函数
    nonce = get_random_bytes(12)                                  # 生成12字节随机nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)              # 初始化AES-GCM密码器
    ciphertext, tag = cipher.encrypt_and_digest(data)             # 加密数据并生成认证tag
    return nonce, tag, ciphertext                                  # 返回nonce、tag和密文

def aesgcm_decrypt(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)              # 初始化AES-GCM解密器带nonce
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)        # 解密且验证tag，异常则抛出
    return plaintext                                              # 返回明文

def chacha20_encrypt(data: bytes, key: bytes):                    # ChaCha20-Poly1305加密函数
    nonce = get_random_bytes(12)                                  # 生成12字节随机nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)          # 初始化ChaCha20-Poly1305密码器
    ciphertext, tag = cipher.encrypt_and_digest(data)             # 加密并生成认证tag
    return nonce, tag, ciphertext                                  # 返回nonce、tag、密文

def chacha20_decrypt(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)          # 初始化解密器
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)        # 解密并验证tag
    return plaintext                                              # 返回明文

def double_encrypt(data: bytes, aesgcm_key: bytes, chacha_key: bytes, salt_aesgcm: bytes, salt_chacha20: bytes):  
    aes_nonce, aes_tag, aes_ciphertext = aesgcm_encrypt(data, aesgcm_key)   # 先用AES-GCM加密数据，得到nonce/tag/密文
    aes_blob = aes_nonce + aes_tag + aes_ciphertext                         # 拼接AES-GCM完整加密块
    c20_nonce, c20_tag, c20_ciphertext = chacha20_encrypt(aes_blob, chacha_key)  # 用ChaCha20-Poly1305加密上述块
    header = {                                                              # 构造文件头metadata
        "algorithm": "double_aesgcm_chacha20poly1305",                     # 标记算法
        "pbkdf2_iterations": PBKDF2_ITERATIONS,                            # 迭代次数
        "key_length": KEY_LENGTH,                                           # 密钥长度
        "salt_aesgcm": base64.b64encode(salt_aesgcm).decode("utf-8"),      # AES盐Base64编码字符串
        "salt_chacha20": base64.b64encode(salt_chacha20).decode("utf-8"),  # ChaCha20盐Base64编码字符串
    }
    return header, c20_nonce, c20_tag, c20_ciphertext                     # 返回完整加密数据结构

def double_decrypt(c20_nonce: bytes, c20_tag: bytes, c20_ciphertext: bytes, aesgcm_key: bytes, chacha_key: bytes):
    aes_blob = chacha20_decrypt(c20_nonce, c20_tag, c20_ciphertext, chacha_key)   # 先用ChaCha20解密，得到AES加密块
    if len(aes_blob) < 12 + 16:                                                  # 校验AES-GCM加密块是否完整（nonce12 + tag16）
        raise ValueError("AES-GCM data format error")                             # 格式错误抛异常
    aes_nonce = aes_blob[:12]                                                     # 获取AES nonce
    aes_tag = aes_blob[12:28]                                                     # 获取AES tag
    aes_ciphertext = aes_blob[28:]                                                # 获取AES密文
    plaintext = aesgcm_decrypt(aes_nonce, aes_tag, aes_ciphertext, aesgcm_key)    # 用AES解密
    return plaintext                                                              # 返回明文

def check_permissions(path: str, mode: str) -> bool:                             # 检查文件权限，读或写
    if mode == 'r':                                                              # 若检查读取权限
        return os.access(path, os.R_OK)                                          # 判断是否可读
    elif mode == 'w':                                                            # 若检查写入权限
        return os.access(path, os.W_OK)                                          # 判断是否可写
    else:
        return False                                                             # 不支持模式返回False

def encrypt_file(path: str, password: str):
    global _encrypt_success_count                                               # 申明使用全局加密计数器
    if not (check_permissions(path, 'r') and check_permissions(path, 'w')):     # 检查文件是否可读写
        with _lock:                                                             # 加锁，线程安全访问
            _skip_list.append(path)                                             # 不可访问则加入跳过列表
        return
    try:
        stat = os.stat(path)                                                    # 获取文件状态信息
        atime, mtime = stat.st_atime, stat.st_mtime                            # 记录访问时间和修改时间
        with open(path, 'rb') as f:                                            # 以二进制读模式打开文件
            data = f.read()                                                     # 读取文件内容
        salt_aesgcm = get_random_bytes(16)                                     # 生成16字节salt用于AES PBKDF2
        salt_chacha20 = get_random_bytes(16)                                   # 生成16字节salt用于ChaCha20 PBKDF2
        aesgcm_key = derive_key(password, salt_aesgcm, PBKDF2_ITERATIONS)      # 派生AES密钥
        chacha_key = derive_key(password, salt_chacha20, PBKDF2_ITERATIONS)    # 派生ChaCha20密钥
        header, nonce, tag, ciphertext = double_encrypt(data, aesgcm_key, chacha_key, salt_aesgcm, salt_chacha20) # 执行双重加密
        write_file_with_header(path, header, nonce, tag, ciphertext)            # 写回文件，覆盖原文件
        os.utime(path, (atime, mtime))                                         # 恢复原本文件访问和修改时间
        with _lock:                                                            # 加锁保护计数器
            _encrypt_success_count += 1                                        # 成功加密计数加一
    except Exception:                                                          # 捕获所有异常
        with _lock:                                                            # 加锁保护
            _fail_list.append(path)                                            # 失败文件记录

def decrypt_file(path: str, password: str):
    global _decrypt_success_count                                               # 申明解密成功计数器
    if not (check_permissions(path, 'r') and check_permissions(path, 'w')):     # 检查文件读写权限
        with _lock:                                                             # 加锁操作
            _skip_list.append(path)                                             # 权限不足，加入跳过列表
        return
    try:
        stat = os.stat(path)                                                    # 获取文件状态信息
        atime, mtime = stat.st_atime, stat.st_mtime                            # 保存访问时间和修改时间
        parsed = read_file_and_parse_header(path)                             # 读取并解析文件头及数据
        if parsed is None:                                                     # 若解析失败
            with _lock:
                _skip_list.append(path)                                        # 加入跳过列表
            return
        header, nonce, tag, ciphertext = parsed                               # 解包解析结果
        if header.get("algorithm") != "double_aesgcm_chacha20poly1305":       # 非本程序加密算法则跳过
            with _lock:
                _skip_list.append(path)
            return
        salt_aesgcm_b64 = header.get("salt_aesgcm")                           # 读出salt aesgcm
        salt_chacha20_b64 = header.get("salt_chacha20")                       # 读出salt chacha20
        if not salt_aesgcm_b64 or not salt_chacha20_b64:                      # 缺盐则失败
            with _lock:
                _fail_list.append(path)
            return
        salt_aesgcm = base64.b64decode(salt_aesgcm_b64)                       # Base64解码salt aesgcm
        salt_chacha20 = base64.b64decode(salt_chacha20_b64)                   # Base64解码salt chacha20
        iterations = header.get("pbkdf2_iterations", PBKDF2_ITERATIONS)       # 取迭代次数，默认预设值
        aesgcm_key = derive_key(password, salt_aesgcm, iterations)            # 派生AES密钥
        chacha_key = derive_key(password, salt_chacha20, iterations)          # 派生ChaCha20密钥
        plaintext = double_decrypt(nonce, tag, ciphertext, aesgcm_key, chacha_key)  # 执行双重解密
        with open(path, 'wb') as f:                                           # 以写二进制模式打开覆盖文件
            f.write(plaintext)                                                # 写回明文
        os.utime(path, (atime, mtime))                                       # 恢复原访问和修改时间
        with _lock:
            _decrypt_success_count += 1                                      # 成功解密计数加一
    except Exception:
        with _lock:
            _fail_list.append(path)                                          # 解密失败记录

def process_file(args):                                                      # 线程执行函数，处理单文件
    path, password, mode = args                                             # 解包参数
    if mode == 'e':                                                         # 加密模式
        encrypt_file(path, password)                                        # 调用加密函数
    else:                                                                  # 解密模式
        decrypt_file(path, password)                                        # 调用解密函数

def process_dir(dir_path: str, password: str, mode: str):
    file_args = []                                                          # 存放所有文件的参数元组列表
    for root, dirs, files in os.walk(dir_path):                            # 遍历目录及所有子目录文件
        for filename in files:
            filepath = os.path.join(root, filename)                        # 组合完整路径
            file_args.append((filepath, password, mode))                   # 加入参数列表
    max_workers = min(32, (os.cpu_count() or 1) + 4)                       # 线程池最大线程数
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:  # 创建线程池
        executor.map(process_file, file_args)                              # 并发执行文件处理

def write_fail_log():
    if not _fail_list:                                                     # 失败列表为空则无日志写入
        return
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:                 # 以写模式打开日志文件
            for file in _fail_list:
                f.write(file + '\n')                                      # 写入失败文件路径每行
    except Exception:                                                     # 失败日志写入异常忽略
        pass

# --------------------------------------------------------------

def main():
    print("=== 双重加密（AES-GCM + ChaCha20-Poly1305）文件加密/解密 ===")   # 显示程序标题
    mode = input("请选择模式（e：加密, d：解密）：").strip().lower()              # 选择模式并统一小写
    if mode not in ('e', 'd'):                                              # 非法模式退出
        print("模式错误，退出。")
        return
    dir_path = input("请输入待处理目录路径：").strip()                        # 输入待处理目录
    if not os.path.isdir(dir_path):                                          # 目录不存在退出
        print("目录不存在，退出。")
        return
    while True:                                                             # 密码输入循环，防止不一致
        pwd1 = getpass("请输入密码：")                                      # 输入密码，不回显
        pwd2 = getpass("请再次输入密码确认：")                              # 再次输入确认
        if pwd1 != pwd2:                                                    # 两次不同提示重新输入
            print("两次密码不一致，请重新输入。")
            continue
        if len(pwd1) == 0:                                                  # 空密码不允许
            print("密码不能为空。")
            continue
        break                                                              # 符合条件退出循环
    process_dir(dir_path, pwd1, mode)                                      # 执行目录批量处理
    write_fail_log()                                                       # 处理完成后写入失败日志
    print("\n=== 处理完成，统计如下 ===")                                   # 输出统计信息
    print(f"成功加密文件数: {_encrypt_success_count}")                      # 输出加密成功数量
    print(f"成功解密文件数: {_decrypt_success_count}")                      # 输出解密成功数量
    print(f"跳过文件数（无权限/格式不符等）: {len(_skip_list)}")             # 输出跳过文件数量
    for p in _skip_list:                                                    # 列出所有跳过文件
        print(f"  跳过: {p}")
    print(f"失败文件数: {len(_fail_list)}")                                # 输出失败文件数量
    if _fail_list:                                                         # 有失败文件则提示日志文件
        print(f"失败文件已记录到 {LOG_FILE}")

if __name__ == '__main__':
    main()                                                               # 程序入口，执行main函数
