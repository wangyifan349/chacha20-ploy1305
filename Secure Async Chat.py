"""
Secure Async Chat & File Transfer
--------------------------------
这是一个基于 Python 的异步安全聊天和文件传输程序。程序逻辑如下：
1. 启动后用户选择角色（服务器或客户端）。
2. 客户端和服务器通过 X25519 密钥交换生成共享密钥，使用 HKDF 派生 AES-GCM 对称密钥。
3. 消息和文件在传输过程中使用 AES-GCM 加密，保证安全性。
4. 支持大文件分块传输，并在传输过程中显示百分比进度。
5. 文件传输完成后，接收方会使用 SHA-256 校验完整性。
6. 聊天记录包含对方 IP、时间戳和消息内容，追加写入 chat_history.log。
7. 消息输入支持单行发送，也可输入多行消息，以 END 结尾，保留换行和缩进。
"""

import asyncio, os, hashlib, time  # 异步、文件操作、hash、时间
from cryptography.hazmat.primitives import hashes, serialization  # 密码学 primitives
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # X25519 DH
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # 密钥派生
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM 对称加密

LOG_FILE = "chat_history.log"  # 聊天记录文件名

# ------------------------
# 日志记录函数
# ------------------------
def log_message(peer_ip, msg):
    """将消息记录到日志文件，包含时间戳和对方 IP"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())  # 当前时间
    with open(LOG_FILE, "a", encoding="utf-8") as f:  # 追加写入
        f.write(f"[{timestamp}] {peer_ip}: {msg}\n")  # 写入日志

# ------------------------
# 握手生成 AES-GCM 密钥
# ------------------------
async def handshake(reader, writer):
    """X25519 DH 握手 + HKDF 派生 AES-GCM 256-bit 对称密钥"""
    private_key = X25519PrivateKey.generate()  # 自己的私钥
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,  # 原始字节
        serialization.PublicFormat.Raw  # 原始格式
    )
    writer.write(public_bytes)  # 发送公钥
    await writer.drain()  # 确保发送完成

    peer_bytes = await reader.readexactly(32)  # 接收对方公钥
    peer_public = X25519PublicKey.from_public_bytes(peer_bytes)  # 构造公钥对象

    shared_key = private_key.exchange(peer_public)  # DH 交换共享密钥

    # HKDF 派生 AES-GCM 密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),  # 使用 SHA256
        length=32,  # 32 bytes = 256-bit AES key
        salt=None,  # 无盐
        info=b'handshake data'  # 可选信息
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)  # AES-GCM 对象
    return aesgcm  # 返回 AES-GCM 对象

# ------------------------
# 异步加密发送
# ------------------------
async def send_encrypted(writer, aesgcm, data):
    """加密数据并发送"""
    nonce = os.urandom(12)  # AES-GCM 12 字节随机 nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)  # 加密
    writer.write(len(ciphertext + nonce).to_bytes(4,'big') + nonce + ciphertext)  # 发送长度+nonce+密文
    await writer.drain()  # 确保发送完成

# ------------------------
# 异步接收解密
# ------------------------
async def recv_encrypted(reader, aesgcm):
    """接收加密数据并解密"""
    size_bytes = await reader.readexactly(4)  # 读取长度字段
    size = int.from_bytes(size_bytes,'big')  # 转成整数
    combined = await reader.readexactly(size)  # 读取 nonce + 密文
    nonce = combined[:12]  # 提取 nonce
    ciphertext = combined[12:]  # 提取密文
    return aesgcm.decrypt(nonce, ciphertext, None)  # 解密返回明文

# ------------------------
# 文件发送（大文件分块 + SHA256 + 进度显示）
# ------------------------
async def send_file(writer, aesgcm, filepath):
    """发送文件，显示进度百分比，并计算 SHA-256"""
    if not os.path.exists(filepath):
        print("File not found")  # 文件不存在
        return

    filename = os.path.basename(filepath).encode()  # 文件名
    await send_encrypted(writer, aesgcm, b"FILE:" + filename)  # 发送文件名

    filesize = os.path.getsize(filepath)  # 文件大小
    sha256 = hashlib.sha256()  # SHA-256 hash 对象
    sent_bytes = 0  # 已发送字节计数

    with open(filepath,"rb") as f:
        while chunk := f.read(4096):  # 分块读取
            sha256.update(chunk)  # 更新 hash
            await send_encrypted(writer, aesgcm, chunk)  # 发送加密块
            sent_bytes += len(chunk)
            percent = (sent_bytes/filesize)*100
            print(f"\rSending {filename.decode()}: {percent:.2f}%", end="")  # 显示进度
    print()
    digest = sha256.digest()  # 文件 hash
    await send_encrypted(writer, aesgcm, b"FILE_END" + digest)  # 文件结束 + hash
    print(f"File {filename.decode()} sent and hashed with SHA256")

# ------------------------
# 接收文件
# ------------------------
async def recv_file(data, save_dir="received"):
    """处理文件头，返回文件对象"""
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)  # 创建保存目录
    if data.startswith(b"FILE:"):
        filename = data[5:].decode()  # 提取文件名
        f = open(os.path.join(save_dir, filename),"wb")  # 打开文件写入
        return f
    return None

# ------------------------
# 消息发送循环（支持单行和多行 END 结尾）
# ------------------------
async def send_loop(writer, aesgcm, peer_ip):
    """单行直接发送，多行以 END 结尾"""
    while True:
        msg = input("Enter message (single line or START for multi-line): ").rstrip()  # 用户输入
        if msg.upper() == "START":  # 多行模式
            print("Multi-line mode: type your message, finish with END on a new line.")
            lines = []
            while True:
                line = input()  # 多行输入
                if line.strip() == "END":
                    break
                lines.append(line)  # 保留缩进和空行
            msg_to_send = "\n".join(lines)  # 合并多行
        else:  # 单行模式
            msg_to_send = msg  # 单行消息

        if msg_to_send.startswith("/sendfile "):  # 文件发送命令
            path = msg_to_send.split(" ",1)[1]
            await send_file(writer, aesgcm, path)
        else:
            await send_encrypted(writer, aesgcm, msg_to_send.encode())  # 发送加密消息
            log_message(peer_ip, msg_to_send)  # 记录日志

# ------------------------
# 服务端
# ------------------------
async def server(host='0.0.0.0', port=9999):
    async def handle_client(reader, writer):
        peer_ip = writer.get_extra_info("peername")[0]  # 获取对方 IP
        aesgcm = await handshake(reader, writer)  # 握手生成 AES-GCM
        print(f"Connected by {peer_ip}. AES-GCM key established.")

        current_file = None  # 当前接收文件对象

        async def recv_loop():
            nonlocal current_file
            while True:
                try:
                    data = await recv_encrypted(reader, aesgcm)  # 接收解密
                    if data.startswith(b"FILE_END"):  # 文件结束
                        digest = data[8:]
                        if current_file:
                            current_file.close()
                            sha256 = hashlib.sha256()
                            with open(current_file.name,"rb") as f:
                                while chunk := f.read(4096):
                                    sha256.update(chunk)
                            if sha256.digest() == digest:
                                print(f"File {current_file.name} verified successfully")
                            else:
                                print(f"File {current_file.name} verification FAILED!")
                            current_file = None
                    elif data.startswith(b"FILE:"):  # 文件名
                        current_file = await recv_file(data)
                        print(f"Receiving file: {current_file.name}")
                    else:  # 普通消息
                        if current_file:
                            current_file.write(data)
                        else:
                            msg = data.decode(errors='ignore')
                            print(f"{peer_ip}: {msg}")
                            log_message(peer_ip, msg)
                except:
                    break

        await asyncio.gather(recv_loop(), send_loop(writer, aesgcm, peer_ip))  # 同时接收和发送

    srv = await asyncio.start_server(handle_client, host, port)  # 启动服务器
    print(f"Server listening on {host}:{port}")
    async with srv:
        await srv.serve_forever()  # 循环监听

# ------------------------
# 客户端
# ------------------------
async def client(host='127.0.0.1', port=9999):
    reader, writer = await asyncio.open_connection(host, port)
    peer_ip = host
    aesgcm = await handshake(reader, writer)
    print(f"Connected to {peer_ip}. AES-GCM key established.")

    current_file = None

    async def recv_loop():
        nonlocal current_file
        while True:
            try:
                data = await recv_encrypted(reader, aesgcm)
                if data.startswith(b"FILE_END"):
                    digest = data[8:]
                    if current_file:
                        current_file.close()
                        sha256 = hashlib.sha256()
                        with open(current_file.name,"rb") as f:
                            while chunk := f.read(4096):
                                sha256.update(chunk)
                        if sha256.digest() == digest:
                            print(f"File {current_file.name} verified successfully")
                        else:
                            print(f"File {current_file.name} verification FAILED!")
                        current_file = None
                elif data.startswith(b"FILE:"):
                    current_file = await recv_file(data)
                    print(f"Receiving file: {current_file.name}")
                else:
                    if current_file:
                        current_file.write(data)
                    else:
                        msg = data.decode(errors='ignore')
                        print(f"{peer_ip}: {msg}")
                        log_message(peer_ip, msg)
            except:
                break

    await asyncio.gather(recv_loop(), send_loop(writer, aesgcm, peer_ip))

# ------------------------
# 交互式菜单
# ------------------------
def main_menu():
    print("=== Secure Async Chat & File Transfer ===")
    print("1. Run as Server")
    print("2. Run as Client")
    choice = input("Select role: ")
    host = input("Host (default 127.0.0.1): ") or "127.0.0.1"
    port = int(input("Port (default 9999): ") or "9999")
    return choice, host, port

if __name__ == "__main__":
    choice, host, port = main_menu()
    if choice == "1":
        asyncio.run(server(host, port))
    else:
        asyncio.run(client(host, port))
