import socket
import threading
import struct
import time
import json
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def log(prefix, message):  # 打印带时间戳的日志，供运行时监控，便于排查网络及加密状态
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [{prefix}] {message}")

def generate_x25519_keypair():  # 生成X25519密钥对：私钥和对应公钥，保证密钥交换安全性
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_aes_gcm_key(private_key, peer_public_key):  # 使用ECDH共享密钥 + HKDF派生AES-GCM对称密钥，实现密钥协商
    shared_secret = private_key.exchange(peer_public_key)  # 计算共享密钥
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256位密钥，符合AES-GCM要求
        salt=None,  # 可加盐提高安全性，此处省略
        info=b"handshake data"  # 信息字段，防止多协议交叉使用同密钥
    )
    return hkdf.derive(shared_secret)  # 输出对称密钥

def recvall(sock, length):  # 确保从socket接收到完整指定长度数据，防止粘包或半包问题
    data = b''
    while len(data) < length:
        packet = sock.recv(length - len(data))  # 逐块接收缓冲区剩余大小
        if not packet:
            raise ConnectionError("Connection closed by peer")  # 对方断开连接异常
        data += packet
    return data

def send_packet(sock, data_bytes):  # 发送带长度前缀（4字节大端）的数据包，保证对端能准确解析数据边界
    sock.sendall(struct.pack('!I', len(data_bytes)))  # 4字节整数，网络字节序
    sock.sendall(data_bytes)  # 发送实际数据内容

def receive_packet(sock):  # 读取完整一包数据，先读4字节长度再读具体内容
    raw_len = recvall(sock, 4)
    (packet_length,) = struct.unpack('!I', raw_len)  # 解包得到整型长度
    return recvall(sock, packet_length)  # 读取对应字节数数据

def save_chat_record(role, text, timestamp_ms):  # 按角色保存聊天内容附带时间戳，方便后续审计或回放
    dt = datetime.fromtimestamp(timestamp_ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    filename = f"chat_record_{role.lower()}.log"  # 生成对应文件名，例如 chat_record_server.log
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{dt}] {role}: {text}\n")  # 追加写入文本内容，支持中文

def perform_server_handshake(conn):  # 服务端握手交换公钥，完成AES密钥协商
    server_priv, server_pub = generate_x25519_keypair()  # 先生成服务端密钥对
    conn.sendall(server_pub.public_bytes())    # 发服务端公钥（32字节）
    client_pub_bytes = recvall(conn, 32)       # 接收客户端公钥
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    aes_key = derive_aes_gcm_key(server_priv, client_pub)  # 派生对称密钥用于后续AES加密通讯
    log("SERVER", "Handshake complete, AES key established")  # 握手成功日志
    return AESGCM(aes_key)  # 返回AES-GCM对象用于加解密

def perform_client_handshake(conn):  # 客户端握手：先收服务端公钥，后发客户端公钥，完成密钥协商
    client_priv, client_pub = generate_x25519_keypair()
    server_pub_bytes = recvall(conn, 32)       # 先读服务器公钥
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    conn.sendall(client_pub.public_bytes())    # 发送客户端公钥
    aes_key = derive_aes_gcm_key(client_priv, server_pub)  # 派生AES密钥
    log("CLIENT", "Handshake complete, AES key established")
    return AESGCM(aes_key)

def sender_loop(conn, aesgcm, role, stop_event):  # 发送线程：从控制台获取消息，加密后发送
    prefix = f"{role}-SENDER"
    try:
        while not stop_event.is_set():
            message_text = input()  # 阻塞等待用户输入
            if stop_event.is_set():
                break
            if not message_text.strip():
                continue  # 跳过空消息，避免发送无效包
            payload = {
                "timestamp": int(time.time() * 1000),  # unix毫秒级时间戳
                "message": message_text.strip()
            }
            data = json.dumps(payload, ensure_ascii=False).encode()  # 转JSON并编码，保持完整的中文等字符
            nonce = os.urandom(12)  # AES-GCM推荐12字节随机数作为nonce
            ciphertext = aesgcm.encrypt(nonce, data, None)  # AEAD加密：nonce+密文+tag确保数据机密与完整
            packet = nonce + ciphertext  # 拼接包体
            try:
                send_packet(conn, packet)  # 通过自定义协议发包，保证粘包安全
                save_chat_record(role, message_text.strip(), payload["timestamp"])  # 本地日志保存消息
            except Exception as e:
                log(prefix, f"Send error: {e}")  # 发送异常时记录并退出循环
                stop_event.set()
                break
    except Exception as e:
        log(prefix, f"Sender loop terminated: {e}")  # 捕获input或其他异常安全退出
    finally:
        stop_event.set()  # 确保退出时通知停止接收线程

def receiver_loop(conn, aesgcm, role, stop_event):  # 接收线程：持续解密包显示消息，直到断线或结束
    prefix = f"{role}-RECEIVER"
    try:
        while not stop_event.is_set():
            packet = receive_packet(conn)  # 读取网络一包完整数据（nonce + 密文）
            nonce = packet[:12]  # 前12字节为nonce
            ciphertext = packet[12:]  # 后续为密文+tag
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # 解密，若数据被篡改则抛异常
            obj = json.loads(plaintext.decode())  # 解析JSON，恢复原始消息格式
            ts = obj.get("timestamp")
            text = obj.get("message")
            dt_str = datetime.fromtimestamp(ts / 1000.0).strftime("%H:%M:%S")  # 时间戳转时间字符串
            print(f"[{role} RECEIVED @ {dt_str}]: {text}")  # 控制台打印收到消息
            save_chat_record(role + "PEER", text, ts)  # 记录来自对方的聊天内容，文件名区别对方角色
    except Exception as e:
        log(prefix, f"Receiver loop terminated: {e}")  # 连接断开或解密异常退出循环
    finally:
        stop_event.set()  # 尽早通知发送线程关闭

def run_server(host, port):
    log("SERVER", f"Listening on {host}:{port}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 允许地址快速重用，避免TIME_WAIT阻塞
    listener.bind((host, port))
    listener.listen(1)
    while True:
        conn, addr = listener.accept()
        log("SERVER", f"Accepted connection from {addr}")  # 接受客户端连接
        try:
            aesgcm = perform_server_handshake(conn)  # 握手完毕启用AES-GCM加密通信
        except Exception as e:
            log("SERVER", f"Handshake failed: {e}")
            conn.close()  # 握手失败关闭	socket，等待下一次连入
            continue
        stop_event = threading.Event()  # 创建停止事件标志，供线程间同步关闭
        t_recv = threading.Thread(target=receiver_loop, args=(conn, aesgcm, "SERVER", stop_event), daemon=True)
        t_send = threading.Thread(target=sender_loop, args=(conn, aesgcm, "SERVER", stop_event), daemon=True)
        t_recv.start()  # 启动接收线程
        t_send.start()  # 启动发送线程
        try:
            while not stop_event.is_set():
                time.sleep(0.5)  # 主线程睡眠，保持程序持续运行，等待线程结束信号
        except KeyboardInterrupt:
            log("SERVER", "KeyboardInterrupt detected, shutting down connection")  # Ctrl+C退出支持
        stop_event.set()
        conn.close()  # 关闭连接，释放资源

def run_client(host, port):
    backoff = 1  # 断线重连初始等待时间
    while True:
        try:
            log("CLIENT", f"Connecting to {host}:{port}")
            conn = socket.create_connection((host, port), timeout=10)  # 支持连接超时，避免无限阻塞
            log("CLIENT", "Connection established")
            aesgcm = perform_client_handshake(conn)  # 握手完成，建立AES-GCM密钥
            stop_event = threading.Event()
            t_recv = threading.Thread(target=receiver_loop, args=(conn, aesgcm, "CLIENT", stop_event), daemon=True)
            t_send = threading.Thread(target=sender_loop, args=(conn, aesgcm, "CLIENT", stop_event), daemon=True)
            t_recv.start()
            t_send.start()
            while not stop_event.is_set():
                time.sleep(0.5)  # 持续等待线程结束或异常
            conn.close()  # 连接关闭，准备重连
            backoff = 1  # 连接成功，重置退避时间
        except Exception as e:
            log("CLIENT", f"Connection lost or error: {e} - retrying in {backoff}s")  # 网络异常重试提示
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)  # 指数退避避免频繁重试(最大30秒)

if __name__ == "__main__":
    mode = input("Select mode (server/client): ").strip().lower()  # 命令行选择角色
    host = "127.0.0.1"
    port = 5000
    if mode == "server":
        run_server(host, port)
    elif mode == "client":
        run_client(host, port)
    else:
        print("Invalid mode selected. Please run again.")  # 输入无效提示并退出
        sys.exit(1)
