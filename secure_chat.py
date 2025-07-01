import socket                                                        # 用于网络通信的socket模块
import threading                                                     # 用于多线程处理
import struct                                                        # 处理二进制数据格式转换
import time                                                          # 提供时间相关函数
import sys                                                           # 系统相关接口（未直接用到）
import os                                                            # 操作系统接口，用于生成随机数等
import json                                                          # JSON格式编码与解码
from cryptography.hazmat.primitives.asymmetric import x25519        # X25519密钥交换算法
from cryptography.hazmat.primitives.kdf.hkdf import HKDF            # HKDF密钥派生函数
from cryptography.hazmat.primitives import hashes                   # 哈希算法支持
from Cryptodome.Cipher import ChaCha20_Poly1305                     # ChaCha20-Poly1305加密算法支持

def generate_private_key():
    private_key = x25519.X25519PrivateKey.generate()                 # 生成X25519私钥对象
    return private_key                                               # 返回私钥

def get_public_bytes(private_key):
    public_key = private_key.public_key()                           # 从私钥派生对应公钥
    public_bytes = public_key.public_bytes()                        # 得到公钥的字节序列
    return public_bytes                                             # 返回公钥字节

def derive_shared_key(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)  # 从对方公钥字节恢复公钥对象
    shared_secret = private_key.exchange(peer_public_key)           # 计算共享秘密
    hkdf = HKDF(                                                    # 创建HKDF实例提取对称密钥
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"x25519-chacha20poly1305"
    )
    derived_key = hkdf.derive(shared_secret)                        # 派生最终的对称加密密钥
    return derived_key                                              # 返回共享密钥

def encrypt_json(key_bytes, data_dict):
    json_bytes = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')  # 压缩json对象并编码为字节
    nonce_bytes = os.urandom(12)                                         # 生成12字节随机nonce
    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)     # 初始化ChaCha20-Poly1305加密器
    ciphertext, tag = cipher.encrypt_and_digest(json_bytes)              # 加密并计算认证tag
    encrypted_bytes = nonce_bytes + ciphertext + tag                     # 拼接nonce、密文和tag
    return encrypted_bytes                                               # 返回加密字节串

def decrypt_json(key_bytes, encrypted_bytes):
    nonce_bytes = encrypted_bytes[0:12]                                  # 从数据中切出nonce
    tag_bytes = encrypted_bytes[-16:]                                    # 取出最后16字节为tag
    ciphertext_bytes = encrypted_bytes[12:-16]                           # 取出密文内容
    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)     # 初始化解密器
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)  # 解密并验证认证tag
    plaintext_str = plaintext_bytes.decode('utf-8')                      # 解码成字符串
    data_dict = json.loads(plaintext_str)                                # 解析JSON成字典
    return data_dict                                                    # 返回解密结果

def send_bytes_with_length(sock, data_bytes):
    length_bytes = struct.pack('>I', len(data_bytes))                   # 4字节大端格式长度
    sock.sendall(length_bytes)                                          # 发送长度信息
    sock.sendall(data_bytes)                                            # 发送实际数据

def receive_n_bytes(sock, n):
    data_buffer = b''                                                   # 数据缓存
    while len(data_buffer) < n:                                         # 循环直到收到足够数据
        chunk = sock.recv(n - len(data_buffer))                         # 接收剩余字节
        if not chunk:                                                   # 连接关闭或无数据
            return b''                                                 # 返回空表示失败
        data_buffer += chunk                                            # 累加数据
    return data_buffer                                                 # 返回完整数据

def receive_bytes_with_length(sock):
    length_bytes = receive_n_bytes(sock, 4)                            # 读取4字节长度
    if not length_bytes:                                               # 连接关闭则返回空
        return b''
    data_length = struct.unpack('>I', length_bytes)[0]                 # 解码长度
    data_bytes = receive_n_bytes(sock, data_length)                    # 读取具体数据
    return data_bytes                                                  # 返回数据

def send_thread_function(sock, shared_key, stop_event, sock_lock):
    print("[SendThread] Ready. Type messages and press Enter to send.")  # 提示用户
    while not stop_event.is_set():
        try:
            user_input = input()                                         # 获取输入
            if len(user_input.strip()) == 0:                            # 空消息忽略
                continue
            message_dict = {"msg": user_input}                          # 组装字典消息
            encrypted_data = encrypt_json(shared_key, message_dict)     # 加密数据
            sock_lock.acquire()                                         # 加锁保护socket操作
            try:
                if sock is None:                                        # Socket已关闭则退出线程
                    print("[SendThread] Socket closed, terminating send thread.")
                    break
                send_bytes_with_length(sock, encrypted_data)            # 发送消息
            finally:
                sock_lock.release()                                     # 释放锁
        except EOFError:                                                # 输入流结束时退出
            print("[SendThread] Input closed, terminating send thread.")
            break
        except Exception as e:
            print("[SendThread] Exception occurred:", repr(e))          # 打印异常并退出
            break
    print("[SendThread] Send thread exited.")                            # 线程结束提示

def receive_thread_function(sock, shared_key, stop_event, sock_lock):
    while not stop_event.is_set():
        try:
            sock_lock.acquire()                                         # 保护socket读操作
            try:
                if sock is None:                                        # socket关闭退出
                    print("[ReceiveThread] Socket closed, terminating receive thread.")
                    break
                encrypted_data = receive_bytes_with_length(sock)       # 接收完整消息包
            finally:
                sock_lock.release()                                     # 释放锁
            if not encrypted_data:                                      # 连接断开退出线程
                print("[ReceiveThread] Connection closed or no data, terminating receive thread.")
                break
            try:
                message_dict = decrypt_json(shared_key, encrypted_data) # 解密
                received_msg = message_dict.get("msg", "<no msg>")      # 解析消息文本
                print("[ReceiveThread] Peer:", received_msg)            # 显示收到内容
            except Exception as e:
                print("[ReceiveThread] Decryption/JSON parsing error:", repr(e))  # 解密异常提示
        except Exception as e:
            print("[ReceiveThread] Exception:", repr(e))                 # IO异常等打印
            break
    print("[ReceiveThread] Receive thread exited.")                      # 线程结束提示

def server_main_loop(local_ip, local_port, stop_event):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # 创建套接字
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 允许地址重用
    server_socket.bind((local_ip, local_port))                           # 绑定地址和端口
    server_socket.listen(1)                                              # 设置监听队列长度1
    server_socket.settimeout(1.0)                                        # 设置超时避免阻塞

    print("[Server] Listening on", local_ip, local_port)                  # 打印服务启动消息
    while not stop_event.is_set():
        try:
            client_socket, client_addr = server_socket.accept()          # 等待客户端连接
        except socket.timeout:
            continue                                                    # 超时继续检查停止信号
        except Exception as e:
            print("[Server] Exception in accept():", repr(e))             # 异常时打印并延时重试
            time.sleep(1)
            continue

        print("[Server] Accepted connection from", client_addr)          # 成功连接提示

        handle_server_connection(client_socket, stop_event)              # 处理客户端连接

        print("[Server] Client disconnected, resuming listen")            # 客户端断开后继续监听

    server_socket.close()                                                # 关闭socket
    print("[Server] Server stopped.")

def handle_server_connection(client_socket, stop_event):
    client_socket_lock = threading.Lock()                               # 创建锁用于socket保护
    with client_socket:
        try:
            server_priv_key = generate_private_key()                    # 创建服务端私钥
            server_pub_bytes = get_public_bytes(server_priv_key)        # 取得对应公钥字节

            send_bytes_with_length(client_socket, server_pub_bytes)     # 发送公钥给客户端

            client_pub_bytes = receive_bytes_with_length(client_socket) # 接收客户端公钥
            if not client_pub_bytes:
                print("[Server] Client public key missing, closing connection")
                return

            shared_key = derive_shared_key(server_priv_key, client_pub_bytes)  # 计算共享密钥
            print("[Server] Shared key established, secure channel ready")

            connection_stop_event = threading.Event()                    # 用于控制单连接线程停止

            send_thread = threading.Thread(target=send_thread_function,
                                           args=(client_socket, shared_key, connection_stop_event, client_socket_lock),
                                           daemon=True, name="Server-SendThread")
            receive_thread = threading.Thread(target=receive_thread_function,
                                              args=(client_socket, shared_key, connection_stop_event, client_socket_lock),
                                              daemon=True, name="Server-ReceiveThread")

            send_thread.start()                                          # 开启发送线程
            receive_thread.start()                                       # 开启接收线程

            while not stop_event.is_set() and send_thread.is_alive() and receive_thread.is_alive():
                time.sleep(0.5)                                          # 持续运行直到停止或线程意外退出

            connection_stop_event.set()                                  # 通知停止通信线程

            try:
                client_socket.shutdown(socket.SHUT_RDWR)                # 关闭连接
            except:
                pass
            client_socket.close()
        except Exception as e:
            print("[Server] Connection handler exception:", repr(e))
        print("[Server] Client connection closed")

def client_main_loop(server_ip, server_port, stop_event):
    client_priv_key = generate_private_key()                            # 客户端私钥
    client_pub_bytes = get_public_bytes(client_priv_key)                # 客户端公钥字节

    sock = None                                                        # 初始化socket
    sock_lock = threading.Lock()                                       # socket操作锁

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # 新建socket
            print("[Client] Connecting to", server_ip, server_port)    # 连接消息
            sock.settimeout(5)
            sock.connect((server_ip, server_port))                       # 连接服务器
            sock.settimeout(None)

            server_pub_bytes = receive_bytes_with_length(sock)          # 接收服务器公钥
            if not server_pub_bytes:
                print("[Client] Server public key not received, closing and retrying")
                sock.close()
                time.sleep(2)
                continue

            send_bytes_with_length(sock, client_pub_bytes)              # 发送客户端公钥

            shared_key = derive_shared_key(client_priv_key, server_pub_bytes)  # 派生共享密钥
            print("[Client] Shared key established, secure channel ready")

            connection_stop_event = threading.Event()                    # 管理通信线程停止的事件标志

            send_thread = threading.Thread(target=send_thread_function,
                                           args=(sock, shared_key, connection_stop_event, sock_lock),
                                           daemon=True, name="Client-SendThread")
            receive_thread = threading.Thread(target=receive_thread_function,
                                              args=(sock, shared_key, connection_stop_event, sock_lock),
                                              daemon=True, name="Client-ReceiveThread")

            send_thread.start()                                          # 启动发送线程
            receive_thread.start()                                       # 启动接收线程

            while not stop_event.is_set() and send_thread.is_alive() and receive_thread.is_alive():
                time.sleep(0.5)                                          # 保持通讯运行

            connection_stop_event.set()                                  # 通知线程退出

            try:
                sock.shutdown(socket.SHUT_RDWR)                          # 关闭socket
            except:
                pass
            sock.close()

            print("[Client] Connection closed, will retry in 2 seconds")
            time.sleep(2)
        except (ConnectionRefusedError, socket.timeout):
            print("[Client] Connection failed, retry after 2 seconds")
            time.sleep(2)
        except Exception as e:
            print("[Client] Exception:", repr(e))
            if sock:
                try:
                    sock.close()
                except:
                    pass
            time.sleep(2)

def read_ip(prompt):
    while True:
        user_input = input(prompt)
        if len(user_input.strip()) > 0:
            return user_input.strip()
        print("Input cannot be empty, please try again.")

def read_port(prompt):
    while True:
        user_input = input(prompt)
        user_input = user_input.strip()
        if not user_input.isdigit():
            print("Please enter a valid numeric port.")
            continue
        port = int(user_input)
        if port < 1 or port > 65535:
            print("Port number must be between 1 and 65535.")
            continue
        return port

def main():
    print("=== Secure TCP Chat Program ===")
    mode = ''

    while mode not in ('server', 'client'):
        mode = input("Select mode (server/client): ").strip().lower()
        if mode not in ('server', 'client'):
            print("Invalid input, please enter 'server' or 'client'.")

    stop_event = threading.Event()

    if mode == 'server':
        local_ip = read_ip("Enter local IP to listen on (e.g., 0.0.0.0): ")
        local_port = read_port("Enter local port to listen on: ")
        print("[Info] Starting server")
        server_thread = threading.Thread(target=server_main_loop,
                                         args=(local_ip, local_port, stop_event),
                                         daemon=True, name="Server-MainThread")       # 设置线程名称
        server_thread.start()
    else:
        server_ip = read_ip("Enter server IP to connect to: ")
        server_port = read_port("Enter server port to connect to: ")
        print("[Info] Starting client")
        client_thread = threading.Thread(target=client_main_loop,
                                         args=(server_ip, server_port, stop_event),
                                         daemon=True, name="Client-MainThread")       # 设置线程名称
        client_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] Ctrl+C detected, shutting down...")
        stop_event.set()
        time.sleep(1)
        print("[Main] Exited cleanly.")

if __name__ == '__main__':
    main()
