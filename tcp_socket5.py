#!/usr/bin/env python3
import socket
import struct
import time
import os
import sys
from multiprocessing import Process, Queue
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import socks  # PySocks

# 公共配置
MAX_DRIFT = 60    # 时间戳最大允许偏差 (秒)
NONCE_SIZE = 12   # ChaCha20-Poly1305 推荐 12 字节 nonce
TS_SIZE = 8       # uint64 时间戳字段长度
LEN_SIZE = 4      # uint32 密文长度字段长度
def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接被关闭")
        buf += chunk
    return buf
def do_handshake(sock, is_client):
    """
    基于 X25519 完成公钥交换，返回初始化好的 ChaCha20Poly1305 对象
    """
    if is_client:
        # 客户端先发公钥
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes()
        sock.sendall(struct.pack('>H', len(pub)) + pub)
        # 再收服务端公钥
        plen = struct.unpack('>H', recv_all(sock, 2))[0]
        peer_pub = recv_all(sock, plen)
    else:
        # 服务端先收客户端公钥
        plen = struct.unpack('>H', recv_all(sock, 2))[0]
        peer_pub = recv_all(sock, plen)

        # 再发自己公钥
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes()
        sock.sendall(struct.pack('>H', len(pub)) + pub)

    peer_key = X25519PublicKey.from_public_bytes(peer_pub)
    shared = priv.exchange(peer_key)
    # 取共享密钥的前 32 字节做 AEAD key
    return ChaCha20Poly1305(shared[:32])


def encrypt_and_send(sock, aead, send_q):
    """
    从 send_q 读明文，封包加密后通过 sock 发送
    帧格式：TS(8B) | NONCE(12B) | LEN(4B) | CT(...)
    """
    try:
        while True:
            data = send_q.get()
            if data is None:
                break
            ts = int(time.time())
            nonce = os.urandom(NONCE_SIZE)
            ct = aead.encrypt(nonce, data, None)
            packet = (
                struct.pack('>Q', ts) +
                nonce +
                struct.pack('>I', len(ct)) +
                ct
            )
            sock.sendall(packet)
    except Exception as e:
        print("[E] send 进程异常:", e)
    finally:
        sock.close()
def recv_and_decrypt(sock, aead, recv_q, role_name):
    """
    从 sock 收加密帧、解密后推入 recv_q
    丢弃过期/未来帧或 MAC 校验失败的帧
    """
    try:
        header_size = TS_SIZE + NONCE_SIZE + LEN_SIZE
        while True:
            hdr = recv_all(sock, header_size)
            ts = struct.unpack('>Q', hdr[:TS_SIZE])[0]
            nonce = hdr[TS_SIZE:TS_SIZE + NONCE_SIZE]
            length = struct.unpack('>I', hdr[TS_SIZE + NONCE_SIZE:])[0]
            ct = recv_all(sock, length)

            # 时间戳校验
            if abs(time.time() - ts) > MAX_DRIFT:
                print(f"[W] {role_name} 丢弃 过期或未来 帧 ts={ts}")
                continue
            # 解密并 MAC 校验
            try:
                data = aead.decrypt(nonce, ct, None)
            except Exception:
                print(f"[W] {role_name} MAC 校验失败，丢弃帧")
                continue
            recv_q.put(data)
    except Exception as e:
        print(f"[E] {role_name} recv 进程异常:", e)
    finally:
        sock.close()


def run_client(server_ip, server_port, local_socks_port):
    """
    客户端主流程：
    1. 建链并 X25519 握手
    2. 启动 send/recv 两个子进程
    3. 本地监听 SOCKS5，将客户端流量推入 send_q，
       并从 recv_q 中读取远端返回再写回给本地 SOCKS5 客户端
    """
    print(f"[*] 连接到服务端 {server_ip}:{server_port} …")
    s = socket.create_connection((server_ip, server_port))
    aead = do_handshake(s, is_client=True)
    print("[*] 握手完成，安全通道已建立")
    send_q = Queue()
    recv_q = Queue()
    p_send = Process(
        target=encrypt_and_send,
        args=(s, aead, send_q),
        daemon=True
    )
    p_recv = Process(
        target=recv_and_decrypt,
        args=(s, aead, recv_q, "客户端"),
        daemon=True
    )
    p_send.start()
    p_recv.start()
    # 本地 SOCKS5 监听
    listen = socket.socket()
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', local_socks_port))
    listen.listen(5)
    print(f"[*] 本地 SOCKS5 代理启动: 127.0.0.1:{local_socks_port}")
    try:
        while True:
            client_sock, _ = listen.accept()
            # 每个连接再 fork 出一个子 Process 来做 SOCKS5 握手／转发
            p = Process(
                target=handle_socks5_client,
                args=(client_sock, send_q, recv_q),
                daemon=True
            )
            p.start()
    except KeyboardInterrupt:
        pass
    finally:
        listen.close()
        send_q.put(None)
        p_send.join()
        p_recv.join()
        print("[*] 客户端退出")


def handle_socks5_client(client_sock, enc_send_q, enc_recv_q):
    """
    完整的 SOCKS5 握手和转发逻辑，使用 enc_send_q/enc_recv_q 做加密隧道
    """
    try:
        # 1. 协商版本和认证
        ver_n = client_sock.recv(2)
        if len(ver_n) != 2 or ver_n[0] != 0x05:
            client_sock.close()
            return
        nmethods = ver_n[1]
        client_sock.recv(nmethods)       # 丢弃方法列表
        client_sock.sendall(b'\x05\x00') # NO AUTH
        # 2. 读请求头
        hdr = recv_all(client_sock, 4)
        cmd = hdr[1]
        if cmd != 1:  # 只支持 CONNECT
            client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            client_sock.close()
            return
        atyp = hdr[3]
        if atyp == 1:      # IPv4
            dst_addr = socket.inet_ntoa(recv_all(client_sock, 4))
        elif atyp == 3:    # domain
            length = recv_all(client_sock, 1)[0]
            dst_addr = recv_all(client_sock, length).decode('ascii')
        elif atyp == 4:    # IPv6
            dst_addr = socket.inet_ntop(socket.AF_INET6, recv_all(client_sock, 16))
        else:
            client_sock.close()
            return
        dst_port = struct.unpack('>H', recv_all(client_sock, 2))[0]
        # 3. 回复客户端“已连接”
        client_sock.sendall(
            b'\x05\x00\x00\x01' +
            socket.inet_aton('0.0.0.0') +
            struct.pack('>H', 0)
        )
        # 4. 开始双向透传
        remote = socket.create_connection((dst_addr, dst_port))
        def forward(src, dst_queue):
            try:
                while True:
                    chunk = src.recv(4096)
                    if not chunk:
                        break
                    dst_queue.put(chunk)
            except:
                pass
            finally:
                dst_queue.put(None)
        p1 = Process(target=forward, args=(client_sock, enc_send_q), daemon=True)
        p2 = Process(target=forward, args=(enc_recv_q, remote), daemon=True)
        p1.start(); p2.start()
        p1.join(); p2.join()
    except Exception as e:
        print("[E] SOCKS5 处理错误:", e)
    finally:
        client_sock.close()


def run_server(listen_host, listen_port):
    """
    服务端主流程：
    1. 监听 TCP，接收客户端连接
    2. 每个连接 fork 两个进程做 send/recv 加密隧道
    3. 处理从客户端经加密隧道来的数据（本示例 echo 回去，实际请改为真正的 SOCKS5 转发逻辑）
    """
    print(f"[*] 服务端监听 {listen_host}:{listen_port}")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(5)
    try:
        while True:
            conn, addr = srv.accept()
            print(f"[*] 新客户端：{addr}")
            # 完成握手后启动加密隧道
            aead = do_handshake(conn, is_client=False)
            print(f"[*] 与 {addr} 握手完成，隧道就绪")
            send_q = Queue()
            recv_q = Queue()
            p_send = Process(
                target=encrypt_and_send,
                args=(conn, aead, send_q),
                daemon=True
            )
            p_recv = Process(
                target=recv_and_decrypt,
                args=(conn, aead, recv_q, "服务端"),
                daemon=True
            )
            p_send.start(); p_recv.start()
            # echo 示例：将 recv_q 里的数据直接送回 send_q
            def echo_loop(rq, sq):
                try:
                    while True:
                        d = rq.get()
                        if d is None:
                            break
                        sq.put(d)
                finally:
                    sq.put(None)
            p_echo = Process(target=echo_loop, args=(recv_q, send_q), daemon=True)
            p_echo.start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        print("[*] 服务端退出")


if __name__ == '__main__':
    print("请选择模式: [1] 客户端  [2] 服务端")
    mode = input("输入 1 或 2 然后回车: ").strip()
    if mode == '1':
        ip = input("请输入服务端 IP: ").strip()
        port = input("请输入服务端端口 (默认 9000): ").strip() or '9000'
        local_port = input("本地 SOCKS5 监听端口 (默认 1080): ").strip() or '1080'
        run_client(ip, int(port), int(local_port))
    elif mode == '2':
        host = input("监听地址 (默认 0.0.0.0): ").strip() or '0.0.0.0'
        port = input("监听端口 (默认 9000): ").strip() or '9000'
        run_server(host, int(port))
    else:
        print("无效输入，退出。")
        sys.exit(1)
