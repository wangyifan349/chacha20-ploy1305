import sys                                                       # 系统模块
import threading                                                 # 线程模块
import time                                                      # 时间模块
import socket                                                    # 套接字模块
import struct                                                    # 处理二进制数据
import json                                                      # JSON数据处理
import os                                                        # 操作系统接口
from cryptography.hazmat.primitives.asymmetric import x25519     # X25519算法
from cryptography.hazmat.primitives.kdf.hkdf import HKDF         # HKDF密钥派生
from cryptography.hazmat.primitives import hashes                # 哈希算法
from Cryptodome.Cipher import ChaCha20_Poly1305                  # ChaCha20-Poly1305加密算法
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel, QHBoxLayout, QMessageBox, QTabWidget, QGridLayout  # PyQt5组件
from PyQt5.QtCore import QThread, pyqtSignal, QObject, Qt        # PyQt5核心组件
from PyQt5.QtGui import QFont                                    # 字体

# ------------------------- 加密和网络辅助函数 -------------------------

def generate_private_key():
    private_key = x25519.X25519PrivateKey.generate()             # 生成私钥
    return private_key                                           # 返回私钥

def get_public_bytes(private_key):
    public_key = private_key.public_key()                        # 获取公钥
    public_bytes = public_key.public_bytes()                     # 获取公钥字节
    return public_bytes                                          # 返回公钥字节

def derive_shared_key(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)  # 对方公钥对象
    shared_secret = private_key.exchange(peer_public_key)        # 计算共享密钥
    hkdf = HKDF(
        algorithm=hashes.SHA256(),                               # 使用SHA256哈希算法
        length=32,                                               # 生成32字节密钥
        salt=None,
        info=b"x25519-chacha20poly1305"                          # 附加信息
    )
    derived_key = hkdf.derive(shared_secret)                     # 派生密钥
    return derived_key                                           # 返回派生的密钥

def encrypt_json(key_bytes, data_dict):
    json_bytes = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')  # JSON序列化为字节
    nonce_bytes = os.urandom(12)                                              # 生成随机nonce
    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)          # 初始化加密器
    ciphertext, tag = cipher.encrypt_and_digest(json_bytes)                   # 加密并生成认证标签
    encrypted_bytes = nonce_bytes + ciphertext + tag                          # 组合加密数据
    return encrypted_bytes                                                    # 返回加密字节

def decrypt_json(key_bytes, encrypted_bytes):
    nonce_bytes = encrypted_bytes[0:12]                                       # 提取nonce
    tag_bytes = encrypted_bytes[-16:]                                         # 提取tag
    ciphertext_bytes = encrypted_bytes[12:-16]                                # 提取密文
    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)          # 初始化解密器
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)  # 解密并验证
    plaintext_str = plaintext_bytes.decode('utf-8')                           # 解码为字符串
    data_dict = json.loads(plaintext_str)                                     # 解析JSON
    return data_dict                                                          # 返回数据字典

def send_bytes_with_length(sock, data_bytes):
    length_bytes = struct.pack('>I', len(data_bytes))                         # 数据长度前缀
    sock.sendall(length_bytes)                                                # 发送长度
    sock.sendall(data_bytes)                                                  # 发送数据

def receive_n_bytes(sock, n):
    data_buffer = b''                                                         # 数据缓冲区
    while len(data_buffer) < n:                                               # 循环接收
        try:
            chunk = sock.recv(n - len(data_buffer))                           # 接收剩余字节
            if not chunk:                                                     # 连接关闭
                return b''                                                    # 返回空字节
            data_buffer += chunk                                              # 添加到缓冲区
        except socket.error:
            return b''                                                        # 异常返回空字节
    return data_buffer                                                        # 返回完整数据

def receive_bytes_with_length(sock):
    length_bytes = receive_n_bytes(sock, 4)                                   # 接收长度
    if not length_bytes:
        return b''                                                            # 返回空字节
    data_length = struct.unpack('>I', length_bytes)[0]                        # 解包长度
    data_bytes = receive_n_bytes(sock, data_length)                           # 接收数据
    return data_bytes                                                         # 返回数据字节

# ------------------------- 通信线程定义 -------------------------

class CommunicationThread(QThread):
    message_received = pyqtSignal(str)                                        # 消息接收信号
    system_message = pyqtSignal(str)                                          # 系统消息信号
    disconnected = pyqtSignal()                                               # 断开连接信号

    def __init__(self, sock, shared_key, is_sender, parent=None):
        super().__init__(parent)
        self.sock = sock                                                      # 套接字
        self.shared_key = shared_key                                          # 共享密钥
        self.is_sender = is_sender                                            # 是否为发送者
        self.stop_event = threading.Event()                                   # 停止事件
        self.message_to_send = None                                           # 待发送消息
        if self.is_sender:
            self.setObjectName("SendThread")                                  # 设置线程名称
        else:
            self.setObjectName("ReceiveThread")

    def run(self):
        if self.is_sender:
            self.send_loop()                                                  # 运行发送循环
        else:
            self.receive_loop()                                               # 运行接收循环

    def send_loop(self):
        while not self.stop_event.is_set():
            if self.message_to_send:
                message_dict = {"msg": self.message_to_send}                  # 构建消息字典
                encrypted_data = encrypt_json(self.shared_key, message_dict)  # 加密消息
                try:
                    send_bytes_with_length(self.sock, encrypted_data)         # 发送加密消息
                    self.message_to_send = None                               # 重置待发送消息
                except Exception as e:
                    self.system_message.emit(f"[SendThread] Exception: {repr(e)}")
                    self.stop_event.set()
                    self.disconnected.emit()
                    break
            else:
                self.msleep(100)                                              # 休眠避免高CPU占用

    def receive_loop(self):
        while not self.stop_event.is_set():
            try:
                encrypted_data = receive_bytes_with_length(self.sock)         # 接收加密数据
                if not encrypted_data:
                    self.system_message.emit("[ReceiveThread] Connection closed by peer.")
                    self.stop_event.set()
                    self.disconnected.emit()
                    break
                message_dict = decrypt_json(self.shared_key, encrypted_data)  # 解密数据
                received_msg = message_dict.get("msg", "<no msg>")            # 获取消息
                self.message_received.emit(received_msg)                      # 发射消息接收信号
            except Exception as e:
                self.system_message.emit(f"[ReceiveThread] Exception: {repr(e)}")
                self.stop_event.set()
                self.disconnected.emit()
                break

    def send_message(self, message):
        self.message_to_send = message                                        # 设置待发送消息

    def stop(self):
        self.stop_event.set()                                                 # 设置停止事件

# ------------------------- 服务器线程定义 -------------------------

class ServerThread(QThread):
    system_message = pyqtSignal(str)                                          # 系统消息信号
    connected = pyqtSignal()                                                  # 连接成功信号

    def __init__(self, local_ip, local_port, chat_window, parent=None):
        super().__init__(parent)
        self.local_ip = local_ip                                              # 本地IP
        self.local_port = local_port                                          # 本地端口
        self.chat_window = chat_window                                        # 聊天窗口引用
        self.stop_event = threading.Event()                                   # 停止事件
        self.setObjectName("ServerThread")                                    # 设置线程名称

    def run(self):
        while not self.stop_event.is_set():
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # 创建套接字
            try:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 端口重用
                server_socket.bind((self.local_ip, self.local_port))          # 绑定地址和端口
                server_socket.listen(1)                                       # 监听
                server_socket.settimeout(1.0)                                 # 设置超时
                self.system_message.emit(f"[Server] Listening on {self.local_ip}:{self.local_port}")

                client_socket = None
                try:
                    client_socket, client_addr = server_socket.accept()       # 接受连接
                    self.system_message.emit(f"[Server] Accepted connection from {client_addr}")
                    self.handle_server_connection(client_socket)
                except socket.timeout:
                    continue                                                  # 超时继续循环
                except Exception as e:
                    self.system_message.emit(f"[Server] Exception: {repr(e)}")
                    time.sleep(1)
                    continue
            except Exception as e:
                self.system_message.emit(f"[Server] Exception: {repr(e)}")
                time.sleep(2)
            finally:
                server_socket.close()                                         # 关闭套接字
                self.system_message.emit("[Server] Server socket closed.")

            if not self.stop_event.is_set():
                self.system_message.emit("[Server] Restarting server...")     # 重启服务器

    def handle_server_connection(self, client_socket):
        try:
            client_socket.settimeout(5)
            server_priv_key = generate_private_key()                          # 生成私钥
            server_pub_bytes = get_public_bytes(server_priv_key)              # 获取公钥字节

            send_bytes_with_length(client_socket, server_pub_bytes)           # 发送公钥
            self.system_message.emit("[Server] Sent public key to client.")

            client_pub_bytes = receive_bytes_with_length(client_socket)       # 接收客户端公钥
            if not client_pub_bytes:
                self.system_message.emit("[Server] Client public key missing, closing connection.")
                return
            self.system_message.emit("[Server] Received public key from client.")

            shared_key = derive_shared_key(server_priv_key, client_pub_bytes) # 派生共享密钥
            self.system_message.emit("[Server] Shared key established, secure channel ready.")

            self.connected.emit()                                             # 发射连接成功信号

            self.chat_window.setup_communication_threads(client_socket, shared_key)  # 设置通信线程

            while not self.stop_event.is_set():
                time.sleep(0.1)                                               # 保持线程活动
                if not self.chat_window.is_connected:
                    break                                                     # 断开连接时退出循环
        except Exception as e:
            self.system_message.emit(f"[Server] Exception: {repr(e)}")
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)                      # 关闭连接
            except:
                pass
            client_socket.close()                                             # 关闭套接字
            self.system_message.emit("[Server] Connection closed.")

    def stop(self):
        self.stop_event.set()                                                 # 设置停止事件

# ------------------------- 客户端线程定义 -------------------------

class ClientThread(QThread):
    system_message = pyqtSignal(str)                                          # 系统消息信号
    connected = pyqtSignal()                                                  # 连接成功信号

    def __init__(self, server_ip, server_port, chat_window, parent=None):
        super().__init__(parent)
        self.server_ip = server_ip                                            # 服务器IP
        self.server_port = server_port                                        # 服务器端口
        self.chat_window = chat_window                                        # 聊天窗口引用
        self.stop_event = threading.Event()                                   # 停止事件
        self.setObjectName("ClientThread")

    def run(self):
        while not self.stop_event.is_set():
            client_priv_key = generate_private_key()                          # 生成私钥
            client_pub_bytes = get_public_bytes(client_priv_key)              # 获取公钥字节
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      # 创建套接字
                self.system_message.emit(f"[Client] Connecting to {self.server_ip}:{self.server_port}")
                sock.settimeout(5)
                sock.connect((self.server_ip, self.server_port))              # 连接服务器
                sock.settimeout(None)

                server_pub_bytes = receive_bytes_with_length(sock)            # 接收服务器公钥
                if not server_pub_bytes:
                    self.system_message.emit("[Client] Server public key not received.")
                    sock.close()
                    time.sleep(2)
                    continue
                self.system_message.emit("[Client] Received public key from server.")

                send_bytes_with_length(sock, client_pub_bytes)                # 发送客户端公钥
                self.system_message.emit("[Client] Sent public key to server.")

                shared_key = derive_shared_key(client_priv_key, server_pub_bytes)  # 派生共享密钥
                self.system_message.emit("[Client] Shared key established, secure channel ready.")
                self.connected.emit()                                         # 发射连接成功信号

                self.chat_window.setup_communication_threads(sock, shared_key)  # 设置通信线程

                while not self.stop_event.is_set():
                    time.sleep(0.1)
                    if not self.chat_window.is_connected:
                        break
            except Exception as e:
                self.system_message.emit(f"[Client] Exception: {repr(e)}")
                if sock:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)                       # 关闭套接字
                    except:
                        pass
                    sock.close()
                time.sleep(2)                                                 # 等待后重试
            if not self.stop_event.is_set():
                self.system_message.emit("[Client] Reconnecting...")          # 重新连接提示

    def stop(self):
        self.stop_event.set()                                                 # 设置停止事件

# ------------------------- 界面定义 -------------------------

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure TCP Chat")                                # 窗口标题
        self.resize(600, 500)                                                 # 窗口尺寸
        self.stop_event = threading.Event()                                   # 停止事件
        self.is_connected = False                                             # 连接状态
        self.init_ui()                                                        # 初始化界面

    def init_ui(self):
        self.main_layout = QVBoxLayout()                                      # 主布局
        self.setLayout(self.main_layout)

        self.tabs = QTabWidget()                                              # 选项卡
        self.main_layout.addWidget(self.tabs)

        self.settings_tab = QWidget()                                         # 设置选项卡
        self.tabs.addTab(self.settings_tab, "Settings")
        self.init_settings_tab()

        self.chat_tab = QWidget()                                             # 聊天选项卡
        self.tabs.addTab(self.chat_tab, "Chat")
        self.init_chat_tab()
        self.tabs.setTabEnabled(1, False)                                     # 禁用聊天选项卡

    def init_settings_tab(self):
        layout = QGridLayout()                                                # 网格布局
        self.settings_tab.setLayout(layout)

        self.mode_label = QLabel("Select Mode:")                              # 模式选择标签
        self.mode_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.mode_label, 0, 0)

        self.mode_buttons = QHBoxLayout()                                     # 模式按钮布局
        layout.addLayout(self.mode_buttons, 0, 1)

        self.server_button = QPushButton("Server")                            # 服务器模式按钮
        self.client_button = QPushButton("Client")                            # 客户端模式按钮
        self.mode_buttons.addWidget(self.server_button)
        self.mode_buttons.addWidget(self.client_button)

        self.server_button.clicked.connect(self.select_server_mode)           # 按钮点击事件
        self.client_button.clicked.connect(self.select_client_mode)

        self.ip_label = QLabel("IP Address:")                                 # IP地址标签
        self.ip_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.ip_label, 1, 0)
        self.ip_input = QLineEdit("0.0.0.0")                                  # IP输入框
        layout.addWidget(self.ip_input, 1, 1)

        self.port_label = QLabel("Port:")                                     # 端口标签
        self.port_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.port_label, 2, 0)
        self.port_input = QLineEdit("12345")                                  # 端口输入框
        layout.addWidget(self.port_input, 2, 1)

        self.start_button = QPushButton("Start")                              # 开始按钮
        layout.addWidget(self.start_button, 3, 0, 1, 2)
        self.start_button.clicked.connect(self.start_chat)

    def init_chat_tab(self):
        layout = QVBoxLayout()                                                # 聊天布局
        self.chat_tab.setLayout(layout)

        self.info_label = QLabel("Secure TCP Chat Program")                   # 信息标签
        self.info_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(self.info_label)

        self.chat_area = QTextEdit()                                          # 聊天区域
        self.chat_area.setReadOnly(True)
        self.chat_area.setFont(QFont("Arial", 12))
        layout.addWidget(self.chat_area)

        input_layout = QHBoxLayout()                                          # 输入布局
        self.input_line = QLineEdit()
        self.input_line.setFont(QFont("Arial", 12))
        self.input_line.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.input_line)

        self.send_button = QPushButton("Send")                                # 发送按钮
        self.send_button.setFont(QFont("Arial", 12))
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)

        layout.addLayout(input_layout)

    def select_server_mode(self):
        self.mode = 'server'                                                  # 模式设为服务器
        self.ip_input.setText("0.0.0.0")                                      # 默认IP
        self.ip_input.setEnabled(False)                                       # 禁用IP输入
        self.port_input.setEnabled(True)
        self.server_button.setEnabled(False)                                  # 禁用服务器按钮
        self.client_button.setEnabled(True)                                   # 启用客户端按钮

    def select_client_mode(self):
        self.mode = 'client'                                                  # 模式设为客户端
        self.ip_input.setText("")                                             # 清空IP
        self.ip_input.setEnabled(True)                                        # 启用IP输入
        self.port_input.setEnabled(True)
        self.server_button.setEnabled(True)
        self.client_button.setEnabled(False)                                  # 禁用客户端按钮

    def start_chat(self):
        ip = self.ip_input.text().strip()                                     # 获取IP
        port = self.port_input.text().strip()                                 # 获取端口
        if not port.isdigit():
            QMessageBox.warning(self, "Warning", "Please enter a valid port number.")
            return
        port = int(port)
        if self.mode == 'server':
            self.server_thread = ServerThread(ip, port, self)                 # 创建服务器线程
            self.server_thread.system_message.connect(self.append_system_message)
            self.server_thread.connected.connect(self.enable_chat_tab)
            self.server_thread.start()                                        # 启动线程
            self.append_system_message("[Server] Starting server...")
        elif self.mode == 'client':
            self.client_thread = ClientThread(ip, port, self)                 # 创建客户端线程
            self.client_thread.system_message.connect(self.append_system_message)
            self.client_thread.connected.connect(self.enable_chat_tab)
            self.client_thread.start()
            self.append_system_message("[Client] Starting client...")
        else:
            QMessageBox.warning(self, "Warning", "Please select a mode.")
            return

    def enable_chat_tab(self):
        self.tabs.setTabEnabled(1, True)                                      # 启用聊天选项卡
        self.tabs.setCurrentIndex(1)                                          # 切换到聊天选项卡
        self.is_connected = True                                              # 设置连接状态

    def append_system_message(self, message):
        self.chat_area.append(f"<b>{message}</b>")                            # 添加系统消息

    def append_peer_message(self, message):
        self.chat_area.append(f"<font color='blue'>Peer: {message}</font>")   # 添加对方消息

    def send_message(self):
        message = self.input_line.text().strip()                              # 获取输入消息
        if message:
            self.chat_area.append(f"You: {message}")                          # 显示自己消息
            self.input_line.clear()
            if hasattr(self, 'send_thread'):
                self.send_thread.send_message(message)                        # 发送消息

    def setup_communication_threads(self, sock, shared_key):
        # 创建发送线程
        self.send_thread = CommunicationThread(sock, shared_key, is_sender=True)
        self.send_thread.system_message.connect(self.append_system_message)
        self.send_thread.disconnected.connect(self.handle_disconnection)
        self.send_thread.start()

        # 创建接收线程
        self.receive_thread = CommunicationThread(sock, shared_key, is_sender=False)
        self.receive_thread.message_received.connect(self.append_peer_message)
        self.receive_thread.system_message.connect(self.append_system_message)
        self.receive_thread.disconnected.connect(self.handle_disconnection)
        self.receive_thread.start()

    def handle_disconnection(self):
        if self.is_connected:
            QMessageBox.information(self, "Disconnected", "Connection was closed.")
            self.tabs.setTabEnabled(1, False)                                 # 禁用聊天选项卡
            self.tabs.setCurrentIndex(0)                                      # 返回设置选项卡
            self.append_system_message("[Info] Disconnected from peer.")
            self.is_connected = False                                         # 重置连接状态
            # 根据模式重启服务器或客户端线程
            if self.mode == 'server' and hasattr(self, 'server_thread'):
                self.server_thread.stop()                                     # 停止旧线程
                self.server_thread = ServerThread(self.ip_input.text(), int(self.port_input.text()), self)
                self.server_thread.system_message.connect(self.append_system_message)
                self.server_thread.connected.connect(self.enable_chat_tab)
                self.server_thread.start()                                    # 重启服务器线程
            elif self.mode == 'client' and hasattr(self, 'client_thread'):
                self.client_thread.stop()                                     # 停止旧线程
                self.client_thread = ClientThread(self.ip_input.text(), int(self.port_input.text()), self)
                self.client_thread.system_message.connect(self.append_system_message)
                self.client_thread.connected.connect(self.enable_chat_tab)
                self.client_thread.start()                                    # 重启客户端线程

# ------------------------- 主函数 -------------------------

def main():
    app = QApplication(sys.argv)                                              # 创建应用程序
    chat_window = ChatWindow()                                                # 实例化聊天窗口
    chat_window.show()                                                        # 显示窗口
    sys.exit(app.exec_())                                                     # 进入主循环

if __name__ == '__main__':
    main()
