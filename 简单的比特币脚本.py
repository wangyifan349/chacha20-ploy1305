import secrets  # 安全随机数生成
import hashlib   # SHA256 / RIPEMD160
from ecdsa import SECP256k1, SigningKey  # 椭圆曲线操作
from bech32 import bech32_encode, convertbits  # Bech32 地址编码
import base58  # WIF 编码/解码

# ---------------------------
# 私钥生成
# ---------------------------
def generate_private_key():
    n = SECP256k1.order  # secp256k1 曲线阶
    while True:
        d = secrets.randbits(256)  # 生成256位随机数
        if 1 <= d < n:  # 确保私钥在有效范围 [1, n-1]
            return d  # 返回整数形式的私钥

# ---------------------------
# 私钥导入 (HEX, DEC, WIF)
# ---------------------------
def import_private_key(key_str):
    key_str = key_str.strip()  # 去掉空格
    # HEX格式
    if all(c in "0123456789abcdefABCDEF" for c in key_str) and len(key_str) in [64, 66]:
        return int(key_str[:64], 16), True  # 返回整数形式私钥, 默认压缩公钥
    # DEC格式
    if key_str.isdigit():
        return int(key_str), True
    # WIF格式
    try:
        wif_bytes = base58.b58decode_check(key_str)  # Base58Check 解码
        if wif_bytes[0] != 0x80:  # 主网 WIF 前缀必须为0x80
            raise ValueError("非主网 WIF")
        # 检查是否压缩
        if len(wif_bytes) == 34 and wif_bytes[-1] == 0x01:  
            compressed = True
            key_int = int.from_bytes(wif_bytes[1:-1], 'big')  # 去掉前缀和压缩标记
        else:
            compressed = False
            key_int = int.from_bytes(wif_bytes[1:], 'big')  # 去掉前缀
        return key_int, compressed  # 返回私钥整数 + 压缩标记
    except Exception:
        raise ValueError("无法解析为私钥")  # 非法输入抛异常

# ---------------------------
# 公钥生成
# ---------------------------
def private_to_pubkey(d, compressed=True):
    sk = SigningKey.from_string(d.to_bytes(32, 'big'), curve=SECP256k1)  # 私钥 -> SigningKey
    vk = sk.verifying_key  # 获取对应公钥
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    if compressed:  # 压缩公钥
        prefix = b'\x02' if y % 2 == 0 else b'\x03'  # 奇偶决定前缀
        return prefix + x.to_bytes(32, 'big')
    else:  # 非压缩公钥
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

# ---------------------------
# HASH160 (SHA256 + RIPEMD160)
# ---------------------------
def hash160(data):
    sha = hashlib.sha256(data).digest()  # SHA256
    rip = hashlib.new('ripemd160', sha).digest()  # RIPEMD160
    return rip

# ---------------------------
# BIP84地址生成 (主网)
# ---------------------------
def pubkey_to_bip84_address(pubkey_bytes):
    hrp = 'bc'  # 主网 Bech32 前缀
    h160 = hash160(pubkey_bytes)  # 公钥 -> HASH160
    data = [0] + convertbits(h160, 8, 5)  # witness version=0 + convert 8bit->5bit
    return bech32_encode(hrp, data)  # Bech32 编码生成地址

# ---------------------------
# 交互式菜单
# ---------------------------
def menu():
    priv_key = None  # 保存私钥
    compressed = True  # 默认生成压缩公钥

    while True:
        print("\n=== Bitcoin Key & Address Menu (主网) ===")
        print("1. 生成新私钥")  
        print("2. 导入私钥 (HEX/DEC/WIF)")
        print("3. 显示私钥、公钥和BIP84地址")
        print("0. 退出")
        choice = input("请选择操作: ").strip()

        if choice == '1':
            priv_key = generate_private_key()  # 调用生成私钥
            compressed = True
            print("✅ 新私钥生成成功。")
        elif choice == '2':
            try:
                key_input = input("输入私钥 (HEX/DEC/WIF): ").strip()
                priv_key, compressed = import_private_key(key_input)  # 导入私钥
                print("✅ 私钥导入成功。压缩公钥:", compressed)
            except Exception as e:
                print("❌ 导入失败:", e)
        elif choice == '3':
            if priv_key is None:
                print("❌ 请先生成或导入私钥")
                continue
            pub = private_to_pubkey(priv_key, compressed=compressed)  # 生成公钥
            addr = pubkey_to_bip84_address(pub)  # 生成 BIP84 地址
            print("私钥(hex):", hex(priv_key))
            print("压缩公钥:" if compressed else "非压缩公钥:", pub.hex())
            print("BIP84地址:", addr)
        elif choice == '0':
            print("退出。")
            break
        else:
            print("无效选项，请重试。")

# ---------------------------
# 启动菜单
# ---------------------------
if __name__ == "__main__":
    menu()  # 启动交互式菜单
