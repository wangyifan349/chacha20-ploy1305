import os
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from coincurve import PrivateKey, PublicKey

"""
本示例展示两种常见椭圆曲线算法的密钥交换（ECDH）过程：
- X25519：现代Curve25519曲线，常用且安全
- secp256k1：比特币等区块链常用椭圆曲线

双方通过交换公钥，利用私钥计算共享密钥。然后使用共享密钥作为对称加密钥匙，
利用AES-GCM对消息进行加密和解密。

演示流程：
1. 生成双方密钥对（私钥 + 公钥）
2. 双方交换公钥
3. 利用私钥和对方公钥计算共享密钥
4. 通过共享密钥加密并解密消息
5. 结果使用JSON格式用于输入输出演示
"""

# -------------------- X25519相关函数 --------------------

def x25519_keygen():
    """生成X25519密钥对"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def x25519_shared_key(private_key, peer_public_key_bytes):
    """计算共享密钥"""
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

def aesgcm_encrypt(key, plaintext, associated_data=b""):
    """AES-GCM加密，返回 nonce + 密文"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 12字节随机数作为nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext

def aesgcm_decrypt(key, data, associated_data=b""):
    """AES-GCM解密data (nonce + ciphertext)"""
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext

def x25519_handshake(input_json):
    """
    输入：
    {
        "alice": {
            "private_key": null 或 hex私钥,
            "public_key": null 或 hex公钥（可为空，自动生成）
        },
        "bob": {
            "private_key": null 或 hex私钥,
            "public_key": null 或 hex公钥
        },
        "message": 需要加密的消息字符串
    }

    输出JSON格式：
    {
      "alice_public_key": hex,
      "bob_public_key": hex,
      "shared_key": hex,
      "encrypted_message": base64,
      "decrypted_message": string
    }
    """
    import base64

    msg_bytes = input_json.get("message", "hello x25519").encode()

    # 如果有输入私钥则加载，没有则生成
    if input_json["alice"].get("private_key"):
        alice_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(input_json["alice"]["private_key"]))
    else:
        alice_priv = x25519.X25519PrivateKey.generate()
    alice_pub = alice_priv.public_key()

    if input_json["bob"].get("private_key"):
        bob_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(input_json["bob"]["private_key"]))
    else:
        bob_priv = x25519.X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key()

    # 计算共享密钥
    alice_shared = alice_priv.exchange(bob_pub)
    bob_shared = bob_priv.exchange(alice_pub)
    assert alice_shared == bob_shared

    # 共享密钥用作AES256密钥（截取32字节）
    aes_key = alice_shared[:32]

    encrypted = aesgcm_encrypt(aes_key, msg_bytes)
    decrypted = aesgcm_decrypt(aes_key, encrypted)

    return json.dumps({
        "alice_public_key": alice_pub.public_bytes().hex(),
        "bob_public_key": bob_pub.public_bytes().hex(),
        "shared_key": alice_shared.hex(),
        "encrypted_message": base64.b64encode(encrypted).decode(),
        "decrypted_message": decrypted.decode()
    }, indent=2)

# -------------------- secp256k1相关函数 --------------------

def secp256k1_keygen():
    """生成secp256k1密钥对"""
    priv = PrivateKey()
    pub = priv.public_key
    return priv, pub

def secp256k1_shared_key(priv: PrivateKey, peer_pub_bytes: bytes) -> bytes:
    """ECDH计算共享密钥"""
    pub = PublicKey(peer_pub_bytes)
    shared = priv.ecdh(pub)
    return shared

def secp256k1_handshake(input_json):
    """
    输入格式同x25519_handshake：
    message为字符串，alice和bob可选私钥hex

    输出：
    {
      "alice_public_key": hex,
      "bob_public_key": hex,
      "shared_key": hex,
      "encrypted_message": base64,
      "decrypted_message": string
    }
    """
    import base64

    msg_bytes = input_json.get("message", "hello secp256k1").encode()

    if input_json["alice"].get("private_key"):
        alice_priv = PrivateKey(bytes.fromhex(input_json["alice"]["private_key"]))
    else:
        alice_priv = PrivateKey()
    alice_pub = alice_priv.public_key

    if input_json["bob"].get("private_key"):
        bob_priv = PrivateKey(bytes.fromhex(input_json["bob"]["private_key"]))
    else:
        bob_priv = PrivateKey()
    bob_pub = bob_priv.public_key

    alice_shared = secp256k1_shared_key(alice_priv, bob_pub.format())
    bob_shared = secp256k1_shared_key(bob_priv, alice_pub.format())
    assert alice_shared == bob_shared

    aes_key = alice_shared[:32]

    encrypted = aesgcm_encrypt(aes_key, msg_bytes)
    decrypted = aesgcm_decrypt(aes_key, encrypted)

    return json.dumps({
        "alice_public_key": alice_pub.format().hex(),
        "bob_public_key": bob_pub.format().hex(),
        "shared_key": alice_shared.hex(),
        "encrypted_message": base64.b64encode(encrypted).decode(),
        "decrypted_message": decrypted.decode()
    }, indent=2)

# -------------------- 主流程示范 --------------------

if __name__ == "__main__":
    print("==== X25519 握手示范 ====")
    input_data = {
        "alice": {"private_key": None, "public_key": None},
        "bob": {"private_key": None, "public_key": None},
        "message": "Hello, this is a secret from x25519!"
    }
    print(x25519_handshake(input_data))

    print("\n==== secp256k1 握手示范 ====")
    input_data = {
        "alice": {"private_key": None, "public_key": None},
        "bob": {"private_key": None, "public_key": None},
        "message": "Hello, this is a secret from secp256k1!"
    }
    print(secp256k1_handshake(input_data))
