# PyNaCl 完整示例与讲解

本教程面向初学者，全面展示纯 PyNaCl（Python 绑定的 libsodium）中常见的加密原语和用法。每个示例都附带详细的 `print` 信息，便于理解流程。

---

## 目录

1. 环境准备  
2. 对称加密：SecretBox (XSalsa20-Poly1305)  
3. AEAD：XChaCha20-Poly1305  
4. 非对称加密：Box (Curve25519 + XSalsa20-Poly1305)  
5. 匿名加密：SealedBox  
6. 数字签名：Ed25519 (SigningKey / VerifyKey)  
7. 哈希计算：BLAKE2b / SHA-256  
8. 密码派生：Argon2id  
9. 随机数与编码：Hex / Base64  
10. 错误处理示例  
11. 完整脚本  

---

## 1. 环境准备

安装 PyNaCl：  
```bash
pip install pynacl
```

若因缺少 libsodium 而安装失败，可先安装系统依赖：  
- Debian/Ubuntu: `sudo apt-get install libsodium-dev`  
- macOS (Homebrew): `brew install libsodium`

验证安装：  
```python
import nacl
print("PyNaCl 版本：", nacl.__version__)
```

---

## 2. 对称加密：SecretBox

SecretBox 基于 XSalsa20-Poly1305 提供认证加密。

```python
from nacl import secret, utils
from nacl.exceptions import CryptoError

def demo_secretbox():
    print("\n=== SecretBox 对称加密 ===")
    # 1. 生成 32 字节密钥
    key = utils.random(secret.SecretBox.KEY_SIZE)
    print("密钥 (hex):", key.hex())
    box = secret.SecretBox(key)

    # 2. 准备明文与 nonce
    plaintext = b"Hello SecretBox!"
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    print("明文:", plaintext)
    print("nonce (hex):", nonce.hex())

    # 3. 加密
    cipher = box.encrypt(plaintext, nonce)
    print("密文 (hex):", cipher.hex())

    # 4. 解密
    try:
        result = box.decrypt(cipher)
        print("解密成功，明文:", result)
    except CryptoError:
        print("解密失败，MAC 校验不通过或被篡改")
```

- `KEY_SIZE = 32`，`NONCE_SIZE = 24`  
- `encrypt` 若不传 `nonce`，则自动生成并附加在输出前  

---

## 3. AEAD：XChaCha20-Poly1305

使用更长 nonce 的 AEAD 接口 `crypto_aead_xchacha20poly1305_ietf`。

```python
from nacl import utils, bindings
from nacl.exceptions import CryptoError

def demo_aead_xchacha20():
    print("\n=== AEAD: XChaCha20-Poly1305 ===")
    key   = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    nonce = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    aad   = b"header-auth"
    msg   = b"Secret AEAD message"

    print("Key (hex):", key.hex())
    print("Nonce (hex):", nonce.hex())
    print("AAD:", aad)
    print("Plaintext:", msg)

    # 加密
    ct = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        msg, aad, nonce, key
    )
    print("Ciphertext (hex):", ct.hex())

    # 解密
    try:
        pt = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct, aad, nonce, key
        )
        print("解密成功，Plaintext:", pt)
    except CryptoError:
        print("解密失败，数据篡改或 AAD 不匹配")
```

- KEY 长度 32，nonce 长度 24  
- `aad` 为额外认证数据，不加密但参与 MAC  

---

## 4. 非对称加密：Box

Box 基于 Curve25519 + XSalsa20-Poly1305，要求双方各自有公私钥对。

```python
from nacl import public, utils, encoding

def demo_box():
    print("\n=== Box: 非对称加密 ===")
    # 1. 生成 Alice 和 Bob 的密钥对
    alice_sk = public.PrivateKey.generate()
    alice_pk = alice_sk.public_key
    bob_sk   = public.PrivateKey.generate()
    bob_pk   = bob_sk.public_key

    print("Alice 公钥 (hex):", alice_pk.encode(encoder=encoding.HexEncoder).decode())
    print("Bob   公钥 (hex):", bob_pk.encode(encoder=encoding.HexEncoder).decode())

    # 2. Alice 加密给 Bob
    box_ab = public.Box(alice_sk, bob_pk)
    message = b"Hello Bob, 我是 Alice"
    cipher_ab = box_ab.encrypt(message)
    print("Alice→Bob 密文 (hex):", cipher_ab.hex())

    # 3. Bob 解密
    box_ba = public.Box(bob_sk, alice_pk)
    decrypted = box_ba.decrypt(cipher_ab)
    print("Bob 解密:", decrypted)
```

- `encrypt` 自动生成并附加 nonce  
- 双方各用自己的私钥和对方的公钥构造 `Box`  

---

## 5. 匿名加密：SealedBox

SealedBox 允许“发信人”不持有密钥，仅用接收者公钥加密。

```python
from nacl.public import SealedBox, PrivateKey, encoding

def demo_sealedbox():
    print("\n=== SealedBox: 匿名加密 ===")
    # 接收者生成密钥对
    sk = PrivateKey.generate()
    pk = sk.public_key
    print("Receiver 公钥 (hex):", pk.encode(encoder=encoding.HexEncoder).decode())

    # 发信人用公钥加密
    sealed = SealedBox(pk)
    msg = b"Anonymous secret"
    cipher = sealed.encrypt(msg)
    print("SealedBox 密文 (hex):", cipher.hex())

    # 接收者解密
    unseal = SealedBox(sk)
    plain = unseal.decrypt(cipher)
    print("解密:", plain)
```

---

## 6. 数字签名：Ed25519

使用 Ed25519 算法进行签名和验签。

```python
from nacl import signing, encoding
from nacl.exceptions import BadSignatureError

def demo_sign_verify():
    print("\n=== Ed25519 签名／验签 ===")
    # 1. 生成签名 KeyPair
    sk = signing.SigningKey.generate()
    vk = sk.verify_key
    print("SigningKey (hex):", sk.encode(encoder=encoding.HexEncoder).decode())
    print("VerifyKey  (hex):", vk.encode(encoder=encoding.HexEncoder).decode())

    # 2. 签名
    msg = b"Message for signing"
    signed = sk.sign(msg)
    print("签名后 (sig+msg, hex):", signed.hex())

    # 3. 验签
    try:
        orig = vk.verify(signed)
        print("验签通过，原文:", orig)
    except BadSignatureError:
        print("验签失败")
```

---

## 7. 哈希计算

```python
from nacl import hash

def demo_hash():
    print("\n=== 哈希计算 ===")
    data = b"hello hash"
    print("原始数据:", data)

    h1 = hash.blake2b(data, digest_size=32)
    print("BLAKE2b-256 (hex):", h1.hex())

    h2 = hash.sha256(data)
    print("SHA-256       (hex):", h2.hex())
```

---

## 8. 密码派生：Argon2id

```python
from nacl import pwhash, utils

def demo_pwhash():
    print("\n=== Argon2id 密码派生 ===")
    password = b"myS3cr3tPwd"
    salt = utils.random(pwhash.argon2id.SALT_SIZE)
    print("Password:", password)
    print("Salt (hex):", salt.hex())

    key = pwhash.argon2id.kdf(
        size=32,
        password=password,
        salt=salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE
    )
    print("Derived key (hex):", key.hex())
```

---

## 9. 随机数与编码：Hex / Base64

```python
from nacl import utils, encoding

def demo_encoding():
    print("\n=== 随机数与编码 ===")
    raw = utils.random(16)
    print("Raw bytes (hex):", raw.hex())

    hex_s = encoding.HexEncoder.encode(raw).decode()
    b64_s = encoding.Base64Encoder.encode(raw).decode()
    print("Hex 编码    :", hex_s)
    print("Base64 编码 :", b64_s)

    # 解码回原始
    back = encoding.Base64Encoder.decode(b64_s)
    print("解码回 Raw (hex):", back.hex())
```

---

## 10. 错误处理示例

```python
from nacl import secret, utils, signing
from nacl.exceptions import CryptoError, BadSignatureError

def demo_error_handling():
    print("\n=== 错误处理示例 ===")
    # SecretBox 解密错误
    try:
        box = secret.SecretBox(utils.random(32))
        box.decrypt(b"bad data")
    except CryptoError:
        print("捕获 CryptoError: 解密失败或 MAC 校验不通过")

    # Ed25519 验签错误
    try:
        sk = signing.SigningKey.generate()
        vk = sk.verify_key
        vk.verify(b"not a valid signature")
    except BadSignatureError:
        print("捕获 BadSignatureError: 签名无效")
```

---

## 11. 完整脚本

将上面各示例函数汇总到 `pynacl_demo.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from nacl import secret, utils, hash, pwhash, bindings, encoding, signing, public
from nacl.public import SealedBox, PrivateKey
from nacl.exceptions import CryptoError, BadSignatureError

def demo_secretbox():    ...  # 参见上文
def demo_aead_xchacha20(): ...
def demo_box():          ...
def demo_sealedbox():    ...
def demo_sign_verify():  ...
def demo_hash():         ...
def demo_pwhash():       ...
def demo_encoding():     ...
def demo_error_handling(): ...

if __name__ == "__main__":
    demo_secretbox()
    demo_aead_xchacha20()
    demo_box()
    demo_sealedbox()
    demo_sign_verify()
    demo_hash()
    demo_pwhash()
    demo_encoding()
    demo_error_handling()
```

运行后即可在控制台查看每个示例的详细输出，帮助你快速掌握 PyNaCl 的各类常用功能。祝学习愉快！
