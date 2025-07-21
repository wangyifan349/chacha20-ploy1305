# PyNaCl 完整教程

> 目的：面向初学者与教学使用，系统性地介绍 PyNaCl（Python bindings for Libsodium）最常见的功能和用法。  
> 涵盖：对称加密、非对称加密、数字签名、哈希、密码派生、随机数生成、编码（Hex/Base64）以及常见错误处理等。  

---

## 目录

1. 环境准备  
2. 快速入门：Hello, PyNaCl  
3. 对称加密 / 解密（SecretBox）  
4. 非对称加密 / 解密（Box）  
5. 数字签名 / 验签（SigningKey & VerifyKey）  
6. 哈希计算（BLAKE2b, SHA-256）  
7. 密码派生（Argon2id KDF）  
8. 随机数与可读字符串  
9. 编码与解码（Hex, Base64）  
10. 错误处理与调试  
11. 完整示例脚本  
12. 常见 Q&A  
13. 参考链接  

---

## 1. 环境准备

1. 安装 PyNaCl  
   ```bash
   pip install pynacl
   ```

2. 如果在 Linux/macOS 上遇到依赖问题，请先安装 libsodium：  
   - Ubuntu/Debian: `sudo apt-get install libsodium-dev`  
   - macOS (Homebrew): `brew install libsodium`  

3. 验证安装  
   ```python
   >>> import nacl
   >>> print(nacl.__version__)
   ```

---

## 2. 快速入门：Hello, PyNaCl

这段代码演示如何生成随机数并打印：

```python
from nacl import utils

# 生成 16 字节随机数
rand_bytes = utils.random(16)
print("随机字节（hex）：", rand_bytes.hex())
```

运行后应看到 16 字节的随机值。

---

## 3. 对称加密 / 解密（SecretBox）

SecretBox 基于 XSalsa20-Poly1305，提供认证加密。

```python
from nacl import secret, utils

# 1. 生成 32 字节对称密钥
key = utils.random(secret.SecretBox.KEY_SIZE)
box = secret.SecretBox(key)

# 2. 准备明文与随机 nonce（24 字节）
plaintext = b"PyNaCl 对称加密示例"
nonce = utils.random(secret.SecretBox.NONCE_SIZE)

# 3. 加密：返回 nonce || 密文 || MAC
ciphertext = box.encrypt(plaintext, nonce)

# 4. 解密：自动验证 MAC
decrypted = box.decrypt(ciphertext)

assert decrypted == plaintext
print("解密成功:", decrypted.decode())
```

- KEY_SIZE = 32，NONCE_SIZE = 24  
- ciphertext 自带 nonce 信息，也可以手动管理 nonce  

---

## 4. 非对称加密 / 解密（Box）

Box 基于 Curve25519 + XSalsa20-Poly1305，要求双方都有公私钥对。

```python
from nacl import public, utils

# 1. 生成发信者与接收者密钥对
sender_sk = public.PrivateKey.generate()
sender_pk = sender_sk.public_key

receiver_sk = public.PrivateKey.generate()
receiver_pk = receiver_sk.public_key

# 2. 发信者加密
box_enc = public.Box(sender_sk, receiver_pk)
cipher = box_enc.encrypt(b"秘密消息")

# 3. 接收者解密
box_dec = public.Box(receiver_sk, sender_pk)
message = box_dec.decrypt(cipher)

print("非对称解密后:", message.decode())
```

- `Box.encrypt` 自动生成并附加 nonce  
- 同一对密钥可多次通信，但每次 encrypt 应使用不同的 nonce  

---

## 5. 数字签名 / 验签（SigningKey & VerifyKey）

SigningKey/VerifyKey 基于 Ed25519，签名后可防篡改且不可伪造。

```python
from nacl import signing

# 1. 生成签名密钥对
signing_key = signing.SigningKey.generate()
verify_key = signing_key.verify_key

# 2. 原始消息
message = b"PyNaCl 数字签名示例"

# 3. 签名：返回 签名 || 原文
signed = signing_key.sign(message)

# 4. 验签
verified = verify_key.verify(signed)  # 验证 MAC 并返回原文

assert verified == message
print("签名验证成功:", verified.decode())
```

- `sign` 方法将签名和消息拼接在一起  
- `verify` 方法自动分离并验证签名  

---

## 6. 哈希计算（BLAKE2b, SHA-256）

```python
from nacl import hash

data = b"hello hashing"

# BLAKE2b，digest_size 最多 64
h1 = hash.blake2b(data, digest_size=32)
print("BLAKE2b-32:", h1.hex())

# SHA-256
h2 = hash.sha256(data)
print("SHA-256 :", h2.hex())
```

- BLAKE2b：更快、更安全，可自定义输出长度  
- 还支持 `hash.sha512`、`hash.blake2s` 等  

---

## 7. 密码派生（Argon2id KDF）

Argon2id 是现代安全推荐的密码哈希算法。

```python
from nacl import pwhash, utils

password = b"my secret password"
salt = utils.random(pwhash.argon2id.SALT_SIZE)

# 派生 32 字节密钥
key = pwhash.argon2id.kdf(
    size=32,
    password=password,
    salt=salt,
    opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
    memlimit=pwhash.argon2id.MEMLIMIT_MODERATE
)

print("派生密钥 (hex)：", key.hex())
```

- `opslimit` 与 `memlimit` 控制时间与内存成本  
- 用于生成对称加密密钥或存储口令散列  

---

## 8. 随机数与可读字符串

```python
from nacl import utils, encoding

# 生成 24 字节
raw = utils.random(24)

# Hex 编码
hex_str = encoding.HexEncoder.encode(raw).decode()
# Base64 编码
b64_str = encoding.Base64Encoder.encode(raw).decode()

print("Hex     :", hex_str)
print("Base64  :", b64_str)
```

- Raw bytes 常用于密钥/nonce  
- 通过 Hex/Base64 转为可存储的字符串  

---

## 9. 编码与解码（Hex, Base64）

```python
from nacl import encoding

hex_str = "4a6f686e"  # "John"
data = encoding.HexEncoder.decode(hex_str)
print(data.decode())  # John

b64 = "Sm9obg=="
print(encoding.Base64Encoder.decode(b64).decode())
```

---

## 10. 错误处理与调试

- 对称/非对称解密异常  
  ```python
  from nacl.exceptions import CryptoError

  try:
      plaintext = box.decrypt(bad_cipher)
  except CryptoError:
      print("解密失败：数据被篡改或密钥/nonce 不匹配")
  ```

- 签名验证失败  
  ```python
  try:
      verify_key.verify(bad_signed)
  except CryptoError:
      print("验签失败：签名不合法或消息被篡改")
  ```

---

## 11. 完整示例脚本

请参见 `example_pynacl_full.py`（已附在本目录），包含以上所有演示，每个函数都有详细注释，直接运行即可。

---

## 12. 常见 Q&A

Q1: 为何对称加密要分开 key 和 nonce？  
A1: nonce 保证每次加密的唯一性，防止重放和密码复用。

Q2: 如何安全地管理密钥？  
A2: 将密钥存储在安全的密钥管理系统（KMS）或使用硬件安全模块（HSM），切勿将原文或密钥硬编码在源代码中。

Q3: Argon2id 参数如何选择？  
A3: 根据业务场景与硬件环境平衡安全和性能，可参考 libsodium 官方文档推荐的 `OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE`。

---

## 13. 参考链接

- PyNaCl 官方文档：https://pynacl.readthedocs.io  
- libsodium 官方文档：https://libsodium.gitbook.io  
- Ed25519 & Curve25519 简介：https://cr.yp.to/  

---

> 通过本教程，你应当熟悉 PyNaCl 的主流加密原语及其在实际工程中的基本用法。在教学或项目中，可据此扩展更多高级特性（如 sealed box、密钥封装、高级流式接口等）。祝学习愉快！
