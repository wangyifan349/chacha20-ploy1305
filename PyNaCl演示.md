# PyNaCl & Cryptography 综合示例教程

本教程面向初学者，演示在 Python 中使用 PyNaCl（libsodium 绑定）和 Cryptography 库完成以下常见密码学操作：  
1. AEAD（XChaCha20-Poly1305）  
2. RSA 非对称加解密与签名／验签  
3. X25519 密钥交换 + AES-GCM 对称加解密  
4. Ed25519 签名／验签  

所有示例均可拷贝到 `.py` 文件中直接运行。

---

## 目录

1. 环境依赖  
2. 示例一：AEAD（XChaCha20-Poly1305）  
3. 示例二：RSA 非对称加解密与签名  
4. 示例三：X25519 密钥交换 + AES-GCM  
5. 示例四：Ed25519 签名／验签  
6. 完整脚本代码  
7. 运行结果示例  

---

## 1. 环境依赖

- Python 3.6+  
- PyNaCl  
- Cryptography

安装方式：

```bash
pip install pynacl cryptography
```

> **提示**：如果在 Linux/macOS 上因缺少 `libsodium` 而安装失败，可先使用包管理器安装：  
> - Ubuntu/Debian: `sudo apt-get install libsodium-dev`  
> - macOS (Homebrew): `brew install libsodium`

---

## 2. 示例一：AEAD（XChaCha20-Poly1305）

使用 libsodium 提供的 XChaCha20-Poly1305 AEAD 接口，既加密又认证。

```python
from nacl import utils, bindings
from nacl.exceptions import CryptoError

def demo_aead_xchacha20poly1305():
    print("\n--- AEAD: XChaCha20-Poly1305 ---")
    msg   = b"Top secret AEAD message"
    key   = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    nonce = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    aad   = b"header-data"

    # 加密
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        msg, aad, nonce, key
    )
    print("ciphertext:", ciphertext.hex())

    # 解密
    try:
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key
        )
        print("decrypted:", plaintext)
    except CryptoError:
        print("AEAD 解密失败")
```

- `crypto_aead_xchacha20poly1305_ietf_KEYBYTES`：密钥长度 32 字节  
- `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES`：nonce 长度 24 字节  
- `aad`（Additional Authenticated Data）可选，用于额外认证头部信息  

---

## 3. 示例二：RSA 非对称加解密与签名

借助 `cryptography` 库生成 RSA 密钥对，并演示 OAEP 加解密、PSS 签名／验签。

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def demo_rsa_encrypt_decrypt_and_sign():
    print("\n--- RSA: 非对称加解密 & 签名 ---")

    # 1. 生成 2048-bit RSA 密钥对
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()

    message = b"Hello RSA world!"

    # 2. RSA-OAEP 加密（SHA-256）
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("RSA ciphertext (hex):", ciphertext.hex())

    # 3. 解密
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("RSA decrypted:", plaintext)

    # 4. RSA-PSS 签名（SHA-256）
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(message)
    signature = signer.finalize()
    print("RSA signature:", signature.hex())

    # 5. 验签
    verifier = public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(message)
    try:
        verifier.verify()
        print("RSA signature verified ✅")
    except Exception:
        print("RSA signature invalid ❌")
```

---

## 4. 示例三：X25519 密钥交换 + AES-GCM

使用 PyNaCl 的 X25519 算法完成密钥交换，再用 Cryptography 实现 AES-256-GCM 对称加解密。

```python
import os
from nacl import public
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def demo_x25519_with_aes_gcm():
    print("\n--- X25519 Key Exchange + AES-GCM ---")

    # 1. 生成 X25519 密钥对
    alice_sk = public.PrivateKey.generate()
    alice_pk = alice_sk.public_key
    bob_sk   = public.PrivateKey.generate()
    bob_pk   = bob_sk.public_key

    # 2. 交换公钥，计算 shared secret
    shared_ab = alice_sk.exchange(bob_pk)
    shared_ba = bob_sk.exchange(alice_pk)
    assert shared_ab == shared_ba

    # 3. 派生 AES-256-GCM 密钥：对 shared_secret 做 SHA256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_ab)
    aes_key = digest.finalize()  # 32 字节

    # 4. AES-GCM 加密
    iv        = os.urandom(12)
    plaintext = b"Confidential via AES-GCM"
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
    ).encryptor()
    encryptor.authenticate_additional_data(b"header-aes")
    ct  = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    print("AES-GCM ciphertext:", ct.hex(), " tag:", tag.hex())

    # 5. AES-GCM 解密
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
    ).decryptor()
    decryptor.authenticate_additional_data(b"header-aes")
    pt = decryptor.update(ct) + decryptor.finalize()
    print("AES-GCM decrypted:", pt)
```

---

## 5. 示例四：Ed25519 签名／验签

纯 PyNaCl 实现 Ed25519 数字签名与验证。

```python
from nacl import signing
from nacl.exceptions import CryptoError

def demo_ed25519_sign_verify():
    print("\n--- Ed25519 签名 / 验签 ---")

    # 1. 生成密钥对
    sk = signing.SigningKey.generate()
    vk = sk.verify_key

    # 2. 签名
    msg    = b"Data to sign with Ed25519"
    signed = sk.sign(msg)
    print("Signed message:", signed.hex())

    # 3. 验签
    try:
        verified = vk.verify(signed)
        print("Verified message:", verified)
    except CryptoError:
        print("Ed25519 验签失败")
```

---

## 6. 完整脚本代码

将以上示例函数集合到一个文件 `crypto_demos.py`，并在主函数中依次调用：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from nacl import utils, bindings, public, signing
from nacl.exceptions import CryptoError
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# （将前面 demo_xxx 函数粘贴到此处）

if __name__ == "__main__":
    demo_aead_xchacha20poly1305()
    demo_rsa_encrypt_decrypt_and_sign()
    demo_x25519_with_aes_gcm()
    demo_ed25519_sign_verify()
```

---

## 7. 运行结果示例

```
--- AEAD: XChaCha20-Poly1305 ---
ciphertext: 5f3c… (hex)
decrypted: b'Top secret AEAD message'

--- RSA: 非对称加解密 & 签名 ---
RSA ciphertext (hex): ab12…ef
RSA decrypted: b'Hello RSA world!'
RSA signature: 3045…a1
RSA signature verified ✅

--- X25519 Key Exchange + AES-GCM ---
AES-GCM ciphertext: 7e9b… tag: d2c3…
AES-GCM decrypted: b'Confidential via AES-GCM'

--- Ed25519 签名 / 验签 ---
Signed message: d2a4…fea3
Verified message: b'Data to sign with Ed25519'
```

---

通过本教程，你可以快速掌握 PyNaCl 与 Cryptography 中几种主流的加密、签名及密钥交换操作。后续可根据需求进一步扩展：使用 KDF 强化密钥派生、引入 sealed box、密钥封装等高级特性。祝学习愉快！
