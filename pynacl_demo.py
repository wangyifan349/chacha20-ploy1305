#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pynacl_demo.py

PyNaCl 各种加密原语与用法演示。涵盖：
1. SecretBox 对称加密
2. AEAD XChaCha20-Poly1305
3. Box 非对称加密
4. SealedBox 匿名加密
5. Ed25519 签名/验签
6. 哈希：BLAKE2b / SHA-256
7. Argon2id 密码派生
8. 随机数与编码（Hex/Base64）
9. 错误处理示例
"""

from nacl import secret, utils, hash, pwhash, bindings, encoding, signing, public
from nacl.public import SealedBox, PrivateKey
from nacl.exceptions import CryptoError, BadSignatureError


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


def demo_aead_xchacha20():
    print("\n=== AEAD: XChaCha20-Poly1305 ===")
    key = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    nonce = utils.random(bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    aad = b"header-auth"
    msg = b"Secret AEAD message"

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


def demo_box():
    print("\n=== Box: 非对称加密 ===")
    # 1. 生成 Alice 和 Bob 的密钥对
    alice_sk = public.PrivateKey.generate()
    alice_pk = alice_sk.public_key
    bob_sk = public.PrivateKey.generate()
    bob_pk = bob_sk.public_key

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


def demo_hash():
    print("\n=== 哈希计算 ===")
    data = b"hello hash"
    print("原始数据:", data)

    h1 = hash.blake2b(data, digest_size=32)
    print("BLAKE2b-256 (hex):", h1.hex())

    h2 = hash.sha256(data)
    print("SHA-256       (hex):", h2.hex())


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
