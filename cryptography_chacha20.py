#!/usr/bin/env python3
"""
ChaCha20-Poly1305 Encryption and Decryption Demo with cryptography library
Requirements:
    pip install cryptography
This script demonstrates how to generate keys, encrypt, and decrypt data
using ChaCha20-Poly1305 authenticated encryption algorithm.
"""

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
print("=== ChaCha20-Poly1305 Encryption/Decryption Demo ===")
# Generate a secure random 32-byte key
key = ChaCha20Poly1305.generate_key()
print(f"Generated key (hex): {key.hex()}")
chacha = ChaCha20Poly1305(key)
# Generate a fresh 12-byte nonce
nonce = os.urandom(12)
print(f"Generated nonce (hex): {nonce.hex()}")
plaintext = b"Example plaintext data to encrypt"
print(f"Plaintext: {plaintext.decode()}")
aad = b""  # Additional Authenticated Data is empty here
# Encrypt
ciphertext = chacha.encrypt(nonce, plaintext, aad)
print(f"Ciphertext + Tag (hex): {ciphertext.hex()}")
# Decrypt
try:
    decrypted = chacha.decrypt(nonce, ciphertext, aad)
    print(f"Decrypted plaintext: {decrypted.decode()}")
except InvalidTag:
    print("ERROR: Authentication failed during decryption! Data may be corrupted or tampered.")
    sys.exit(1)
