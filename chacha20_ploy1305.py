#!/usr/bin/env python3
# coding: utf-8
"""
ChaCha20-Poly1305 File and Directory Encryption/Decryption Tool
Features:
  - Uses ChaCha20 stream cipher and Poly1305 MAC for authenticated encryption.
  - Supports in-place encryption and decryption of all regular files under a target directory.
  - Encrypted file format: nonce (12 bytes) | tag (16 bytes) | ciphertext (rest).
  - Automatically preserves file access and modification times.
  - Skips non-regular files (such as symlinks, pipes, devices).
Notes:
  - The key must be 32 bytes, provided as a 64-character hex string.
  - Keep your key secure; loss of key will make files unrecoverable!
  - Strongly recommended to back up original data before using this tool.
Author:   Wang YiFan
Date:     2026
"""
import os
import struct
import sys
import getpass
############# Cryptographic Primitives #############
def rotate_left(value: int, bits: int) -> int:
    """
    Rotate a 32-bit integer left by 'bits' places.
    """
    return ((value << bits) & 0xffffffff) | (value >> (32 - bits))
def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Core ChaCha20 block function. Outputs 64 bytes of keystream for the given key, counter, and nonce.
    Args:
      key:     32-byte (256-bit) key
      counter: 4-byte integer block counter, usually starts from 0 or 1
      nonce:   12-byte unique nonce per message
    Returns:
      64-byte keystream block
    """
    constants = b'expand 32-byte k'
    # ChaCha20 state: [constant | key | counter | nonce]
    state = list(struct.unpack('<4I', constants) +           # 16 bytes: constants ("expa" "nd 3" "2-by" "te k")
                 struct.unpack('<8I', key) +                 # 32 bytes: key (8 words)
                 (counter,) +                                # 4 bytes: block counter
                 struct.unpack('<3I', nonce))                # 12 bytes: nonce (3 words)
    working_state = state.copy()
    def quarter_round(x, a, b, c, d):
        """
        One quarter round operation -- modifies x in-place.
        Repeats addition, xor, and rotation (per spec).
        """
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotate_left(x[d], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotate_left(x[b], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotate_left(x[d], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotate_left(x[b], 7)
    # 20 total rounds (10 column and 10 diagonal double-rounds)
    for _ in range(10):
        # "Column" rounds: operate on 4 columns of the state matrix
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        # "Diagonal" rounds: operate on diagonals of the state matrix
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
    # Add the original state to the working state (mod 2^32)
    output_words = [(working_state[i] + state[i]) & 0xffffffff for i in range(16)]
    # Pack output as 64 bytes (16 little-endian uint32's)
    return struct.pack('<16I', *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, init_counter: int, input_bytes: bytes) -> bytes:
    """
    Encrypts or decrypts data using ChaCha20. (XORs keystream blocks with input.)
    Args:
      key:          32-byte key
      nonce:        12-byte unique nonce for the message
      init_counter: Starting block counter (1 for encryption, 0 is reserved for Poly1305 key)
      input_bytes:  Plaintext (for encrypt) or ciphertext (for decrypt)
    Returns:
      Encrypted or decrypted bytes (identical process)
    """
    output = bytearray()
    input_len = len(input_bytes)
    n_blocks = (input_len + 63) // 64  # Process in 64-byte blocks
    for block_idx in range(n_blocks):
        block_offset = block_idx * 64
        block = input_bytes[block_offset : block_offset + 64]
        keystream = chacha20_block(key, init_counter + block_idx, nonce)
        for i in range(len(block)):
            output.append(block[i] ^ keystream[i])  # XOR each byte with keystream
    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    Parses and clamps the Poly1305 32-byte key (r, s), as specified in RFC 8439.
    Args:
      key: 32-byte bytes object (first 16 bytes for r, next 16 for s)
    Returns:
      (r, s) as integers, with r bits properly clamped
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]  # s does not need clamping

    # Clamp certain bits of r per Poly1305 spec
    r_bytes[3]  &= 15    # Clear upper 4 bits  (byte 3)
    r_bytes[7]  &= 15
    r_bytes[11] &= 15
    r_bytes[15] &= 15
    r_bytes[4]  &= 252   # Clear lower 2 bits  (byte 4)
    r_bytes[8]  &= 252
    r_bytes[12] &= 252
    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    return r, s
def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    Computes a Poly1305 MAC (message authentication code) for given message and key.
    Args:
      key: 32 bytes - Poly1305 one-time key (from ChaCha20 block 0)
      msg: Data to authenticate (bytes)
    Returns:
      16-byte authentication tag
    """
    r, s = poly1305_clamp_r_s(key)
    prime = (1 << 130) - 5   # Poly1305 prime
    accumulator = 0
    idx = 0
    while idx < len(msg):
        block = msg[idx:idx+16]
        blocklen = len(block)
        if blocklen < 16:
            block += b"\x00" * (16 - blocklen)
        # Integer representation, add implicit 1<<8*len per Poly1305 spec
        n = int.from_bytes(block, "little") + (1 << (8*blocklen))
        accumulator = (accumulator + n) % prime
        accumulator = (accumulator * r) % prime
        idx += 16

    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    Pads data to next multiple of 16 bytes using zeros (Poly1305 padding).
    """
    pad_len = (16 - (len(data) % 16)) % 16
    if pad_len == 0:
        return data
    return data + b"\x00" * pad_len

def encode_u64_le(val: int) -> bytes:
    """
    Encode a Python integer as an unsigned 64-bit little-endian byte string.
    """
    return struct.pack('<Q', val)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
    """
    Complete AEAD encryption using ChaCha20-Poly1305.
    Args:
      key:       32-byte secret key
      nonce:     12-byte unique nonce
      plaintext: Data to encrypt
      aad:       Additional Authenticated Data (optional)
    Returns:
      (ciphertext, tag), both bytes objects
    """
    # Generate Poly1305 one-time key: ChaCha20 block 0
    poly_key = chacha20_block(key, 0, nonce)[:32]
    # Main encryption (counter starts at 1)
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)
    # Build MAC input: AAD, padded | ciphertext, padded | AAD len (8 bytes) | ciphertext len (8 bytes)
    mac_data = (
        pad16(aad) +
        pad16(ciphertext) +
        encode_u64_le(len(aad)) +
        encode_u64_le(len(ciphertext))
    )
    tag = poly1305_mac(poly_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """
    Complete AEAD decryption with authentication using ChaCha20-Poly1305.
    Raises ValueError if authentication fails.
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = (
        pad16(aad) +
        pad16(ciphertext) +
        encode_u64_le(len(aad)) +
        encode_u64_le(len(ciphertext))
    )
    expected_tag = poly1305_mac(poly_key, mac_data)
    if expected_tag != tag:
        raise ValueError("Poly1305 MAC authentication failed! (Wrong key or corrupted file?)")
    return chacha20_crypt(key, nonce, 1, ciphertext)

################### File Operations ###################

def encrypt_file(filepath: str, key: bytes):
    """
    Encrypts a single file in-place.
    File storage format: [nonce (12 bytes)] | [tag (16 bytes)] | ciphertext
    Preserves original file access and modification time.
    """
    nonce = os.urandom(12)  # Generate a fresh nonce for this file
    file_stat = os.stat(filepath)
    atime, mtime = file_stat.st_atime, file_stat.st_mtime

    with open(filepath, "rb") as fin:
        plaintext = fin.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)
    with open(filepath, "wb") as fout:
        fout.write(nonce + tag + ciphertext)  # Write all data in format: nonce|tag|ciphertext
    os.utime(filepath, (atime, mtime))  # Restore timestamps
def decrypt_file(filepath: str, key: bytes):
    """
    Decrypts a single file in-place.
    Expects file format: [nonce (12 bytes)] | [tag (16 bytes)] | ciphertext
    Preserves original file access and modification time.
    """
    file_stat = os.stat(filepath)
    atime, mtime = file_stat.st_atime, file_stat.st_mtime

    with open(filepath, "rb") as fin:
        content = fin.read()
    if len(content) < 28:
        raise ValueError("File too short to contain ChaCha20-Poly1305 structure.")

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)
    with open(filepath, "wb") as fout:
        fout.write(plaintext)
    os.utime(filepath, (atime, mtime))  # Restore timestamps
def process_directory(target_dir: str, key: bytes, mode: str):
    """
    Recursively encrypts or decrypts all regular files in given directory (in-place).
    Skips non-regular files with a warning.
    Args:
      target_dir: Directory path
      key:        32-byte secret key
      mode:       "encrypt" or "decrypt"
    """
    for dirpath, dirnames, filenames in os.walk(target_dir):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                if not os.path.isfile(filepath):  # Skip non-regular files
                    print(f"Skipped non-regular file: {filepath}")
                    continue
                if mode == "encrypt":
                    encrypt_file(filepath, key)
                    print(f"[Encrypted] {filepath}")
                else:
                    decrypt_file(filepath, key)
                    print(f"[Decrypted] {filepath}")
            except Exception as exc:
                print(f"[FAILED] {filepath}: {exc}")
################## Command Line UI ####################
if __name__ == '__main__':
    print('\n===== ChaCha20-Poly1305 Directory Encryption/Decryption Tool =====')
    print('!!! Please back up files before running this tool. Losing your key means loss of data! !!!\n')
    # Prompt for 32-byte key as hex string (masked input)
    key_hex = getpass.getpass("Enter your 32-byte secret key as 64 hex digits: ").strip()
    try:
        key = bytes.fromhex(key_hex)
    except Exception:
        print("Invalid key format! Must be 64 hexadecimal digits (32 bytes).")
        sys.exit(1)
    if len(key) != 32:
        print("Key must be exactly 32 bytes (64 hexadecimal digits).")
        sys.exit(1)
    # Prompt for directory path
    dir_input = input("Enter the full path to the target directory: ").strip()
    if not os.path.isdir(dir_input):
        print(f"Directory does not exist: {dir_input}")
        sys.exit(1)
    # Prompt for operation
    operation = input("Choose operation (e: encrypt, d: decrypt): ").strip().lower()
    if operation == "e":
        print(f"Starting encryption for directory: {dir_input}")
        process_directory(dir_input, key, "encrypt")
        print("Encryption finished.")
    elif operation == "d":
        print(f"Starting decryption for directory: {dir_input}")
        process_directory(dir_input, key, "decrypt")
        print("Decryption finished.")
    else:
        print("Invalid operation. Enter 'e' to encrypt or 'd' to decrypt.")
