import os
import struct

def rotl(x: int, n: int) -> int:
    """Rotate left a 32-bit integer x by n bits."""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Compute a single 64-byte ChaCha20 key stream block.
    """
    constants = b"expand 32-byte k"
    const_words = struct.unpack("<4I", constants)
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    state = list(const_words + key_words + (counter,) + nonce_words)
    working = state.copy()

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl(x[d], 16)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl(x[b], 12)

        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl(x[d], 8)

        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl(x[b], 7)

    iteration = 0
    while iteration < 10:
        # Column rounds
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        iteration += 1

    output_words = []
    idx = 0
    while idx < 16:
        output_words.append((working[idx] + state[idx]) & 0xffffffff)
        idx += 1

    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    ChaCha20 encryption/decryption: XOR data with keystream.
    """
    output = bytearray()
    data_length = len(data)
    block_count = (data_length + 63) // 64

    block_index = 0
    while block_index < block_count:
        block_start = block_index * 64
        block_end = block_start + 64
        block = data[block_start:block_end]
        keystream = chacha20_block(key, counter + block_index, nonce)

        byte_index = 0
        while byte_index < len(block):
            output.append(block[byte_index] ^ keystream[byte_index])
            byte_index += 1

        block_index += 1

    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    Clamp the Poly1305 'r' portion and return integers r and s.
    """
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r_int = int.from_bytes(r_bytes, "little")
    s_int = int.from_bytes(s_bytes, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    Compute the Poly1305 authentication tag.
    """
    r, s = poly1305_clamp_r_s(key)
    prime_p = (1 << 130) - 5
    accumulator = 0

    msg_idx = 0
    msg_len = len(msg)
    while msg_idx < msg_len:
        block = msg[msg_idx:msg_idx + 16]
        if len(block) < 16:
            block = block + (b"\x00" * (16 - len(block)))
        n = int.from_bytes(block, "little") + (1 << 128)
        accumulator = (accumulator + n) % prime_p
        accumulator = (accumulator * r) % prime_p
        msg_idx += 16

    tag_num = (accumulator + s) % (1 << 128)
    return tag_num.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    Pad data with zero bytes to a 16-byte multiple.
    """
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        return data
    else:
        return data + (b"\x00" * padding_len)

def u64_le(n: int) -> bytes:
    """Encode integer as 8-byte little-endian bytes."""
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 AEAD encryption."""
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly1305_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """ChaCha20-Poly1305 AEAD decryption and verification."""
    poly1305_key = chacha20_block(key, 0, nonce)[:32]

    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    calculated_tag = poly1305_mac(poly1305_key, mac_data)
    if calculated_tag != tag:
        raise ValueError("Poly1305 authentication failed!")

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(file_path: str, key: bytes):
    """Encrypt a single file in place."""
    nonce = os.urandom(12)

    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as file:
        plaintext = file.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    with open(file_path, "wb") as file:
        file.write(nonce + tag + ciphertext)

    os.utime(file_path, (atime, mtime))

def decrypt_file(file_path: str, key: bytes):
    """Decrypt a single file in place."""
    stat_info = os.stat(file_path)
    atime = stat_info.st_atime
    mtime = stat_info.st_mtime

    with open(file_path, "rb") as file:
        content = file.read()

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(file_path, "wb") as file:
        file.write(plaintext)

    os.utime(file_path, (atime, mtime))

def encrypt_directory(input_directory: str, key: bytes):
    """Recursively encrypt all files in a directory in place."""
    for current_root, directories, files in os.walk(input_directory):
        file_index = 0
        while file_index < len(files):
            filename = files[file_index]
            filepath = os.path.join(current_root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as exc:
                print(f"Encrypt failed: {filepath} - {exc}")
            file_index += 1

def decrypt_directory(input_directory: str, key: bytes):
    """Recursively decrypt all files in a directory in place."""
    for current_root, directories, files in os.walk(input_directory):
        file_index = 0
        while file_index < len(files):
            filename = files[file_index]
            filepath = os.path.join(current_root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as exc:
                print(f"Decrypt failed: {filepath} - {exc}")
            file_index += 1

# Sample key bytes (replace with your own secure key).
key = b'\x18\xe7\xc6\x14\xf0\xc9\xd2a\x04\xd9\xcf3\xc6\xb5\x1c\xc1\nQ\xec\xdbhd\xbe\x12\xcb\x08\x86\x9a\x05\xe7\xedO'

"""
# To generate a random key and print in hex format:
import os

key = os.urandom(32)
hex_key = key.hex()
print(f"Generated key (hex): {hex_key}")
"""

if len(key) != 32:
    print("Error: Key length must be 32 bytes!")
    exit(1)

target_directory = input("Please enter the target directory path: ").strip()
if not os.path.isdir(target_directory):
    print(f"Error: Directory does not exist: {target_directory}")
    exit(1)

operation = input("Please enter operation type (e: encrypt, d: decrypt): ").strip().lower()
if operation == "e":
    print(f"Starting encryption of directory: {target_directory}")
    encrypt_directory(target_directory, key)
    print("Encryption completed")
elif operation == "d":
    print(f"Starting decryption of directory: {target_directory}")
    decrypt_directory(target_directory, key)
    print("Decryption completed")
else:
    print("Error: Operation type only supports e (encrypt) or d (decrypt)")
    exit(1)
