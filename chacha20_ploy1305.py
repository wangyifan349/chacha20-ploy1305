import os
import struct

def rotl(x: int, n: int) -> int:
    """Rotate left a 32-bit integer x by n bits."""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Compute a single 64-byte ChaCha20 keystream block.
    Parameters:
      key: 32 bytes key.
      counter: 32-bit integer.
      nonce: 12 bytes.
    Returns:
      64-byte keystream block.
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

    # Perform 10 rounds, with each round containing a column round and a diagonal round.
    for _ in range(10):
        # Column round
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # Diagonal round
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    output_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    ChaCha20 encryption/decryption: XOR the data with the keystream.
    Parameters:
      key: 32 bytes key.
      nonce: 12 bytes nonce.
      counter: Initial counter, generally starting from 1 (0 is used for generating the Poly1305 key stream).
      data: Data to be encrypted or decrypted.
    Returns:
      Processed data.
    """
    output = bytearray()
    data_length = len(data)
    block_count = (data_length + 63) // 64

    for block_index in range(block_count):
        block_start = block_index * 64
        block_end = block_start + 64
        block = data[block_start:block_end]
        keystream = chacha20_block(key, counter + block_index, nonce)

        for byte_index in range(len(block)):
            output.append(block[byte_index] ^ keystream[byte_index])

    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    Parse the Poly1305 32-byte key:
     - The first 16 bytes are used as r and are "clamped" as specified.
     - The last 16 bytes are used as s and remain unchanged.
    Returns:
      Two integers (r, s).
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]

    # Clear the high 4 bits of bytes at indexes 3, 7, 11, 15 (only keep the low 4 bits)
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    # Clear the low 2 bits of bytes at indexes 4, 8, 12 (only keep the high 6 bits)
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r_int = int.from_bytes(r_bytes, "little")
    s_int = int.from_bytes(s_bytes, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    Compute the Poly1305 authentication tag (MAC).
    Parameters:
      key: 32-byte key, with the first 16 bytes as r (to be clamped) and the last 16 as s.
      msg: The message to authenticate.
    Returns:
      16-byte MAC.
    """
    r, s = poly1305_clamp_r_s(key)
    prime_p = (1 << 130) - 5
    accumulator = 0

    msg_idx = 0
    msg_len = len(msg)
    while msg_idx < msg_len:
        block = msg[msg_idx:msg_idx + 16]
        block_length = len(block)
        # Padding is added only for converting to an integer and does not affect the implicit bit.
        if block_length < 16:
            block = block + (b"\x00" * (16 - block_length))
        # Add the implicit 1 (represented in the lowest bit as 1 << (8 * block_length)) based on the actual block length.
        n = int.from_bytes(block, "little") + (1 << (8 * block_length))
        accumulator = (accumulator + n) % prime_p
        accumulator = (accumulator * r) % prime_p
        msg_idx += 16

    tag_num = (accumulator + s) % (1 << 128)
    return tag_num.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """
    Pad data to a multiple of 16 bytes (using 0x00 for padding).
    """
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        return data
    else:
        return data + (b"\x00" * padding_len)

def u64_le(n: int) -> bytes:
    """Encode an integer as 8 bytes in little-endian."""
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""):
    """
    ChaCha20-Poly1305 AEAD encryption.
    Parameters:
      key: 32-byte master key.
      nonce: 12-byte random nonce.
      plaintext: Plaintext data.
      aad: Additional authenticated data (AAD), which is included in the MAC but not encrypted.
    Returns:
      (ciphertext, tag)
    """
    # Use the ChaCha20 block with counter 0 to generate the Poly1305 key (first 32 bytes only)
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    # Generate the keystream for encryption starting from counter 1
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    # Construct MAC data: A || pad16(A) || C || pad16(C) || [len(A)]_8 || [len(C)]_8
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly1305_key, mac_data)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """
    ChaCha20-Poly1305 AEAD decryption with authentication.
    Parameters:
      key: 32-byte master key.
      nonce: 12-byte random nonce.
      ciphertext: Encrypted data.
      tag: 16-byte authentication tag.
      aad: Additional authenticated data.
    Returns:
      The plaintext data. If authentication fails, an exception is raised.
    """
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))
    calculated_tag = poly1305_mac(poly1305_key, mac_data)
    if calculated_tag != tag:
        raise ValueError("Poly1305 authentication failed!")
    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(file_path: str, key: bytes):
    """
    Encrypt a single file in-place.
    File storage format: nonce (12 bytes) || tag (16 bytes) || ciphertext
    """
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
    """
    Decrypt a single file in-place.
    Expected file format: nonce (12 bytes) || tag (16 bytes) || ciphertext
    """
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
    """Recursively encrypt all files in the directory in-place."""
    for current_root, directories, files in os.walk(input_directory):
        for filename in files:
            filepath = os.path.join(current_root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as exc:
                print(f"Encrypt failed: {filepath} - {exc}")

def decrypt_directory(input_directory: str, key: bytes):
    """Recursively decrypt all files in the directory in-place."""
    for current_root, directories, files in os.walk(input_directory):
        for filename in files:
            filepath = os.path.join(current_root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as exc:
                print(f"Decrypt failed: {filepath} - {exc}")


# Example key, 32 bytes (please replace with your own key)
key = b'\x18\xe7\xc6\x14\xf0\xc9\xd2a\x04\xd9\xcf3\xc6\xb5\x1c\xc1\nQ\xec\xdbhd\xbe\x12\xcb\x08\x86\x9a\x05\xe7\xedO'
"""
# Alternatively, generate a random key and print its hex representation
key = os.urandom(32)
print(f"Generated key (hex): {key.hex()}")
"""

if len(key) != 32:
    print("Error: Key length must be 32 bytes!")
    exit(1)

target_directory = input("Please enter the target directory path: ").strip()
if not os.path.isdir(target_directory):
    print(f"Error: Directory does not exist: {target_directory}")
    exit(1)

operation = input("Please enter the operation type (e: encrypt, d: decrypt): ").strip().lower()
if operation == "e":
    print(f"Starting encryption on directory: {target_directory}")
    encrypt_directory(target_directory, key)
    print("Encryption completed")
elif operation == "d":
    print(f"Starting decryption on directory: {target_directory}")
    decrypt_directory(target_directory, key)
    print("Decryption completed")
else:
    print("Error: Operation type must be either e (encrypt) or d (decrypt)")
    exit(1)
