#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import base64
import struct
import stat
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
# ——————————————————————————————————————————————————————————————————————
# 1) ChaCha20 primitives
# ——————————————————————————————————————————————————————————————————————
def rotate_left_32(value, shift):
    """Rotate a 32-bit integer to the left."""
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

def quarter_round(a, b, c, d):
    """Apply one ChaCha20 quarter round to four state words."""
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left_32(d, 16)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left_32(b, 12)
    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left_32(d, 8)
    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left_32(b, 7)
    return a, b, c, d

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate one 64-byte ChaCha20 keystream block."""
    constant = b"expa" b"nd 3" b"2-by" b"te k"
    constant_0, constant_1, constant_2, constant_3 = struct.unpack("<4I", constant)
    key_0, key_1, key_2, key_3, key_4, key_5, key_6, key_7 = struct.unpack("<8I", key)
    nonce_0, nonce_1, nonce_2 = struct.unpack("<3I", nonce)
    state = [
        constant_0, constant_1, constant_2, constant_3,
        key_0, key_1, key_2, key_3,
        key_4, key_5, key_6, key_7,
        counter, nonce_0, nonce_1, nonce_2,
    ]
    working_state = state.copy()
    for _ in range(10):
        # Column rounds
        working_state[0], working_state[4], working_state[8], working_state[12] = quarter_round(
            working_state[0], working_state[4], working_state[8], working_state[12]
        )
        working_state[1], working_state[5], working_state[9], working_state[13] = quarter_round(
            working_state[1], working_state[5], working_state[9], working_state[13]
        )
        working_state[2], working_state[6], working_state[10], working_state[14] = quarter_round(
            working_state[2], working_state[6], working_state[10], working_state[14]
        )
        working_state[3], working_state[7], working_state[11], working_state[15] = quarter_round(
            working_state[3], working_state[7], working_state[11], working_state[15]
        )
        # Diagonal rounds
        working_state[0], working_state[5], working_state[10], working_state[15] = quarter_round(
            working_state[0], working_state[5], working_state[10], working_state[15]
        )
        working_state[1], working_state[6], working_state[11], working_state[12] = quarter_round(
            working_state[1], working_state[6], working_state[11], working_state[12]
        )
        working_state[2], working_state[7], working_state[8], working_state[13] = quarter_round(
            working_state[2], working_state[7], working_state[8], working_state[13]
        )
        working_state[3], working_state[4], working_state[9], working_state[14] = quarter_round(
            working_state[3], working_state[4], working_state[9], working_state[14]
        )
    output_words = [
        (working_state[index] + state[index]) & 0xffffffff
        for index in range(16)
    ]
    return struct.pack("<16I", *output_words)

def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Encrypt or decrypt data by XORing it with the ChaCha20 keystream."""
    output = bytearray(len(data))
    offset = 0
    while offset < len(data):
        keystream_block = chacha20_block(key, counter, nonce)
        chunk = data[offset:offset + 64]
        for index in range(len(chunk)):
            output[offset + index] = chunk[index] ^ keystream_block[index]
        offset += 64
        counter += 1
    return bytes(output)
# ——————————————————————————————————————————————————————————————————————
# 2) Poly1305 primitives
# ——————————————————————————————————————————————————————————————————————
def clamp_r(r_bytes: bytearray) -> bytearray:
    """Apply the Poly1305 clamp mask to the r value."""
    r_bytes[3] &= 15
    r_bytes[7] &= 15
    r_bytes[11] &= 15
    r_bytes[15] &= 15
    r_bytes[4] &= 252
    r_bytes[8] &= 252
    r_bytes[12] &= 252
    return r_bytes

def poly1305_mac(key: bytes, message: bytes) -> bytes:
    """Compute a Poly1305 authentication tag."""
    r_bytes = clamp_r(bytearray(key[:16]))
    s_value = int.from_bytes(key[16:], "little")
    r_value = int.from_bytes(r_bytes, "little")
    prime = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        block_value = int.from_bytes(chunk + b"\x01", "little")
        accumulator = (accumulator + block_value) * r_value % prime
    tag_value = (accumulator + s_value) & ((1 << 128) - 1)
    return tag_value.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """Pad data to a 16-byte boundary."""
    remainder = len(data) % 16
    if remainder == 0:
        return data
    return data + b"\x00" * (16 - remainder)

def make_poly_input(ciphertext: bytes) -> bytes:
    """Build the Poly1305 input for ChaCha20-Poly1305 without AAD."""
    return (
        ciphertext
        + pad16(ciphertext)
        + struct.pack("<Q", 0)
        + struct.pack("<Q", len(ciphertext))
    )
# ——————————————————————————————————————————————————————————————————————
# 3) AEAD: ChaCha20-Poly1305 without AAD
# ——————————————————————————————————————————————————————————————————————
def aead_encrypt(key: bytes, data: bytes):
    """Encrypt data and return nonce, ciphertext, and authentication tag."""
    nonce = secrets.token_bytes(12)
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, nonce, 1, data)
    tag = poly1305_mac(one_time_key, make_poly_input(ciphertext))
    return nonce, ciphertext, tag

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Authenticate and decrypt ciphertext."""
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    if poly1305_mac(one_time_key, make_poly_input(ciphertext)) != tag:
        raise ValueError("Poly1305 tag verification failed")
    return chacha20_xor(key, nonce, 1, ciphertext)
# ——————————————————————————————————————————————————————————————————————
# 4) File metadata backup and JSON tail encoding/decoding
# ——————————————————————————————————————————————————————————————————————
END_MARKER = b"###END###"
def backup_file_times(path):
    """Save file access time and modification time."""
    file_status = os.stat(path)
    return file_status.st_atime, file_status.st_mtime

def restore_file_times(path, file_times):
    """Restore file access time and modification time."""
    os.utime(path, times=file_times)

def backup_file_mode(path):
    """Save file permission bits."""
    return stat.S_IMODE(os.stat(path).st_mode)

def restore_file_mode(path, file_mode):
    """Restore file permission bits."""
    os.chmod(path, file_mode)

def encode_tail(nonce: bytes, tag: bytes) -> bytes:
    """Encode nonce and tag as a JSON tail followed by an end marker."""
    payload = {
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    json_tail = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return json_tail + END_MARKER

def decode_tail(blob: bytes):
    """Decode nonce and tag from the JSON tail."""
    marker_index = blob.rfind(END_MARKER)
    if marker_index < 0:
        raise ValueError("END_MARKER not found")
    search_start = max(0, marker_index - 4096)
    segment = blob[search_start:marker_index]
    for offset in range(len(segment)):
        try:
            document = segment[offset:].decode("utf-8")
            payload = json.loads(document)
            nonce = base64.b64decode(payload["nonce"])
            tag = base64.b64decode(payload["tag"])
            return nonce, tag, search_start + offset, marker_index + len(END_MARKER)
        except Exception:
            continue
    raise ValueError("Failed to parse JSON tail")
# ——————————————————————————————————————————————————————————————————————
# 5) Single-file encryption/decryption handlers
# ——————————————————————————————————————————————————————————————————————
def process_encryption(path: str, key: bytes) -> str:
    """Encrypt one file in place."""
    try:
        data = open(path, "rb").read()
        nonce, ciphertext, tag = aead_encrypt(key, data)
        tail = encode_tail(nonce, tag)
        file_times = backup_file_times(path)
        file_mode = backup_file_mode(path)
        with open(path, "wb") as output_file:
            output_file.write(ciphertext)
            output_file.write(tail)
        restore_file_times(path, file_times)
        restore_file_mode(path, file_mode)
        return None
    except Exception as error:
        return str(error)
def process_decryption(path: str, key: bytes) -> str:
    """Decrypt one file in place."""
    try:
        blob = open(path, "rb").read()
        nonce, tag, split_index, end_index = decode_tail(blob)
        ciphertext = blob[:split_index]
        plaintext = aead_decrypt(key, nonce, ciphertext, tag)
        file_times = backup_file_times(path)
        file_mode = backup_file_mode(path)
        with open(path, "wb") as output_file:
            output_file.write(plaintext)
        restore_file_times(path, file_times)
        restore_file_mode(path, file_mode)
        return None
    except Exception as error:
        return str(error)
# ——————————————————————————————————————————————————————————————————————
# 6) Directory traversal and concurrent scheduling
# ——————————————————————————————————————————————————————————————————————
def gather_files(root: str):
    """Collect all files under a directory recursively."""
    file_paths = []
    for base_directory, _, filenames in os.walk(root):
        for filename in filenames:
            file_paths.append(os.path.join(base_directory, filename))
    return file_paths
# ——————————————————————————————————————————————————————————————————————
# 7) Main entry point
# ——————————————————————————————————————————————————————————————————————
def main():
    """Program entry point."""
    operation_mode = ""
    while operation_mode not in ("enc", "dec"):
        operation_mode = input("Select mode enc(encrypt) / dec(decrypt): ").strip().lower()
    root_directory = input("Enter the target directory: ").strip()
    if not os.path.isdir(root_directory):
        print("Directory does not exist. Exiting.")
        sys.exit(1)
    key_hex = input("Enter a 32-byte hexadecimal key: ").strip()
    try:
        key = bytes.fromhex(key_hex)
    except Exception:
        print("Invalid key format. Exiting.")
        sys.exit(1)
    if len(key) != 32:
        print("Key length is not 32 bytes. Exiting.")
        sys.exit(1)
    try:
        thread_count = int(input("Enter the number of worker threads (>= 1): ").strip())
        if thread_count < 1:
            raise ValueError
    except Exception:
        print("Invalid thread count. Exiting.")
        sys.exit(1)
    files = gather_files(root_directory)
    if not files:
        print("No files found in the directory. Exiting.")
        sys.exit(0)
    action_name = "encrypting" if operation_mode == "enc" else "decrypting"
    print(f"Start {action_name} {len(files)} files with {thread_count} worker threads...")
    errors = []
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {
            executor.submit(
                process_encryption if operation_mode == "enc" else process_decryption,
                path,
                key,
            ): path
            for path in files
        }
        for future in as_completed(futures):
            error = future.result()
            if error:
                errors.append((futures[future], error))
    if errors:
        print("\nThe following files failed:", file=sys.stderr)
        for path, error in errors:
            print(f"{path} failed: {error}", file=sys.stderr)
        sys.exit(1)
    print("All files processed successfully.")
if __name__ == "__main__":
    main()
