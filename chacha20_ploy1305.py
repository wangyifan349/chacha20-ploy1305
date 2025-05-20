import os
import struct

def rotl(x, n):
    """Rotate 32-bit integer x left by n bits."""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Produce a single 64-byte ChaCha20 key stream block.
    - key: 32-byte symmetric key
    - counter: 32-bit block counter
    - nonce: 12-byte nonce
    Returns 64 bytes of key stream.
    """
    constants = b"expand 32-byte k"
    const_words = struct.unpack("<4I", constants)
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    # Initialize ChaCha20 state with constants, key, counter and nonce (16 words)
    state = list(const_words + key_words + (counter,) + nonce_words)
    working = state.copy()

    def quarterround(x, a, b, c, d):
        """Perform ChaCha20 quarter round operation on elements a,b,c,d of x in place."""
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

    # Execute 20 rounds: 10 iterations of double rounds (column + diagonal)
    for _ in range(10):
        # Column rounds
        quarterround(working, 0, 4, 8, 12)
        quarterround(working, 1, 5, 9, 13)
        quarterround(working, 2, 6, 10, 14)
        quarterround(working, 3, 7, 11, 15)
        # Diagonal rounds
        quarterround(working, 0, 5, 10, 15)
        quarterround(working, 1, 6, 11, 12)
        quarterround(working, 2, 7, 8, 13)
        quarterround(working, 3, 4, 9, 14)

    # Add original state to the working state (mod 2^32)
    output_words = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    # Pack result as 64 bytes little-endian
    return struct.pack("<16I", *output_words)

def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    Encrypt or decrypt arbitrary-length data with ChaCha20 by XOR with key stream.
    - key: 32-byte key
    - nonce: 12-byte nonce
    - counter: initial 32-bit block counter (usually 1 for encryption)
    - data: plaintext or ciphertext
    Returns: output bytes of same length as input.
    """
    output = bytearray()
    n_blocks = (len(data) + 63) // 64  # Calculate number of 64-byte blocks, rounded up
    for block_idx in range(n_blocks):
        block = data[block_idx*64 : (block_idx+1)*64]
        keystream = chacha20_block(key, counter + block_idx, nonce)
        for i in range(len(block)):
            output.append(block[i] ^ keystream[i])
    return bytes(output)

def poly1305_clamp_r_s(key: bytes):
    """
    Clamp the r portion of Poly1305 key and separate r and s as integers.
    - key: 32-byte Poly1305 key = r(16 bytes) || s(16 bytes)
    Returns (r_int, s_int) as big integers.
    """
    r = bytearray(key[:16])
    s = key[16:]

    # Clamp r per Poly1305 specification to reduce weaknesses
    r[3]  &= 0x0f
    r[7]  &= 0x0f
    r[11] &= 0x0f
    r[15] &= 0x0f
    r[4]  &= 0xfc
    r[8]  &= 0xfc
    r[12] &= 0xfc

    r_int = int.from_bytes(r, "little")
    s_int = int.from_bytes(s, "little")
    return r_int, s_int

def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    Compute Poly1305 message authentication code (MAC) for given message.
    - key: 32-byte Poly1305 key (r and s)
    - msg: message to authenticate
    Returns 16-byte authentication tag.
    """
    r, s = poly1305_clamp_r_s(key)
    p = (1 << 130) - 5  # Prime modulus for Poly1305
    acc = 0             # Initialize accumulator to zero

    # Process message in 16-byte blocks
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        # Pad block with zeros if less than 16 bytes
        if len(block) < 16:
            block += b"\x00" * (16 - len(block))

        # Interpret block as a 128-bit little-endian integer
        n = int.from_bytes(block, "little")
        # Add 2^128 to the block number per Poly1305 spec (high bit)
        n += 1 << 128

        # Modular addition and multiplication with accumulator and r
        acc = (acc + n) % p
        acc = (acc * r) % p

    # Final tag is accumulator plus s modulo 2^128
    tag = (acc + s) % (1 << 128)
    # Convert tag to 16-byte little-endian bytes
    return tag.to_bytes(16, "little")

def pad16(data: bytes) -> bytes:
    """Pad bytes to a multiple of 16 bytes by appending zero bytes."""
    pad_len = (16 - (len(data) % 16)) % 16
    if pad_len == 0:
        return data
    return data + (b"\x00" * pad_len)

def u64_le(n: int) -> bytes:
    """Encode integer n as 8-byte little-endian bytes."""
    return struct.pack("<Q", n)

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    """
    Encrypt plaintext using ChaCha20-Poly1305 (without AAD).
    Procedure:
      1. Generate Poly1305 key by encrypting 32 bytes from block with counter=0.
      2. Encrypt plaintext starting with counter=1.
      3. Compute Poly1305 tag over (AAD||padding||ciphertext||padding||lengths).
       AAD is empty here.
    Returns (ciphertext, 16-byte tag).
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]

    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)

    aad = b""
    poly_msg = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    tag = poly1305_mac(poly_key, poly_msg)
    return ciphertext, tag

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    """
    Decrypt and verify ChaCha20-Poly1305 ciphertext without AAD.
    Raises ValueError if authentication fails.
    Returns original plaintext if verification passes.
    """
    poly_key = chacha20_block(key, 0, nonce)[:32]

    aad = b""
    poly_msg = pad16(aad) + pad16(ciphertext) + u64_le(len(aad)) + u64_le(len(ciphertext))

    calc_tag = poly1305_mac(poly_key, poly_msg)
    if calc_tag != tag:
        raise ValueError("Poly1305 authentication failed!")

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)
    return plaintext

def encrypt_file(in_filepath: str, key: bytes):
    """
    Encrypt a single file in place.
    File format after encryption:
    [12-byte nonce || 16-byte Poly1305 tag || ciphertext]
    Original file access and modification times are preserved.
    """
    nonce = os.urandom(12)

    stat = os.stat(in_filepath)
    atime = stat.st_atime
    mtime = stat.st_mtime

    with open(in_filepath, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)

    with open(in_filepath, "wb") as f:
        f.write(nonce + tag + ciphertext)

    os.utime(in_filepath, (atime, mtime))

def decrypt_file(in_filepath: str, key: bytes):
    """
    Decrypt a single file in place.
    Expects file format:
    [12-byte nonce || 16-byte Poly1305 tag || ciphertext]
    Raises ValueError if authentication fails.
    Restores original file access and modification times after decryption.
    """
    stat = os.stat(in_filepath)
    atime = stat.st_atime
    mtime = stat.st_mtime

    with open(in_filepath, "rb") as f:
        content = f.read()

    nonce = content[:12]
    tag = content[12:28]
    ciphertext = content[28:]

    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)

    with open(in_filepath, "wb") as f:
        f.write(plaintext)

    os.utime(in_filepath, (atime, mtime))

def encrypt_directory(input_dir: str, key: bytes):
    """
    Recursively encrypt all files in the directory, in-place.
    Files are overwritten with encrypted content.
    Original file names and timestamps are preserved.
    Errors are printed but do not stop processing.
    """
    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                encrypt_file(filepath, key)
                print(f"Encrypted: {filepath}")
            except Exception as e:
                print(f"Encrypt failed: {filepath} - {e}")

def decrypt_directory(input_dir: str, key: bytes):
    """
    Recursively decrypt all files in the directory, in-place.
    Files are overwritten with decrypted content.
    Original file names and timestamps are preserved.
    Errors (e.g. auth failure) are printed but do not stop processing.
    """
    for root, dirs, files in os.walk(input_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                decrypt_file(filepath, key)
                print(f"Decrypted: {filepath}")
            except Exception as e:
                print(f"Decrypt failed: {filepath} - {e}")

# Main interactive section:

key = b"your 32 bytes key here______________"  # Must be exactly 32 bytes. Please verify length.
if len(key) != 32:
    print("Error: Key length must be exactly 32 bytes!")
    exit(1)

input_dir = input("Please enter the target directory path: ").strip()
if not os.path.isdir(input_dir):
    print(f"Error: Directory does not exist: {input_dir}")
    exit(1)

op = input("Please enter operation type (e: encrypt, d: decrypt): ").strip().lower()
if op == "e":
    print(f"Starting encryption on directory: {input_dir}")
    encrypt_directory(input_dir, key)
    print("Encryption completed.")
elif op == "d":
    print(f"Starting decryption on directory: {input_dir}")
    decrypt_directory(input_dir, key)
    print("Decryption completed.")
else:
    print("Error: Unsupported operation type. Please enter 'e' or 'd'.")
    exit(1)
