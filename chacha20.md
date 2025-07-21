ChaCha20-Poly1305 in Pure Python (Educational)

> ⚠️ **Warning:** This code is **not** safe for production!  
> Python’s big-integer math is variable-time, has no side-channel protections, and is slow.  
> Always use a vetted library (e.g. `cryptography`, OpenSSL, libsodium) in real systems.

---

## 1. How It Works (Step by Step)

1. **ChaCha20 stream cipher**  
   - Takes a 32-byte key, 12-byte nonce, and 32-bit counter  
   - Produces 64-byte keystream blocks  
   - Encryption: ciphertext = plaintext XOR keystream  

2. **Poly1305 message authentication code (MAC)**  
   - One-time key (r||s) produced by ChaCha20 (counter=0)  
   - Processes the data (we’ll MAC the ciphertext)  
   - Outputs a 16-byte tag  

3. **AEAD construction**  
   - Derive Poly1305 key from ChaCha20 block 0  
   - Encrypt plaintext with ChaCha20 starting at counter=1  
   - Compute Poly1305 over the ciphertext  
   - Append 16-byte tag  

4. **Decryption**  
   - Re-derive Poly1305 key from ChaCha20 block 0  
   - MAC the received ciphertext and verify it matches the tag  
   - If tag is valid, decrypt (XOR with keystream)  

---

## 2. Complete Code with Encryption & Decryption

```python
import struct

# --- 2.1 Utility: 32-bit rotate left ---
def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

# --- 2.2 ChaCha20 quarter-round ---
def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]; s[b] = rotl32(s[b], 7)

# --- 2.3 ChaCha20 block function (64 bytes output) ---
def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("Key must be 32 bytes, nonce 12 bytes")
    # Constants
    constants = b"expand 32-byte k"
    # Pack state: constants ∥ key ∥ counter ∥ nonce
    state = list(struct.unpack(
        "<4I8I3I",
        constants + key + struct.pack("<I3I", counter, *struct.unpack("<3I", nonce))
    ))
    working = state.copy()
    # 20 rounds: 10 × (column + diagonal)
    for _ in range(10):
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
    # Add original state
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff
    return struct.pack("<16I", *working)

# --- 2.4 ChaCha20 encryption (stream XOR) ---
def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    blocks = (len(data) + 63) // 64
    for i in range(blocks):
        block = data[i*64:(i+1)*64]
        keystream = chacha20_block(key, counter + i, nonce)
        for j, byte in enumerate(block):
            out.append(byte ^ keystream[j])
    return bytes(out)

# --- 2.5 Poly1305 MAC ---
def poly1305_mac(msg: bytes, r_key: bytes, s_key: bytes) -> bytes:
    # Clamp r per RFC 7539
    r = int.from_bytes(r_key, "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(s_key, "little")
    p = (1 << 130) - 5
    acc = 0
    # Process each 16-byte block
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        # Append one byte of 0x01 (the universal pad)
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = (acc + n) % p
        acc = (acc * r) % p
    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")

# --- 2.6 AEAD Encrypt ---
def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    # 1) Derive one-time Poly1305 key from block 0
    otk = chacha20_block(key, 0, nonce)[:32]
    r_key, s_key = otk[:16], otk[16:]
    # 2) Encrypt plaintext with counter=1
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    # 3) Compute MAC over ciphertext
    tag = poly1305_mac(ciphertext, r_key, s_key)
    return ciphertext, tag

# --- 2.7 AEAD Decrypt ---
def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    # 1) Re-derive Poly1305 key
    otk = chacha20_block(key, 0, nonce)[:32]
    r_key, s_key = otk[:16], otk[16:]
    # 2) Verify MAC
    expected = poly1305_mac(ciphertext, r_key, s_key)
    if not constant_time_eq(expected, tag):
        raise ValueError("Tag mismatch! Decryption failed.")
    # 3) Decrypt with counter=1
    plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)
    return plaintext

# --- 2.8 Constant-time compare to prevent timing attacks ---
def constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

# --- 3. Example Usage ---
if __name__ == "__main__":
    # Sample key & nonce (never reuse nonce!)
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    message = b"Hello, ChaCha20-Poly1305!"

    # Encrypt
    ct, tg = aead_encrypt(key, nonce, message)
    print("Ciphertext:", ct.hex())
    print("Tag:       ", tg.hex())

    # Decrypt (with correct tag)
    pt = aead_decrypt(key, nonce, ct, tg)
    print("Decrypted: ", pt)

    # Tamper (to show authentication)
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0x01  # flip a bit
    try:
        aead_decrypt(key, nonce, bytes(bad_ct), tg)
    except ValueError as e:
        print("Decryption failed:", e)
```

---

### How to read the code

- **rotl32**: 32-bit left rotation  
- **quarter_round**: core mixing operation of ChaCha20  
- **chacha20_block**: builds a 64-byte keystream block from key∥counter∥nonce  
- **chacha20_encrypt**: splits input into 64-byte chunks, XORs each with its keystream block  
- **poly1305_mac**: clamps r, processes each 16-byte chunk plus a `0x01` byte, multiplies & adds mod (2¹³⁰–5), then adds s  
- **aead_encrypt**:  
  1. Run block(…, counter=0) → one-time key for Poly1305  
  2. Encrypt data with counter=1…  
  3. MAC the ciphertext → tag  
- **aead_decrypt**:  
  1. Recompute one-time key (counter=0)  
  2. Verify tag (constant-time)  
  3. Decrypt (counter=1)

This example covers a **full** encrypt–authenticate–decrypt cycle and demonstrates tag-verification failure.
