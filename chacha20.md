# ChaCha20-Poly1305: Concise Overview and Pure Python Implementation

> A dependency-free Python example illustrating why ChaCha20-Poly1305 is simple and efficient.

## 1. Algorithm Overview

# ChaCha20-Poly1305: Concise Overview and Pure Python Implementation

This document explains the core ideas of ChaCha20-Poly1305, why it is efficient, and provides a dependency-free Python example.

## 1. Algorithm Overview

1. ChaCha20: a stream cipher based on addition, XOR, and fixed-rotation operations  
2. Poly1305: a Message Authentication Code (MAC) based on arithmetic modulo 2¹³⁰–5  
3. AEAD construction:  
   - Use ChaCha20 to generate a one-time key and encrypt the plaintext  
   - Use Poly1305 to authenticate the ciphertext and any associated data

## 2. Why It’s Efficient

- Only uses integer addition, XOR, and bit rotations; no lookup tables or branches  
- Small working state (512 bits) fits in registers or caches  
- Easily parallelizable and vectorizable  
- Resistant to side-channel attacks (no S-Boxes)

## 3. Algorithm Details

3.1 Quarter Round  
Given four 32-bit words a, b, c, d:
```
a += b; d ^= a; d  = ROTL(d,16)
c += d; b ^= c; b  = ROTL(b,12)
a += b; d ^= a; d  = ROTL(d, 8)
c += d; b ^= c; b  = ROTL(b, 7)
```

3.2 Block Function  
- Initialize a 16×32-bit state: 4 words of constants ∥ 8 words of key ∥ 1 word counter ∥ 3 words nonce  
- Copy it to a working state, perform 10 column rounds and 10 diagonal rounds (20 rounds total)  
- Add the working state back to the original state and output 64 bytes of keystream

3.3 Poly1305  
- Input: 16 B `r` (with low 3 bits and high 4 bits cleared), 16 B `s`  
- Split the message into 16 B blocks, append `0x01`, interpret as a little-endian integer, accumulate in `acc`, multiply by `r`, reduce modulo 2¹³⁰–5  
- Final tag = `(acc + s) mod 2¹²⁸` as 16 bytes

## 4. Pure Python Implementation

```python
import struct

def rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d],16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b],12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = rotl32(s[b], 7)

def chacha20_block(key, counter, nonce):
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I8I3I",
        constants + key + struct.pack("<I3I", counter, *struct.unpack("<3I", nonce))
    ))
    working = state.copy()
    for _ in range(10):
        # Column rounds
        quarter_round(working, 0,4, 8,12)
        quarter_round(working, 1,5, 9,13)
        quarter_round(working, 2,6,10,14)
        quarter_round(working, 3,7,11,15)
        # Diagonal rounds
        quarter_round(working, 0,5,10,15)
        quarter_round(working, 1,6,11,12)
        quarter_round(working, 2,7, 8,13)
        quarter_round(working, 3,4, 9,14)
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff
    return struct.pack("<16I", *working)

def chacha20_encrypt(key, counter, nonce, plaintext):
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        ks = chacha20_block(key, counter + i//64, nonce)
        block = plaintext[i:i+64]
        out.extend(b ^ ks[j] for j, b in enumerate(block))
    return bytes(out)

def poly1305_mac(msg, r_key, s_key):
    r = int.from_bytes(r_key, "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i+16] + b"\x01", "little")
        acc = (acc + n) % p
        acc = (acc * r) % p
    s = int.from_bytes(s_key, "little")
    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")

def aead_chacha20_poly1305(key, nonce, plaintext, aad=b""):
    # 1. Generate one-time Poly1305 key
    otk = chacha20_block(key, 0, nonce)[:32]
    r_key, s_key = otk[:16], otk[16:]
    # 2. Encrypt
    ct = chacha20_encrypt(key, 1, nonce, plaintext)
    # 3. Authenticate
    def pad(x): return x + b"\x00" * ((16 - len(x)%16)%16)
    mac_data = pad(aad) + pad(ct) \
               + struct.pack("<Q", len(aad)) \
               + struct.pack("<Q", len(ct))
    tag = poly1305_mac(mac_data, r_key, s_key)
    return ct, tag

# Example
if __name__ == "__main__":
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    pt = b"Hello, ChaCha20-Poly1305!"
    ct, tag = aead_chacha20_poly1305(key, nonce, pt, aad=b"header")
    print("Ciphertext:", ct.hex())
    print("Tag:       ", tag.hex())
```

## 5. Summary

- ChaCha20-Poly1305 combines a stream cipher with a one-pass MAC for high performance.  
- Only basic arithmetic and bit-wise operations are used, making it ideal for general-purpose CPUs and embedded systems.  
- For production use, rely on vetted cryptographic libraries and implement constant-time operations, replay protection, etc.
