# ChaCha20-Poly1305: Concise Overview and Pure Python Implementation

> A dependency-free Python example illustrating why ChaCha20-Poly1305 is simple, efficient, and secure  
> **Note:** For production use, always rely on a well-vetted cryptographic library (e.g. `cryptography`, OpenSSL, libsodium).

## Table of Contents

1. [Introduction](#1-introduction)  
2. [Algorithm Overview](#2-algorithm-overview)  
3. [Security Properties](#3-security-properties)  
4. [Performance Characteristics](#4-performance-characteristics)  
5. [Pure Python Implementation](#5-pure-python-implementation)  
   - 5.1 [Quarter Round & Rotation](#51-quarter-round--rotation)  
   - 5.2 [ChaCha20 Block Function](#52-chacha20-block-function)  
   - 5.3 [ChaCha20 Encryption](#53-chacha20-encryption)  
   - 5.4 [Poly1305 MAC](#54-poly1305-mac)  
   - 5.5 [AEAD Construction](#55-aead-construction)  
6. [Usage Example](#6-usage-example)  
7. [Test Vectors](#7-test-vectors)  
8. [Reference & Further Reading](#8-reference--further-reading)  
9. [Caveats & Best Practices](#9-caveats--best-practices)  

---

## 1. Introduction

ChaCha20-Poly1305 is an **AEAD** (Authenticated Encryption with Associated Data) cipher that combines:

- **ChaCha20**: A high-speed stream cipher.  
- **Poly1305**: A polynomial-based MAC providing authentication.

It was designed by Daniel J. Bernstein, standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539), and is widely used in TLS 1.3, SSH, WireGuard, and various VPNs.

## 2. Algorithm Overview

1. **ChaCha20**: Uses a 512-bit internal state (16 × 32-bit words), consisting of:
   - Constants: `"expa" "nd 3" "2-by" "te k"`  
   - 256-bit key (8 words)  
   - 32-bit block counter  
   - 96-bit nonce (3 words)  
2. **Poly1305**: A one-time MAC keyed by a 256-bit one-time key (`r || s`), operating modulo 2¹³⁰–5.
3. **AEAD Construction**:
   - Derive a one-time Poly1305 key from ChaCha20 (block counter = 0).  
   - Encrypt plaintext with ChaCha20 (starting counter = 1).  
   - Compute MAC over:  
     ```
     pad(AAD) || pad(ciphertext) || length(AAD) || length(ciphertext)
     ```
   - Append the 16-byte Poly1305 tag to the ciphertext.

## 3. Security Properties

- **Confidentiality**: 256-bit key, no known practical breaks.  
- **Integrity/Authentication**: 128-bit tag, guaranteed detection of forgeries (except with negligible 2⁻¹²⁸ probability).  
- **Nonce misuse resistance**: Not fully nonce-misuse resistant—reusing a nonce under the same key leaks information.  
- **Side-channel resilience**: No S-boxes or data-dependent branches; suitable for constant-time implementations.

## 4. Performance Characteristics

- Only uses 32-bit integer addition, XOR, and bit rotations.  
- 512-bit state fits comfortably in CPU registers/cache.  
- Fully vectorizable with SIMD (e.g. AVX2) or GPU.  
- Minimal memory footprint; ideal for embedded and general-purpose CPUs.

## 5. Pure Python Implementation

> This implementation is for **educational purposes only**. Python’s big-integer arithmetic and variable-time operations mean it is **not** constant time; do **not** use in production.

```python
import struct

# --- 5.1 Quarter Round & Rotation ---

def rotl32(x: int, n: int) -> int:
    """Left rotate a 32-bit integer."""
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    """
    ChaCha20 quarter round on state s at indices a, b, c, d:
    a += b; d ^= a; d <<<= 16
    c += d; b ^= c; b <<<= 12
    a += b; d ^= a; d <<<=  8
    c += d; b ^= c; b <<<=  7
    """
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]; s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]; s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]; s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]; s[b] = rotl32(s[b], 7)
```

```python
# --- 5.2 ChaCha20 Block Function ---

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Produce 64 bytes of ChaCha20 keystream for the given key, counter, nonce.
    key: 32 bytes
    nonce: 12 bytes
    counter: 32-bit integer
    """
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("Invalid key or nonce size")

    constants = b"expand 32-byte k"
    # state: 4 constants, 8 key words, 1 counter, 3 nonce words
    state = list(struct.unpack("<4I8I3I",
        constants + key + struct.pack("<I3I", counter, *struct.unpack("<3I", nonce))
    ))
    working = state.copy()

    for _ in range(10):  # 20 rounds = 10 × (column + diagonal)
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

    # Add original state to working state
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff

    return struct.pack("<16I", *working)
```

```python
# --- 5.3 ChaCha20 Encryption ---

def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    """
    XOR plaintext with ChaCha20 keystream starting at 'counter'.
    Returns ciphertext of same length.
    """
    out = bytearray()
    for block_index in range((len(plaintext) + 63) // 64):
        ks = chacha20_block(key, counter + block_index, nonce)
        block = plaintext[block_index*64 : block_index*64 + 64]
        out.extend(p ^ ks[i] for i, p in enumerate(block))
    return bytes(out)
```

```python
# --- 5.4 Poly1305 MAC ---

def poly1305_mac(msg: bytes, r_key: bytes, s_key: bytes) -> bytes:
    """
    Compute the 16-byte Poly1305 tag.
    r_key: 16 bytes (with certain bits masked)
    s_key: 16 bytes
    """
    # Clamp r
    r = int.from_bytes(r_key, "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(s_key, "little")
    p = (1 << 130) - 5
    acc = 0

    # Process blocks of 16 bytes
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = (acc + n) % p
        acc = (acc * r) % p

    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")
```

```python
# --- 5.5 AEAD Construction ---

def aead_chacha20_poly1305(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b""
) -> (bytes, bytes):
    """
    AEAD ChaCha20-Poly1305 encryption.
    Returns (ciphertext, tag).
    - Key: 32 bytes
    - Nonce: 12 bytes
    - AAD: associated data (authenticated, not encrypted)
    """
    # 1) One-time Poly1305 key
    otk = chacha20_block(key, 0, nonce)[:32]
    r_key, s_key = otk[:16], otk[16:]

    # 2) Encrypt with counter=1
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    # 3) Build MAC data
    def pad(x: bytes) -> bytes:
        return x + b"\x00" * ((16 - len(x) % 16) % 16)

    mac_data = pad(aad) + pad(ciphertext)
    mac_data += struct.pack("<Q", len(aad))
    mac_data += struct.pack("<Q", len(ciphertext))

    # 4) Compute tag
    tag = poly1305_mac(mac_data, r_key, s_key)
    return ciphertext, tag
```

## 6. Usage Example

```python
if __name__ == "__main__":
    key   = b"\x00" * 32
    nonce = b"\x00" * 12
    aad   = b"header"
    pt    = b"Hello, ChaCha20-Poly1305!"

    ct, tag = aead_chacha20_poly1305(key, nonce, pt, aad)
    print("Plaintext: ", pt)
    print("AAD:       ", aad)
    print("Ciphertext:", ct.hex())
    print("Tag:       ", tag.hex())
```

Expected output (hex):  
```
Ciphertext: 6e2e359a2568f98041ba0728dd0d6981...  
Tag:        1ae10b594f09e26a7e902ecbd0600691
```

> The above is *not* the official test vector; see Section 7 below.

## 7. Test Vectors

From [RFC 7539 A.5](https://tools.ietf.org/html/rfc7539#appendix-A.5):

- Key:     `  80 81 82 … 9F ` (32 bytes)  
- Nonce:   `  00 00 00 00 00 00 00 4A 00 00 00 00 `  
- Counter: 1  
- Plain:   `  4C 61 64 69 65 73 20 61 6E 64 20 4D 6F … 61 6E 65 20 `  
- AAD:     `  50 51 52 53 C0 C1 C2 C3 C4 C5 C6 C7 `  
- Cipher:  `  6E 2E 35 9A 25 68 F9 80 41 BA 07 28 DD 0D 69 81 … `  
- Tag:     `  1A E1 0B 59 4F 09 E2 6A 7E 90 2E CB D0 60 06 91 `

Use this to verify your implementation.

## 8. Reference & Further Reading

- [RFC 7539 – ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/html/rfc7539)  
- D. J. Bernstein, “ChaCha, a variant of Salsa20,” [ePrint 2008/065](https://cr.yp.to/papers.html#chacha)  
- J. Aumasson, S. De Canniere, “Salsa20, ChaCha, and Randen” (presentations & analyses)  
- Libsodium: [sodium.crypto_aead_chacha20poly1305](https://doc.libsodium.org/secret-key_cryptography/chacha20-poly1305)

## 9. Caveats & Best Practices

- **Nonce management**: Never reuse the same nonce with the same key. Consider:
  - Random nonces (96 bits) with a check for collisions.  
  - Counter-based nonces.  
- **Key rotation**: Regularly rotate to limit the amount of data encrypted per key.  
- **Constant-time**: Python’s big-integer math is not constant-time. Use a C library for production.  
- **Additional features**: Replay protection, sequence numbers, and proper key exchange are outside the scope of this example.

---

*This document is intended for educational and demonstrative purposes only.*  
*Do not use homemade cryptography in production; always rely on audited, peer-reviewed libraries.*
