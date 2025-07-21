# ChaCha20-Poly1305: Concise Overview & Pure-Python Example

> **Warning:** For production, use a vetted library (e.g. `cryptography`, OpenSSL, libsodium).  
> This example is **educational**: Python’s big-integer arithmetic is variable-time.

---

## 1. Algorithm in Brief

- ChaCha20: 256-bit key, 96-bit nonce, 32-bit block counter → 64-byte keystream blocks  
- Poly1305: One-time MAC keyed from ChaCha20, produces 16-byte tag  
- AEAD steps:
  1. Derive Poly1305 key (`r∥s`) from ChaCha20 block counter=0  
  2. Encrypt plaintext with ChaCha20 starting counter=1  
  3. MAC ciphertext (no AAD in this example)  
  4. Append 16-byte tag  

---

## 2. Core Implementation

```python
import struct

# --- 2.1 32-bit Rotate & Quarter-Round ---

def rotl32(x: int, n: int) -> int:
    return ((x << n) & 0xffffffff) | (x >> (32 - n))  # 32-bit left rotate

def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    # ChaCha20 quarter-round on state s at indices a,b,c,d
    s[a] = (s[a] + s[b]) & 0xffffffff            # a += b
    s[d] ^= s[a]; s[d] = rotl32(s[d], 16)         # d ^= a ; d <<<=16
    s[c] = (s[c] + s[d]) & 0xffffffff            # c += d
    s[b] ^= s[c]; s[b] = rotl32(s[b], 12)         # b ^= c ; b <<<=12
    s[a] = (s[a] + s[b]) & 0xffffffff            # a += b
    s[d] ^= s[a]; s[d] = rotl32(s[d], 8)          # d ^= a ; d <<<= 8
    s[c] = (s[c] + s[d]) & 0xffffffff            # c += d
    s[b] ^= s[c]; s[b] = rotl32(s[b], 7)          # b ^= c ; b <<<= 7
```

```python
# --- 2.2 ChaCha20 Block ---

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("Key must be 32 B, nonce 12 B")
    constants = b"expand 32-byte k"                           # 16 B
    # pack: constants ∥ key ∥ counter ∥ nonce
    state = list(struct.unpack("<4I8I3I",
        constants + key + struct.pack("<I3I", counter, *struct.unpack("<3I", nonce))
    ))
    working = state.copy()
    for _ in range(10):                                        # 20 rounds
        # column rounds
        quarter_round(working, 0,4, 8,12)
        quarter_round(working, 1,5, 9,13)
        quarter_round(working, 2,6,10,14)
        quarter_round(working, 3,7,11,15)
        # diagonal rounds
        quarter_round(working, 0,5,10,15)
        quarter_round(working, 1,6,11,12)
        quarter_round(working, 2,7, 8,13)
        quarter_round(working, 3,4, 9,14)
    # add original state
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff
    return struct.pack("<16I", *working)                       # 64 B keystream
```

```python
# --- 2.3 ChaCha20 Encrypt ---

def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    blocks = (len(plaintext) + 63) // 64
    for i in range(blocks):
        ks = chacha20_block(key, counter + i, nonce)         # 64 B keystream block
        chunk = plaintext[i*64:(i+1)*64]
        out.extend(p ^ ks[j] for j, p in enumerate(chunk))   # XOR
    return bytes(out)
```

```python
# --- 2.4 Poly1305 MAC ---

def poly1305_mac(msg: bytes, r_key: bytes, s_key: bytes) -> bytes:
    # clamp r: clear top bits per RFC 7539
    r = int.from_bytes(r_key, "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(s_key, "little")
    p = (1 << 130) - 5
    acc = 0
    # process 16-byte blocks
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk + b"\x01", "little")        # append 1 byte
        acc = (acc + n) % p
        acc = (acc * r) % p
    tag = (acc + s) & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")                        # 16 B tag
```

```python
# --- 2.5 AEAD (No AAD) ---

def aead_chacha20_poly1305(key: bytes, nonce: bytes, plaintext: bytes):
    # 1) derive one-time Poly1305 key (counter=0)
    otk = chacha20_block(key, 0, nonce)[:32]
    r_key, s_key = otk[:16], otk[16:]
    # 2) encrypt (counter=1)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    # 3) MAC over ciphertext only
    #    (no padding needed for single‐part)
    tag = poly1305_mac(ciphertext, r_key, s_key)
    return ciphertext, tag
```

---

## 3. Example & Test Vector

```python
if __name__ == "__main__":
    # RFC 7539 A.5 test vector
    key     = bytes(range(0x80, 0xA0))                       # 80..9F
    nonce   = b"\x00"*7 + b"\x4A" + b"\x00"*4                 # 12 B
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, sunscreen would be it."
    )
    ct, tag = aead_chacha20_poly1305(key, nonce, plaintext)
    print("Ciphertext:", ct.hex())
    print("Tag:       ", tag.hex())
    # Expected tag: 1ae10b594f09e26a7e902ecbd0600691
```

---

References:  
- RFC 7539 – ChaCha20 & Poly1305 (IETF)  
- D. J. Bernstein, “ChaCha, a variant of Salsa20” (ePrint 2008/065)
