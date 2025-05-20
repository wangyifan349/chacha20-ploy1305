# 🔐 ChaCha20-Poly1305 Directory Encryption Tool

## 🚀 Overview

This Python tool implements the **ChaCha20-Poly1305** authenticated encryption algorithm according to [RFC 8439](https://tools.ietf.org/html/rfc8439), designed for **recursive, in-place encryption/decryption** of all files inside a directory. Filenames and timestamps are preserved during processing.

---

## 🔑 Core Algorithm Workflow

1. 🎲 **Nonce generation**: For each file encrypted, a fresh, random 12-byte nonce is generated to ensure uniqueness.

2. 🔐 **Poly1305 key derivation**: Encrypt a 32-byte zero block with ChaCha20 (`counter=0`) using the file's nonce and key to derive the Poly1305 key (`r` and `s`).

3. 🛡️ **Encryption**: Encrypt the plaintext content with ChaCha20 starting at block counter 1, producing ciphertext.

4. 📋 **Authentication tag calculation**:
   - Calculate a **Poly1305 tag** over:
     - Additional Authenticated Data (AAD): empty in this version.
     - Padding to 16-byte boundaries.
     - Ciphertext.
     - Length fields for AAD and ciphertext.
   - This tag ensures data integrity 🔍 and authenticity ✅.

5. 💾 **File output**: The encrypted file format:
   
   ```
   [ 12-byte nonce ] || [ 16-byte Poly1305 tag ] || [ ciphertext ]
   ```
   
   The original file is overwritten with this encrypted blob.

6. 🔄 **Decryption**:
   - Extract nonce, tag, and ciphertext from file.
   - Verify Poly1305 tag — decryption aborts if verification fails ❌.
   - Decrypt ciphertext back to plaintext using ChaCha20.
   - Overwrite original file with decrypted content.

---

## 📂 Usage

1. Set your symmetric key in the script:

```python
key = b"your 32 bytes key here______________"  # EXACTLY 32 bytes 🔐
```

2. Run the script:

```bash
python your_script.py
```

3. Follow prompts:

- Enter **directory path** to encrypt/decrypt recursively.
- Select operation:
  - `e` — encrypt all files recursively 🔒
  - `d` — decrypt all files recursively 🔓

---

## 📁 File Format Details

| Component                | Size (Bytes) | Description                          |
|--------------------------|--------------|------------------------------------|
| Nonce                    | 12           | Unique random nonce per file 🔄      |
| Poly1305 Authentication Tag | 16           | Ensures integrity and authenticity ✅ |
| Ciphertext               | Variable     | The encrypted file contents 🛡️         |

---
## ⚠️ Security Notes

- Use a cryptographically secure **32-byte key** 🔑.
- **Never reuse nonce with the same key** (this causes catastrophic failure).
- The nonce is 12 bytes and must be unique per file.
- Poly1305 tag failure immediately stops decryption of that file ❌.
- Currently no support for Additional Authenticated Data (AAD).
- **⚠️ Important:** Before running on your own valuable data, **please test thoroughly on non-critical files first** to ensure expected behavior and prevent accidental data loss!
- Intended for learning or personal use; audit carefully before production.
---

## 🛠️ Dependencies

- Python 3.6 or newer
- Standard libraries: `os`, `struct`

---

## 📜 License

This project is licensed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.

---

## 🙋 Author
wangyifan349@gmail.com

wangyifan1999@protonmail.com
