# 🔐 ChaCha20-Poly1305 Directory Encryption Tool

## 🚀 Overview

This Python script implements the **ChaCha20-Poly1305** authenticated encryption algorithm following [RFC 8439](https://tools.ietf.org/html/rfc8439), designed for **recursive, in-place encryption and decryption** of all files within a directory. It preserves filenames and timestamps during processing.

---

## 💡 How It Works

1. 🎲 **Nonce Generation**  
   Generates a fresh, random 12-byte nonce for each file to guarantee uniqueness.

2. 🔑 **Poly1305 Key Derivation**  
   Derives the Poly1305 key by encrypting a zero block with ChaCha20 (counter=0) using the file’s nonce and key.

3. 🔐 **Encryption**  
   Encrypts the plaintext with ChaCha20 (starting block counter 1), producing the ciphertext.

4. 🛡️ **Authentication Tag Creation**  
   Calculates a Poly1305 tag over:  
   - Additional Authenticated Data (empty in this version)  
   - Proper padding  
   - Ciphertext  
   - Length fields for AAD & ciphertext  
   This ensures integrity and authenticity.

5. 💾 **Encrypted File Format**  
   The original file is overwritten with:  
   ```
   [12-byte nonce] || [16-byte Poly1305 tag] || [ciphertext]
   ```

6. 🔄 **Decryption**  
   Extracts nonce, tag, ciphertext → verifies tag → decrypts ciphertext → overwrites with plaintext. Aborts if authentication fails.

---

## ⚙️ Usage Instructions

1. Set your **32-byte key** in the script:  
   ```python
   key = b'your 32 bytes key here__________'  # Exactly 32 bytes!
   ```  
   Or generate a secure random key:  
   ```python
   import os
   key = os.urandom(32)
   print(f"Your key (hex): {key.hex()}")
   ```

2. Run the script:  
   ```bash
   python chacha20-poly1305.py
   ```

3. Follow prompts to:  
   - Enter the target directory path  
   - Choose operation:  
     - `e` for encrypt all files recursively 🔒  
     - `d` for decrypt all files recursively 🔓

---

## 📂 File Format Summary

| Component                 | Size (Bytes) | Description                      |
|---------------------------|--------------|--------------------------------|
| Nonce                     | 12           | Unique per file nonce           |
| Poly1305 Authentication Tag | 16           | Data integrity & authenticity  |
| Ciphertext                | Variable     | Encrypted file contents        |

---

## ⚠️ Security Considerations

- Always use a **cryptographically secure 32-byte key**.  
- **Do NOT reuse nonces with the same key**, as this breaks security guarantees.  
- Poly1305 tag verification failures abort decryption to protect integrity.  
- This version does **not support Additional Authenticated Data (AAD)**.  
- **Test carefully on non-critical data before real usage!**  
- For personal or educational use; **audit thoroughly before production deployment**.

---

## 🛠 Dependencies

- Python 3.6+  
- Standard Python libraries: `os`, `struct`

---

## 📜 License

MIT License. See [LICENSE](./LICENSE) for details.

---

## 🙋 Author

wangyifan349@gmail.com  
wangyifan1999@protonmail.com
