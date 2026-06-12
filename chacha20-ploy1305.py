"""
ChaCha20-Poly1305 File/Directory Encryption Script

This script is used to recursively encrypt or decrypt all files under a specified
directory. After the program starts, the user first enters a password, then enters
the target directory path, and finally chooses the operation type: enter e for
encryption, or d for decryption. The script does not hardcode the key or password
in the source code. Instead, it derives a 32-byte key from the password entered
at runtime, and uses that key for subsequent ChaCha20-Poly1305 encryption and
authentication.

Core logic:

1. Key derivation:
   The user-entered password is not used directly as the ChaCha20-Poly1305 key.
   Instead, PBKDF2-HMAC-SHA256 is used to derive a fixed-length 32-byte key.
   This avoids hardcoding a key in the source code and provides better resistance
   against brute-force attacks than a simple sha256(password).
   To keep the original file format unchanged, the current version uses a fixed
   salt. If the file format can be changed in the future, this can be further
   improved by using an independent random salt for each file.

2. File encryption:
   When encrypting each individual file, the program generates a random 12-byte
   nonce, then uses ChaCha20 to encrypt the file plaintext into ciphertext. At
   the same time, Poly1305 authenticates the ciphertext and generates a 16-byte
   authentication tag. The final file format remains:
       nonce(12 bytes) || tag(16 bytes) || ciphertext

3. File decryption:
   During decryption, the program reads the first 12 bytes of the file as the
   nonce, the next 16 bytes as the tag, and the remaining bytes as the ciphertext.
   It then derives the key again from the same user-entered password and first
   verifies the Poly1305 authentication tag. If authentication fails, it means
   the password is wrong, the file has been tampered with, or the file content is
   corrupted, and the program refuses to decrypt it. Only after authentication
   succeeds does the program use ChaCha20 to recover the plaintext.

4. Directory processing:
   If the target is a directory, the script recursively traverses all files in
   the directory using os.walk, and calls encrypt_file or decrypt_file for each
   file. Each file gets its own nonce, so even when the same user password is
   used, the encrypted output of different files is different.

Notes:

- This script overwrites files in place. Encryption replaces the original file
  with ciphertext, and decryption replaces the encrypted file with plaintext.
  Back up important data before using it in practice.
- Encryption and decryption must use the same password. If the password is lost,
  the original files cannot be recovered.

"""

import os          # Provides file, directory, random-byte, and timestamp operations.
import struct      # Converts integers to and from little-endian byte sequences.
import getpass     # Reads passwords without echoing them to the terminal.
import hashlib     # Provides PBKDF2-HMAC-SHA256 for key derivation.
import hmac        # Provides constant-time tag comparison to reduce timing side channels.


def rotl(value: int, shift_bits: int) -> int:
    """Rotate a 32-bit integer value left by shift_bits bits."""
    left_part = (value << shift_bits) & 0xffffffff      # Shift left and truncate to 32 bits, because Python integers are unbounded.
    right_part = value >> (32 - shift_bits)             # Take the high bits that wrapped around during the left shift.
    return left_part | right_part                       # Combine both parts to form the 32-bit rotate-left result.


def quarter_round(state_words, first_index, second_index, third_index, fourth_index):
    """ChaCha20 quarter-round function."""
    state_words[first_index] = (state_words[first_index] + state_words[second_index]) & 0xffffffff
    state_words[fourth_index] ^= state_words[first_index]                    # XOR the fourth state word with the updated first word.
    state_words[fourth_index] = rotl(state_words[fourth_index], 16)          # Rotate left by 16 bits as specified by ChaCha20.

    state_words[third_index] = (state_words[third_index] + state_words[fourth_index]) & 0xffffffff
    state_words[second_index] ^= state_words[third_index]                    # Mix the third state word into the second state word.
    state_words[second_index] = rotl(state_words[second_index], 12)          # Rotate left by 12 bits as specified by ChaCha20.

    state_words[first_index] = (state_words[first_index] + state_words[second_index]) & 0xffffffff
    state_words[fourth_index] ^= state_words[first_index]                    # Second mixing step to further diffuse the state.
    state_words[fourth_index] = rotl(state_words[fourth_index], 8)           # Rotate left by 8 bits as specified by ChaCha20.

    state_words[third_index] = (state_words[third_index] + state_words[fourth_index]) & 0xffffffff
    state_words[second_index] ^= state_words[third_index]                    # Final XOR-mixing step in the quarter round.
    state_words[second_index] = rotl(state_words[second_index], 7)           # Rotate left by 7 bits as specified by ChaCha20.


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Compute a single 64-byte ChaCha20 keystream block.

    Parameters:
        key: 32 bytes
        counter: 32-bit integer
        nonce: 12 bytes

    Returns:
        A 64-byte keystream block.
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")             # ChaCha20 uses a fixed 256-bit key.

    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")           # IETF ChaCha20-Poly1305 uses a 96-bit nonce.

    constants = b"expand 32-byte k"                                  # Standard ChaCha20 constant.

    constant_words = struct.unpack("<4I", constants)                 # Split the 16-byte constant into four little-endian 32-bit integers.
    key_words = struct.unpack("<8I", key)                            # Split the 32-byte key into eight little-endian 32-bit integers.
    nonce_words = struct.unpack("<3I", nonce)                        # Split the 12-byte nonce into three little-endian 32-bit integers.

    state_words = [0] * 16                                           # ChaCha20 internal state consists of sixteen 32-bit words.

    for constant_index in range(4):
        state_words[constant_index] = constant_words[constant_index] # state[0..3] contains the fixed constant.

    for key_word_index in range(8):
        state_words[4 + key_word_index] = key_words[key_word_index]  # state[4..11] contains the 256-bit key.

    state_words[12] = counter                                        # state[12] is the block counter.

    for nonce_word_index in range(3):
        state_words[13 + nonce_word_index] = nonce_words[nonce_word_index]  # state[13..15] contains the 96-bit nonce.

    working_words = state_words.copy()                               # The working state is modified by rounds; the original state is needed for final addition.

    round_count = 10                                                  # Each loop includes one column round and one diagonal round, for 20 rounds total.
    for round_index in range(round_count):
        quarter_round(working_words, 0, 4, 8, 12)                    # Column round: first column.
        quarter_round(working_words, 1, 5, 9, 13)                    # Column round: second column.
        quarter_round(working_words, 2, 6, 10, 14)                   # Column round: third column.
        quarter_round(working_words, 3, 7, 11, 15)                   # Column round: fourth column.
        quarter_round(working_words, 0, 5, 10, 15)                   # Diagonal round: first diagonal.
        quarter_round(working_words, 1, 6, 11, 12)                   # Diagonal round: second diagonal.
        quarter_round(working_words, 2, 7, 8, 13)                    # Diagonal round: third diagonal.
        quarter_round(working_words, 3, 4, 9, 14)                    # Diagonal round: fourth diagonal.

    output_words = [0] * 16                                          # Holds the final output state.
    for word_index in range(16):
        output_words[word_index] = (working_words[word_index] + state_words[word_index]) & 0xffffffff
        # Final ChaCha20 step: add the working state to the original state word by word, still truncated to 32 bits.

    output_block = struct.pack("<16I", *output_words)                # Pack sixteen 32-bit integers into a 64-byte keystream block.
    return output_block


def chacha20_crypt(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """
    Encrypt or decrypt data with ChaCha20 by XORing it with the keystream.
    """
    result_bytes = bytearray()                                       # Accumulate output bytes efficiently.

    data_length = len(data)                                          # Length of the input data.

    block_num = data_length // 64                                    # Each ChaCha20 block produces 64 bytes of keystream.
    if data_length % 64 != 0:
        block_num += 1                                               # A final partial block still requires one keystream block.

    for block_index in range(block_num):
        keystream_block = chacha20_block(key, counter + block_index, nonce)  # Use an increasing counter so each block gets a different keystream.

        block_start = block_index * 64                               # Start offset of the current data block.
        block_end = block_start + 64                                 # Theoretical end offset of the current data block.

        if block_end > data_length:
            block_end = data_length                                  # The final block may be shorter than 64 bytes.

        data_block = data[block_start:block_end]                     # Current block of input data.

        for byte_index in range(len(data_block)):
            encrypted_byte = data_block[byte_index] ^ keystream_block[byte_index]
            result_bytes.append(encrypted_byte)                      # Encryption and decryption are both data XOR keystream.

    return bytes(result_bytes)


def poly1305_clamp_r_s(key: bytes):
    """
    Parse a 32-byte Poly1305 key:
    the first 16 bytes are r and must be clamped; the last 16 bytes are s.
    Returns two integers: r and s.
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes.")           # A Poly1305 one-time key is always 32 bytes.

    r_bytes = bytearray(key[:16])                                    # The first 16 bytes are r and must be clamped.
    s_bytes = key[16:]                                               # The last 16 bytes are s and are used directly as an integer.

    r_bytes[3] &= 0x0f                                               # Clamp: clear selected bits in r to restrict its value.
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f

    r_bytes[4] &= 0xfc                                               # Clamp: ensure selected low bits are zero.
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r_value = int.from_bytes(r_bytes, "little")                      # Interpret r as a little-endian integer.
    s_value = int.from_bytes(s_bytes, "little")                      # Interpret s as a little-endian integer.

    return r_value, s_value


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """
    Compute the Poly1305 message authentication code.
    """
    r_value, s_value = poly1305_clamp_r_s(key)                       # Split and clamp the Poly1305 key.

    prime_modulus = (1 << 130) - 5                                   # Poly1305 modulus p = 2^130 - 5.
    accumulator = 0                                                  # Initial accumulator value.

    message_length = len(msg)                                        # Length of the message to authenticate.
    message_offset = 0                                               # Current processing offset.

    while message_offset < message_length:
        message_block = msg[message_offset:message_offset + 16]      # Poly1305 processes 16-byte blocks.
        message_block_length = len(message_block)

        if message_block_length < 16:
            padded_block = message_block + b"\x00" * (16 - message_block_length)  # Zero-pad the final partial block to 16 bytes.
        else:
            padded_block = message_block

        block_number = int.from_bytes(padded_block, "little")        # Interpret the current block as a little-endian integer.
        block_number += 1 << (8 * message_block_length)              # Append the implicit 1 bit to each block.

        accumulator = (accumulator + block_number) % prime_modulus   # Add the current block to the accumulator.
        accumulator = (accumulator * r_value) % prime_modulus        # Multiply by r and reduce modulo p.

        message_offset += 16                                         # Move to the next 16-byte block.

    accumulator = (accumulator + s_value) % (1 << 128)               # Add s and truncate to 128 bits.

    authentication_tag = accumulator.to_bytes(16, "little")          # Output the 16-byte authentication tag.
    return authentication_tag


def pad16(data: bytes) -> bytes:
    """
    Pad data with zero bytes until its length is a multiple of 16.
    """
    data_length = len(data)
    remainder = data_length % 16                                     # Check whether the current length is already a multiple of 16.

    if remainder == 0:
        return data                                                  # If already aligned, add no extra padding.

    padding_size = 16 - remainder                                    # Number of zero bytes needed.
    padded_data = data + (b"\x00" * padding_size)                    # Zero-pad to the 16-byte boundary as required by the AEAD format.

    return padded_data


def u64_le(number: int) -> bytes:
    """
    Encode a 64-bit integer as an 8-byte little-endian value.
    """
    return struct.pack("<Q", number)                                 # <Q means unsigned 64-bit little-endian integer.


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    AEAD ChaCha20-Poly1305 encryption function without AAD.

    Inputs:
        key - 32-byte key
        nonce - 12-byte nonce
        plaintext - data to encrypt

    Outputs:
        ciphertext, authentication tag
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")             # AEAD ChaCha20-Poly1305 uses a fixed 32-byte key.

    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")           # The nonce must be exactly 12 bytes.

    poly1305_key = chacha20_block(key, 0, nonce)[:32]                # counter=0 is reserved for generating the Poly1305 one-time key.
    ciphertext = chacha20_crypt(key, nonce, 1, plaintext)            # Actual data encryption starts from counter=1 to avoid reusing counter=0.

    aad = b""                                                        # This script does not use additional authenticated data.

    mac_data = (
        pad16(aad)                                                   # AAD is padded to a 16-byte boundary; here it is empty.
        + pad16(ciphertext)                                          # The ciphertext is padded to a 16-byte boundary before authentication.
        + u64_le(len(aad))                                           # Append the AAD length, as required by the ChaCha20-Poly1305 AEAD format.
        + u64_le(len(ciphertext))                                    # Append the ciphertext length to prevent length-related tampering.
    )

    tag = poly1305_mac(poly1305_key, mac_data)                       # Generate the authentication tag using Poly1305.

    return ciphertext, tag


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    AEAD ChaCha20-Poly1305 decryption function without AAD.

    Inputs:
        key - 32-byte key
        nonce - 12-byte nonce
        ciphertext - encrypted data
        tag - 16-byte authentication tag

    Output:
        plaintext data

    Raises ValueError if authentication fails.
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")             # Keep the same key length requirement as the encryption side.

    if len(nonce) != 12:
        raise ValueError("Nonce length must be 12 bytes.")           # Reject data with an invalid nonce length.

    if len(tag) != 16:
        raise ValueError("Tag length must be 16 bytes.")             # A Poly1305 authentication tag is always 16 bytes.

    poly1305_key = chacha20_block(key, 0, nonce)[:32]                # Regenerate the same Poly1305 one-time key during decryption.

    aad = b""                                                        # This script uses no AAD, so the decryption side must also keep it empty.

    mac_data = (
        pad16(aad)                                                   # AAD authentication portion.
        + pad16(ciphertext)                                          # Ciphertext authentication portion.
        + u64_le(len(aad))                                           # AAD length.
        + u64_le(len(ciphertext))                                    # Ciphertext length.
    )

    calculated_tag = poly1305_mac(poly1305_key, mac_data)            # Recompute the authentication tag.

    if not hmac.compare_digest(calculated_tag, tag):
        raise ValueError("Poly1305 authentication failed!")          # A mismatch means wrong password, corrupted file, or tampering.

    plaintext = chacha20_crypt(key, nonce, 1, ciphertext)            # Decrypt only after authentication succeeds.

    return plaintext


def get_key_from_password() -> bytes:
    """
    Derive a 32-byte key from the user-entered password.

    To keep the original file format unchanged, this script does not write an
    additional salt field. Therefore, it uses PBKDF2-HMAC-SHA256 with a fixed
    salt. This is more robust than directly using sha256(password), while still
    preserving the existing file format:
        nonce(12) || tag(16) || ciphertext
    """
    password = getpass.getpass("Enter password: ")                   # Hide the password input so it is not shown on the terminal.

    if not password:
        raise ValueError("Password must not be empty.")              # Reject empty passwords because they are too weak.

    salt = b"chacha20-poly1305-password-key"                         # Fixed salt: a compromise to keep the old file format unchanged.

    key = hashlib.pbkdf2_hmac(
        "sha256",                                                    # Use HMAC-SHA256 as PBKDF2's underlying pseudorandom function.
        password.encode("utf-8"),                                    # Encode the user password as bytes.
        salt,                                                        # The salt participates in key derivation.
        300000,                                                      # Iteration count; higher values resist brute force better but start slower.
        dklen=32,                                                    # ChaCha20-Poly1305 requires a 32-byte key.
    )

    return key


def encrypt_file(file_path: str, key: bytes):
    """
    Encrypt a single file in place.

    File storage format: nonce(12) || tag(16) || ciphertext
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")       # Only process real files, not directories or invalid paths.

    nonce = os.urandom(12)                                           # A new random nonce must be generated for every encryption operation.

    file_stat_info = os.stat(file_path)                              # Read the original file metadata.
    access_time = file_stat_info.st_atime                            # Preserve the original access time.
    modification_time = file_stat_info.st_mtime                      # Preserve the original modification time.

    with open(file_path, "rb") as input_file:
        plaintext = input_file.read()                                # Read the entire file as plaintext.

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)  # Produce both ciphertext and authentication tag.

    with open(file_path, "wb") as output_file:
        output_file.write(nonce)                                     # Write the 12-byte nonce first; it is required for decryption.
        output_file.write(tag)                                       # Then write the 16-byte authentication tag.
        output_file.write(ciphertext)                                # Finally write the actual ciphertext.
    os.utime(file_path, (access_time, modification_time))            # Restore the original timestamps to minimize metadata changes.


def decrypt_file(file_path: str, key: bytes):
    """
    Decrypt a single file in place.

    Input file format: nonce(12) || tag(16) || ciphertext
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")       # Only decrypt real files.
    file_stat_info = os.stat(file_path)                              # Preserve timestamps before decryption.
    access_time = file_stat_info.st_atime
    modification_time = file_stat_info.st_mtime
    with open(file_path, "rb") as input_file:
        file_content = input_file.read()                             # Read the complete encrypted file content.
    if len(file_content) < 28:
        raise ValueError("File content too short to be valid encrypted file.")  # Minimum size is 12-byte nonce + 16-byte tag.
    nonce = file_content[:12]                                        # The first 12 bytes are the nonce.
    tag = file_content[12:28]                                        # The next 16 bytes are the Poly1305 authentication tag.
    ciphertext = file_content[28:]                                   # The remaining bytes are the ciphertext.
    plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)  # Authenticate first; return plaintext only if authentication succeeds.
    with open(file_path, "wb") as output_file:
        output_file.write(plaintext)                                 # Overwrite the file in place with the decrypted plaintext.
    os.utime(file_path, (access_time, modification_time))            # Restore the timestamps from before decryption.
def encrypt_directory(directory: str, key: bytes):
    """
    Recursively encrypt all files under a directory in place.
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a valid directory: {directory}")  # Confirm that the target is a directory.
    for root_path, subdirectories, file_names in os.walk(directory):  # Recursively traverse the directory tree.
        for file_name in file_names:
            file_path = os.path.join(root_path, file_name)           # Build the full file path.
            try:
                encrypt_file(file_path, key)                         # Encrypt a single file.
                print(f"Encrypted: {file_path}")                     # Print a success log for maintenance and troubleshooting.
            except Exception as error:
                print(f"Encryption failed for {file_path}: {str(error)}")  # One failed file should not stop the rest of the directory.
def decrypt_directory(directory: str, key: bytes):
    """
    Recursively decrypt all files under a directory in place.
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a valid directory: {directory}")  # Confirm that the target is a directory.
    for root_path, subdirectories, file_names in os.walk(directory):  # Recursively traverse the directory tree.
        for file_name in file_names:
            file_path = os.path.join(root_path, file_name)           # Build the full file path.
            try:
                decrypt_file(file_path, key)                         # Decrypt a single file.
                print(f"Decrypted: {file_path}")                     # Print a success log.
            except Exception as error:
                print(f"Decryption failed for {file_path}: {str(error)}")  # Failure usually means wrong password, corrupted file, or a non-encrypted file.
if __name__ == "__main__":
    try:
        key = get_key_from_password()                                # Derive the encryption key from the user password when the program starts.
        if len(key) != 32:
            print("Error: key length must be 32 bytes!")              # Defensive check; PBKDF2 should normally return exactly 32 bytes.
            exit(1)
        target_directory = input("Enter target directory path: ").strip()  # Read the target directory from user input.
        if not os.path.isdir(target_directory):
            print("Error: directory does not exist:", target_directory)  # This script currently processes directories, not single file paths.
            exit(1)
        operation = input("Enter operation type (e: encrypt, d: decrypt): ").strip().lower()  # Normalize user input.
        if operation == "e":
            print("Starting directory encryption:", target_directory)
            encrypt_directory(target_directory, key)                  # Recursively encrypt files in the directory.
            print("Encryption completed")
        elif operation == "d":
            print("Starting directory decryption:", target_directory)
            decrypt_directory(target_directory, key)                  # Recursively decrypt files in the directory.
            print("Decryption completed")
        else:
            print("Error: operation type only supports e (encrypt) or d (decrypt)")  # Reject invalid operation types.
            exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled")                               # Exit cleanly when the user presses Ctrl+C.
        exit(1)
    except Exception as error:
        print("Error:", str(error))                                  # Catch unexpected errors without showing a full traceback to regular users.
        exit(1)
