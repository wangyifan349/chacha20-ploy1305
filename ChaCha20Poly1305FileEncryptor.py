import os
import json
import base58
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from concurrent.futures import ThreadPoolExecutor, as_completed

def b58encode(data_bytes):
    return base58.b58encode(data_bytes).decode('utf-8')  # Encode bytes to base58 string

def b58decode(data_str):
    return base58.b58decode(data_str.encode('utf-8'))  # Decode base58 string to bytes

def derive_key(password_str, salt_bytes = b'somesaltvalue', iteration_count = 10000, key_length = 16):
    """
    Use PBKDF2 HMAC SHA256 to derive a key from password string.
    """
    key_bytes = hashlib.pbkdf2_hmac('sha256', password_str.encode('utf-8'), salt_bytes, iteration_count, key_length)  # Derive key with PBKDF2
    return key_bytes

def encrypt_file(file_path, key_bytes):
    with open(file_path, 'rb') as file_reader:
        plaintext_bytes = file_reader.read()  # Read file data
    cipher = ChaCha20_Poly1305.new(key=key_bytes)  # Create cipher object
    ciphertext_bytes, tag_bytes = cipher.encrypt_and_digest(plaintext_bytes)  # Encrypt and get tag
    result_dict = {
        'nonce': b58encode(cipher.nonce),                  # Encode nonce
        'ciphertext': b58encode(ciphertext_bytes),         # Encode ciphertext
        'tag': b58encode(tag_bytes),                        # Encode tag
    }
    return result_dict  # Return dict with encrypted data

def decrypt_file(encrypted_dict, file_path, key_bytes):
    nonce_bytes = b58decode(encrypted_dict['nonce'])       # Decode nonce
    ciphertext_bytes = b58decode(encrypted_dict['ciphertext'])  # Decode ciphertext
    tag_bytes = b58decode(encrypted_dict['tag'])            # Decode tag
    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)  # Create cipher object with nonce
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)  # Decrypt and verify tag
    with open(file_path, 'wb') as file_writer:
        file_writer.write(plaintext_bytes)  # Write decrypted data to file

def scan_files(directory_path):
    file_paths = []
    for current_dir_path, directories, filenames in os.walk(directory_path):
        for filename in filenames:
            absolute_path = os.path.join(current_dir_path, filename)  # Absolute path of file
            relative_path = os.path.relpath(absolute_path, directory_path)  # Relative path from root
            file_paths.append(relative_path)  # Collect relative path
    return file_paths  # Return list of file relative paths

def encrypt_worker(arguments):
    relative_path, root_directory, key_bytes = arguments
    absolute_path = os.path.join(root_directory, relative_path)  # Absolute file path
    encrypted_result = encrypt_file(absolute_path, key_bytes)  # Encrypt file content
    with open(absolute_path, 'wb') as file_writer:
        file_writer.write(b'')  # Overwrite original file with empty content
    return relative_path, encrypted_result  # Return path and encrypted data

def decrypt_worker(arguments):
    relative_path, encrypted_dict, root_directory, key_bytes = arguments
    absolute_path = os.path.join(root_directory, relative_path)  # Absolute file path
    folder_path = os.path.dirname(absolute_path)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path, exist_ok=True)  # Create directories if missing
    decrypt_file(encrypted_dict, absolute_path, key_bytes)  # Decrypt data and write file
    return relative_path  # Return file path

def main():
    import getpass
    import sys

    mode_input = input("Choose operation mode encrypt or decrypt: ").strip().lower()  # Get mode input
    if mode_input != 'encrypt' and mode_input != 'decrypt':  
        print("Invalid mode input. Please enter encrypt or decrypt.")  # Validate mode
        sys.exit(1)

    directory_input = input("Enter directory path to scan: ").strip()  # Get root directory
    if not os.path.isdir(directory_input):
        print("Given directory does not exist.")  # Validate directory exists
        sys.exit(1)

    json_file_input = input("Enter JSON file path to read or save encrypted data: ").strip()  # JSON path

    password_input = getpass.getpass("Enter your password (will be used to derive 16 byte key): ")  # Get password securely
    key_bytes = derive_key(password_input)  # Derive key with PBKDF2
    print("Key derived successfully. Key length is: {} bytes".format(len(key_bytes)))  # Inform key length

    thread_count = min(32, (os.cpu_count() or 1) + 4)  # Determine thread count to use

    if mode_input == 'encrypt':
        file_list = scan_files(directory_input)  # Get all files to encrypt
        encrypted_results = dict()
        print("Starting encryption of {} files using {} threads...".format(len(file_list), thread_count))

        executor = ThreadPoolExecutor(max_workers=thread_count)  # Create thread pool
        future_list = []
        for file_relative_path in file_list:
            arguments = (file_relative_path, directory_input, key_bytes)  # Prepare arguments tuple
            future = executor.submit(encrypt_worker, arguments)  # Submit encrypt task
            future_list.append(future)

        for future in as_completed(future_list):
            relative_path_result, encrypted_data_result = future.result()  # Wait for results
            encrypted_results[relative_path_result] = encrypted_data_result  # Collect encrypted data

        executor.shutdown(wait=True)  # Shutdown thread pool

        with open(json_file_input, 'w', encoding='utf-8') as json_writer:
            json.dump(encrypted_results, json_writer, indent=4, ensure_ascii=False)  # Write JSON results
        print("Encryption complete. Results saved to {}".format(json_file_input))

    else:
        if not os.path.isfile(json_file_input):
            print("JSON file for encrypted data does not exist: {}".format(json_file_input))  # Check file
            sys.exit(1)

        with open(json_file_input, 'r', encoding='utf-8') as json_reader:
            encrypted_results = json.load(json_reader)  # Load JSON encrypted data

        print("Starting decryption of {} files using {} threads...".format(len(encrypted_results), thread_count))

        executor = ThreadPoolExecutor(max_workers=thread_count)  # Thread pool for decrypt
        future_list = []
        for file_relative_path in encrypted_results:
            encrypted_data_item = encrypted_results[file_relative_path]
            arguments = (file_relative_path, encrypted_data_item, directory_input, key_bytes)  # Arguments tuple
            future = executor.submit(decrypt_worker, arguments)  # Submit decrypt task
            future_list.append(future)

        for future in as_completed(future_list):
            _ = future.result()  # Wait for decrypt results

        executor.shutdown(wait=True)  # Shutdown thread pool

        print("Decryption complete. All files restored successfully.")

if __name__ == '__main__':
    main()
