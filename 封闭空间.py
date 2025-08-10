import os
import sys
import pickle
from glob import glob
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# 支持的扩展名
TEXT_EXT = ['.txt', '.md', '.rtf']
IMAGE_EXT = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']
VIDEO_EXT = ['.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv']

def load_or_create_key(path: str) -> bytes:
    if os.path.exists(path):
        return open(path, 'rb').read()
    key = get_random_bytes(32)
    with open(path, 'wb') as f:
        f.write(key)
    return key

def collect_files(src_dir: str) -> dict:
    data = {}
    for ext in TEXT_EXT + IMAGE_EXT + VIDEO_EXT:
        pattern = os.path.join(src_dir, '**', f'*{ext}')
        for filepath in glob(pattern, recursive=True):
            rel = os.path.relpath(filepath, src_dir)
            with open(filepath, 'rb') as f:
                data[rel] = f.read()
    return data

def commit_data(data: dict, key: bytes, vault_path: str):
    plaintext = pickle.dumps(data)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(vault_path, 'wb') as f:
        f.write(nonce + tag + ciphertext)

def load_data(key: bytes, vault_path: str) -> dict:
    blob = open(vault_path, 'rb').read()
    nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return pickle.loads(plaintext)

def encrypt_flow():
    src = input("请输入要加密的目录路径：").strip()
    if not os.path.isdir(src):
        print("输入路径不存在或不是目录。")
        sys.exit(1)
    vault = input("请输入输出的容器文件名（例如 vault.bin）：").strip()
    keyfile = input("请输入或创建密钥文件名（例如 vault.key）：").strip()

    key = load_or_create_key(keyfile)
    files_dict = collect_files(src)
    if not files_dict:
        print("未找到任何符合条件的文件。")
        sys.exit(1)

    commit_data(files_dict, key, vault)
    print(f"已生成加密容器：{vault}，共包含 {len(files_dict)} 个文件。")

def decrypt_flow():
    vault = input("请输入要解密的容器文件名：").strip()
    if not os.path.isfile(vault):
        print("容器文件不存在。")
        sys.exit(1)
    keyfile = input("请输入密钥文件名：").strip()
    if not os.path.isfile(keyfile):
        print("密钥文件不存在。")
        sys.exit(1)
    outdir = input("请输入解密后文件输出目录：").strip()
    os.makedirs(outdir, exist_ok=True)

    key = open(keyfile, 'rb').read()
    files_dict = load_data(key, vault)
    for rel, content in files_dict.items():
        dest = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(content)
    print(f"已解密并恢复 {len(files_dict)} 个文件 到：{outdir}")

def main():
    print("请选择操作模式：\n  1. 加密目录 → 容器\n  2. 解密容器 → 目录")
    choice = input("输入 1 或 2：").strip()
    if choice == '1':
        encrypt_flow()
    elif choice == '2':
        decrypt_flow()
    else:
        print("无效选择。")

if __name__ == '__main__':
    main()
