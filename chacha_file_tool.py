"""
本脚本用于对指定目录下的文件执行 ChaCha20-Poly1305 批量加密或解密操作。程序使用用户输入的密码配合
PBKDF2-HMAC-SHA256 派生 32 字节密钥，并为每个文件单独生成 salt 和 nonce。加密后的数据会在文件头中写入
魔术头、迭代次数、salt 和 nonce，以便后续解密时恢复所需参数；解密时会先检查魔术头，仅处理由本程序生成的
加密文件，普通文件会自动跳过。

脚本采用 os.walk 递归收集目录中的普通文件，并通过 ThreadPoolExecutor 对多个文件进行并发处理，以提高批量
任务的执行效率。所有处理均为原地覆盖写回，不额外生成输出目录，也不修改文件名；写入阶段通过“临时文件 +
os.replace()”的方式完成替换，以降低处理中断或写入失败时造成文件损坏的风险。
"""

import os                                                  # 文件与系统操作
import sys                                                 # 程序退出
import struct                                              # 打包/解析二进制头
import tempfile                                            # 临时文件，保证原子覆盖
import getpass                                             # 读取密码且不回显
from pathlib import Path                                   # 路径处理
from concurrent.futures import ThreadPoolExecutor, as_completed  # 多线程批量处理

from cryptography.exceptions import InvalidTag             # AEAD 认证失败异常
from cryptography.hazmat.primitives import hashes          # PBKDF2 所需哈希算法
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # AEAD 算法
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC          # 密码派生

MAGIC = b"CCP3HDR1"                                        # 魔术头，用于识别本程序加密文件
KEY_SIZE = 32                                              # ChaCha20-Poly1305 密钥长度
SALT_SIZE = 16                                             # PBKDF2 salt 长度
NONCE_SIZE = 12                                            # ChaCha20-Poly1305 nonce 长度
TAG_SIZE = 16                                              # Poly1305 tag 长度
DEFAULT_ITERATIONS = 600_000                               # 默认 PBKDF2 迭代次数
DEFAULT_WORKERS = min(32, (os.cpu_count() or 1) * 2)       # 默认线程数
HEADER_SIZE = len(MAGIC) + 4 + SALT_SIZE + NONCE_SIZE      # MAGIC + iterations + salt + nonce
MIN_ENCRYPTED_SIZE = HEADER_SIZE + TAG_SIZE                # 最小加密文件长度


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """用密码派生出 32 字节对称密钥"""                   # 不直接把密码当 key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),                         # PBKDF2 使用 SHA-256
        length=KEY_SIZE,                                   # 输出 32 字节
        salt=salt,                                         # 每个文件单独 salt
        iterations=iterations,                             # 迭代次数可由用户输入
    )
    return kdf.derive(password.encode("utf-8"))            # 派生字节密钥


def encrypt_bytes(data: bytes, password: str, iterations: int) -> bytes:
    """加密字节数据并返回完整文件内容"""                  # 输出会写回原文件
    salt = os.urandom(SALT_SIZE)                           # 生成随机 salt
    nonce = os.urandom(NONCE_SIZE)                         # 生成随机 nonce
    key = derive_key(password, salt, iterations)           # 从密码派生 key
    cipher = ChaCha20Poly1305(key)                         # 创建 ChaCha20-Poly1305 对象
    ct = cipher.encrypt(nonce, data, None)                 # AAD 传 None，返回 ciphertext||tag
    header = (
        MAGIC                                              # 魔术头
        + struct.pack(">I", iterations)                    # 4 字节保存迭代次数
        + salt                                             # 保存 salt，解密时需要
        + nonce                                            # 保存 nonce，解密时需要
    )
    return header + ct                                     # 拼成最终文件内容


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """解密 encrypt_bytes() 生成的字节数据"""             # 仅处理带 MAGIC 的数据
    if len(blob) < MIN_ENCRYPTED_SIZE:
        raise ValueError("文件长度不足，不是有效加密文件")   # 长度检查
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("文件头不匹配，这不是本程序加密的文件")  # 魔术头检查
    offset = len(MAGIC)                                    # 从 MAGIC 后面开始解析
    iterations = struct.unpack(">I", blob[offset:offset + 4])[0]
    offset += 4
    if iterations <= 0:
        raise ValueError("文件中的迭代次数无效")             # 防止解析出脏值
    salt = blob[offset:offset + SALT_SIZE]                 # 提取 salt
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]               # 提取 nonce
    offset += NONCE_SIZE
    ct = blob[offset:]                                     # 剩余部分是 ciphertext||tag
    key = derive_key(password, salt, iterations)           # 重新派生 key
    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(nonce, ct, None)             # 解密并验证 tag
    except InvalidTag as e:
        raise ValueError("解密失败：密码错误，或文件已损坏/被篡改") from e


def has_magic_header(path: Path) -> bool:
    """判断文件是否带本程序的魔术头"""                   # 只在解密模式使用
    try:
        with path.open("rb") as f:
            head = f.read(len(MAGIC))                      # 仅读取头部几字节
        return head == MAGIC
    except OSError:
        return False


def atomic_overwrite(path: Path, data: bytes) -> None:
    """通过临时文件 + replace 原地覆盖"""                # 比直接写更稳
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",                           # 临时文件名前缀
        suffix=".tmp",                                     # 临时文件后缀
        dir=str(path.parent),                              # 放到原目录，便于原子替换
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)                                  # 先写临时文件
            f.flush()                                      # 刷缓冲区
            os.fsync(f.fileno())                           # 尽量落盘
        try:
            st = path.stat()                               # 尝试继承原文件权限
            os.chmod(tmp_path, st.st_mode)
        except OSError:
            pass
        os.replace(tmp_path, path)                         # 原子替换原文件
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()                          # 异常时清理临时文件
        except OSError:
            pass
        raise


def process_one_file(path: Path, password: str, mode: str, iterations: int):
    """处理单个文件，供线程池调用"""                   # 返回 (状态, 路径, 信息)
    data = path.read_bytes()                               # 整个文件读入内存

    if mode == "encrypt":
        new_data = encrypt_bytes(data, password, iterations)   # 加密时不判断，直接执行
        atomic_overwrite(path, new_data)                       # 覆盖原文件
        return "ok", str(path), "加密成功"
    if not has_magic_header(path):
        return "skip", str(path), "不是本程序加密文件，跳过"    # 仅解密时判断魔术头
    new_data = decrypt_bytes(data, password)                  # 解密文件内容
    atomic_overwrite(path, new_data)                          # 覆盖原文件
    return "ok", str(path), "解密成功"


def collect_files_with_os_walk(src_dir: Path):
    """使用 os.walk 收集目录下所有普通文件"""           # 保留 os.walk 方式
    files = []
    for root, _, names in os.walk(src_dir):
        root_path = Path(root)
        for name in names:
            file_path = root_path / name
            if file_path.is_file():
                files.append(file_path)
    return files


def process_directory(src_dir: Path, password: str, mode: str, iterations: int, max_workers: int):
    """批量处理目录中的文件"""                           # 多线程并发处理
    files = collect_files_with_os_walk(src_dir)              # 先收集文件列表
    ok = 0
    skip = 0
    failed = 0
    errors = []
    if not files:
        return {"total": 0, "ok": 0, "skip": 0, "failed": 0, "errors": []}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_one_file, path, password, mode, iterations): path
            for path in files
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                status, file_name, message = future.result()
                if status == "ok":
                    ok += 1
                    print(f"[OK]   {file_name}  {message}")
                else:
                    skip += 1
                    print(f"[SKIP] {file_name}  {message}")
            except Exception as e:
                failed += 1
                errors.append((str(path), str(e)))
                print(f"[ERR]  {path}  {e}")

    return {
        "total": len(files),
        "ok": ok,
        "skip": skip,
        "failed": failed,
        "errors": errors,
    }


def ask_non_empty(prompt: str) -> str:
    """读取非空输入"""                                   # 输入为空直接退出
    value = input(prompt).strip()
    if not value:
        raise SystemExit("输入不能为空，程序结束。")
    return value


def parse_mode(raw: str) -> str:
    """解析模式输入"""                                   # 支持中英文和缩写
    text = raw.strip().lower()
    if text in {"encrypt", "enc", "e", "加密"}:
        return "encrypt"
    if text in {"decrypt", "dec", "d", "解密"}:
        return "decrypt"
    raise SystemExit("模式无效，只能输入 encrypt/decrypt 或 加密/解密。")


def parse_positive_int(raw: str, default_value: int, field_name: str) -> int:
    """解析正整数，可直接回车用默认值"""                 # 用于线程数与迭代次数
    text = raw.strip()
    if not text:
        return default_value
    try:
        value = int(text)
    except ValueError:
        raise SystemExit(f"{field_name} 必须是整数。")
    if value <= 0:
        raise SystemExit(f"{field_name} 必须大于 0。")
    return value


def run_once():
    """执行一次加密/解密任务"""                         # 原 main() 的主体逻辑挪到这里
    print("=== ChaCha20-Poly1305 原地批量处理工具 ===")   # 单次任务启动提示

    mode = parse_mode(ask_non_empty("请选择模式 [encrypt/decrypt 或 加密/解密]: "))
    src_dir = Path(ask_non_empty("请输入处理目录: ")).expanduser().resolve()
    password = getpass.getpass("请输入密码: ")            # 密码不回显
    if not password:
        raise SystemExit("密码不能为空，程序结束。")

    iterations = parse_positive_int(
        input(f"请输入密码迭代次数(直接回车默认 {DEFAULT_ITERATIONS}): "),
        DEFAULT_ITERATIONS,
        "迭代次数",
    )
    workers = parse_positive_int(
        input(f"请输入线程数(直接回车默认 {DEFAULT_WORKERS}): "),
        DEFAULT_WORKERS,
        "线程数",
    )
    if not src_dir.exists() or not src_dir.is_dir():
        raise SystemExit(f"目录不存在或不是目录: {src_dir}")
    print()
    print(f"模式: {mode}")                                # 展示当前参数
    print(f"目录: {src_dir}")
    print(f"密码迭代次数: {iterations}")
    print(f"线程数: {workers}")
    print("开始处理...\n")

    result = process_directory(
        src_dir=src_dir,
        password=password,
        mode=mode,
        iterations=iterations,
        max_workers=workers,
    )

    print("\n=== 处理完成 ===")
    print(f"扫描文件数: {result['total']}")
    print(f"成功: {result['ok']}")
    print(f"跳过: {result['skip']}")
    print(f"失败: {result['failed']}")

    if result["errors"]:
        print("\n错误明细:")
        for file_name, err in result["errors"]:
            print(f"  - {file_name}: {err}")

def main():
    """主菜单循环"""                                     # 处理完成后回到这里
    while True:
        print("\n=== 主菜单 ===")                         # 主菜单标题
        print("1. 执行加密/解密")                         # 菜单项 1
        print("2. 退出程序")                              # 菜单项 2
        choice = input("请输入选项(1/2): ").strip()      # 读取用户选择
        if choice == "1":
            print()                                       # 菜单和任务之间空一行
            run_once()                                    # 执行一次任务，完成后自动回到主菜单
        elif choice == "2":
            print("程序已退出。")                         # 退出提示
            break
        else:
            print("无效选项，请重新输入。")               # 非法输入提示

if __name__ == "__main__":
    try:
        main()                                            # 启动主菜单
    except KeyboardInterrupt:
        print("\n用户中断。")
        sys.exit(1)
