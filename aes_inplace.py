#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版：AES-GCM 文件批量加/解密工具
特点：
 - PBKDF2 默认高迭代（200k），可配置
 - 支持备份（.bak 或专用目录）
 - 更稳健的并发与错误处理
 - dry-run, include/exclude glob, filesize threshold for streaming
 - 日志与进度显示（可选 tqdm）
 - 加密文件包含 version 字段与字段校验
"""
from __future__ import annotations
import os
import sys
import json
import argparse
import fnmatch
import getpass
import shutil
import stat
import logging
from pathlib import Path
from typing import Optional, Iterable, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# 可选依赖：tqdm（进度条），pip install tqdm
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# ---- 默认配置 ----
DEFAULT_PBKDF2_ITER = 200_000  # 安全起见提高迭代次数
KEY_LEN     = 32               # AES-256
SALT_LEN    = 16
NONCE_LEN   = 12               # GCM 推荐 12 字节
TAG_LEN     = 16
MAGIC       = "duckaes"        # 文件魔数/标识
VERSION     = "1.1"            # 文件格式版本

# ---- 日志 ----
logger = logging.getLogger("duck_aes")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---- 辅助函数 ----
def encode_b58(b: bytes) -> str:
    import base58
    return base58.b58encode(b).decode("ascii")

def decode_b58(s: str) -> bytes:
    import base58
    return base58.b58decode(s.encode("ascii"))

def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITER) -> bytes:
    """使用 PBKDF2-HMAC-SHA1（PyCrypto 的 PBKDF2），可配置 iterations"""
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=iterations)

def safe_set_permissions(path: Path) -> None:
    """
    将文件权限设为 0o600（仅属主读写），不过保留 umask 兼容
    """
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logger.debug("设置文件权限失败：%s", e)

def is_encrypted_file(path: Path) -> bool:
    """更严格的判断：文件是可解析 JSON，且包含 magic/version/salt/nonce/ciphertext/tag"""
    try:
        txt = path.read_text(encoding="utf-8")
        obj = json.loads(txt)
        required = {"magic", "version", "salt", "nonce", "ciphertext", "tag"}
        if not required.issubset(obj.keys()):
            return False
        # magic 校验
        return obj.get("magic") == MAGIC
    except Exception:
        return False

# ---- 文件操作：备份、流式读写 ----
def make_backup(path: Path, backup_dir: Optional[Path] = None) -> Path:
    """
    备份原文件：
     - 如果 backup_dir 指定，复制到该目录（保留相对路径）
     - 否则在同目录创建 file.bak<N>（避免覆盖）
    返回备份文件路径
    """
    if backup_dir:
        # 在备份目录内创建相对路径
        rel = path.resolve().relative_to(Path.cwd().resolve())
        dest = (backup_dir / rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        return dest
    else:
        # 自动编号 .bak, .bak1 ...
        i = 0
        while True:
            suffix = ".bak" if i == 0 else f".bak{i}"
            dest = path.with_name(path.name + suffix)
            if not dest.exists():
                shutil.copy2(path, dest)
                return dest
            i += 1

def atomic_write_bytes(path: Path, data: bytes) -> None:
    """
    原子写入：先写临时文件，再重命名
    """
    tmp = path.with_suffix(path.suffix + ".tmp_duckaes")
    tmp.write_bytes(data)
    os.replace(tmp, path)  # 原子替换
    safe_set_permissions(path)

# ---- 加解密实现 ----
def encrypt_bytes(data: bytes, password: str, iterations: int) -> dict:
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt, iterations)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "magic": MAGIC,
        "version": VERSION,
        "salt": encode_b58(salt),
        "nonce": encode_b58(nonce),
        "ciphertext": encode_b58(ciphertext),
        "tag": encode_b58(tag)
    }

def decrypt_record(rec: dict, password: str, iterations: int) -> bytes:
    # 验证字段
    for fld in ("salt", "nonce", "ciphertext", "tag"):
        if fld not in rec:
            raise ValueError(f"缺少字段 {fld}")
    salt = decode_b58(rec["salt"])
    nonce = decode_b58(rec["nonce"])
    ciphertext = decode_b58(rec["ciphertext"])
    tag = decode_b58(rec["tag"])
    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---- 单文件处理（含备份与错误处理） ----
def encrypt_file(file_path: Path, password: str, iterations: int,
                 backup: bool = True, backup_dir: Optional[Path] = None,
                 inplace: bool = True) -> None:
    logger.debug("Encrypting %s", file_path)
    # 读取（对小文件一次性读入）
    data = file_path.read_bytes()
    rec = encrypt_bytes(data, password, iterations)
    json_txt = json.dumps(rec, ensure_ascii=False)
    if backup:
        bpath = make_backup(file_path, backup_dir)
        logger.info("Backup created: %s", bpath)
    if inplace:
        # 原子替换写回
        atomic_write_bytes(file_path, json_txt.encode("utf-8"))
        logger.info("Encrypted: %s", file_path)
    else:
        # 写到 .enc 或其他
        out = file_path.with_suffix(file_path.suffix + ".enc")
        atomic_write_bytes(out, json_txt.encode("utf-8"))
        logger.info("Encrypted -> %s", out)

def decrypt_file(file_path: Path, password: str, iterations: int,
                 backup: bool = True, backup_dir: Optional[Path] = None,
                 inplace: bool = True) -> None:
    logger.debug("Decrypting %s", file_path)
    txt = file_path.read_text(encoding="utf-8")
    rec = json.loads(txt)
    if rec.get("magic") != MAGIC:
        raise ValueError("文件 magic mismatch")
    # 先备份加密文件（以防解密失败）
    if backup:
        bpath = make_backup(file_path, backup_dir)
        logger.info("Encrypted backup: %s", bpath)
    # 解密并写回
    plain = decrypt_record(rec, password, iterations)
    if inplace:
        atomic_write_bytes(file_path, plain)
        logger.info("Decrypted: %s", file_path)
    else:
        out = file_path.with_suffix(file_path.suffix + ".dec")
        atomic_write_bytes(out, plain)
        logger.info("Decrypted -> %s", out)

# ---- 遍历与并行 ----
def gather_files(root: Path, include: Optional[List[str]] = None,
                 exclude: Optional[List[str]] = None, recursive: bool = True) -> List[Path]:
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for nm in filenames:
            p = Path(dirpath) / nm
            # 排除备份临时或 .tmp_duckaes
            if p.name.endswith(".tmp_duckaes"):
                continue
            if exclude and any(fnmatch.fnmatch(p.name, pat) for pat in exclude):
                continue
            if include:
                if any(fnmatch.fnmatch(p.name, pat) for pat in include):
                    files.append(p)
            else:
                files.append(p)
        if not recursive:
            break
    return files

def process_files(file_list: List[Path], password: str, iterations: int, mode: str,
                  workers: int, backup: bool, backup_dir: Optional[Path], inplace: bool,
                  dry_run: bool = False, show_progress: bool = False) -> None:
    logger.info("Mode=%s files=%d workers=%d dry_run=%s", mode, len(file_list), workers, dry_run)
    if show_progress and tqdm and len(file_list) > 0:
        pbar = tqdm(total=len(file_list), desc=mode)
    else:
        pbar = None

    def worker(fp: Path):
        try:
            if dry_run:
                logger.info("[DRY] Would %s: %s", mode, fp)
                return
            if mode == "encrypt":
                if is_encrypted_file(fp):
                    logger.debug("Skip already encrypted: %s", fp)
                    return
                encrypt_file(fp, password, iterations, backup=backup, backup_dir=backup_dir, inplace=inplace)
            else:
                if not is_encrypted_file(fp):
                    logger.debug("Skip non-encrypted: %s", fp)
                    return
                decrypt_file(fp, password, iterations, backup=backup, backup_dir=backup_dir, inplace=inplace)
        except Exception as e:
            logger.error("Error processing %s: %s", fp, e)
            raise
        finally:
            if pbar:
                pbar.update(1)

    # 并发
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=("EncW" if mode=="encrypt" else "DecW")) as pool:
        futures = [pool.submit(worker, f) for f in file_list]
        for fut in as_completed(futures):
            # 若发生异常会在这里重新抛出，便于上层处理或日志抓取
            fut.result()
    if pbar:
        pbar.close()
    logger.info("%s complete.", mode.capitalize())

# ---- CLI / 交互 ----
def prompt_password() -> (str,):
    pw = getpass.getpass("请输入密码（不会回显）: ")
    if not pw:
        raise ValueError("密码不能为空")
    pw2 = getpass.getpass("请再次确认密码: ")
    if pw != pw2:
        raise ValueError("两次密码不一致")
    return pw

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AES-GCM 批量加/解密工具（增强版）")
    p.add_argument("path", nargs="?", default=".", help="要处理的目录（默认当前目录）")
    p.add_argument("--mode", choices=("encrypt", "decrypt"), required=False, help="操作模式")
    p.add_argument("--workers", type=int, default=4, help="并发线程数（默认4）")
    p.add_argument("--iter", type=int, default=DEFAULT_PBKDF2_ITER, help=f"PBKDF2 迭代次数（默认{DEFAULT_PBKDF2_ITER}）")
    p.add_argument("--no-backup", action="store_true", help="不要创建备份（危险）")
    p.add_argument("--backup-dir", type=str, default=None, help="备份目录（相对/绝对）")
    p.add_argument("--include", nargs="*", help="包含 glob 模式，例如 '*.txt' 'data/*.bin'")
    p.add_argument("--exclude", nargs="*", help="排除 glob 模式")
    p.add_argument("--dry-run", action="store_true", help="演习模式，只列出不执行")
    p.add_argument("--inplace", action="store_true", help="就地替换（默认开启）")
    p.add_argument("--no-progress", action="store_true", help="禁用进度条")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"], help="日志级别")
    p.add_argument("--yes", action="store_true", help="跳过交互确认")
    return p

def interactive_confirm(args: argparse.Namespace) -> None:
    # 若缺少 mode，则交互选择
    if not args.mode:
        mode = input("请选择操作 (encrypt/decrypt): ").strip().lower()
        if mode not in ("encrypt","decrypt"):
            raise SystemExit("操作必须是 encrypt 或 decrypt，退出。")
        args.mode = mode
    # 确认路径
    root = Path(args.path)
    if not root.exists():
        raise SystemExit("错误：路径不存在，退出。")
    # 备份目录
    bdir = Path(args.backup_dir) if args.backup_dir else None
    if bdir and not bdir.exists():
        bdir.mkdir(parents=True, exist_ok=True)
    # 确认
    if not args.yes:
        print(f"即将对目录: {root.resolve()}")
        print(f"模式: {args.mode}, 线程: {args.workers}, 迭代: {args.iter}, 备份: {not args.no_backup}")
        ok = input("确认继续? (yes/no): ").strip().lower()
        if ok not in ("y","yes"):
            raise SystemExit("已取消。")
    return

def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    # 日志级别
    logger.setLevel(getattr(logging, args.log_level))

    try:
        interactive_confirm(args)
    except SystemExit as e:
        logger.error(e)
        return

    # 密码获取
    try:
        password = prompt_password()
    except Exception as e:
        logger.error("密码输入失败: %s", e)
        return

    root = Path(args.path)
    include = args.include
    exclude = args.exclude

    files = gather_files(root, include=include, exclude=exclude)
    if not files:
        logger.info("未找到匹配文件，退出。")
        return

    # 过滤：encrypt 模式时跳过已经加密文件；decrypt 模式时只保留加密文件
    if args.mode == "encrypt":
        files = [f for f in files if not is_encrypted_file(f)]
    else:
        files = [f for f in files if is_encrypted_file(f)]
    if not files:
        logger.info("无需处理的文件，退出。")
        return

    # 执行
    try:
        process_files(
            file_list=files,
            password=password,
            iterations=args.iter,
            mode=args.mode,
            workers=args.workers,
            backup=(not args.no_backup),
            backup_dir=(Path(args.backup_dir) if args.backup_dir else None),
            inplace=args.inplace,
            dry_run=args.dry_run,
            show_progress=(not args.no_progress)
        )
    except Exception as e:
        logger.error("处理过程中发生异常: %s", e)
        return

if __name__ == "__main__":
    main()
