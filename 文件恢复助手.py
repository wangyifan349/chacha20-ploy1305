import os
import sys
import platform

READ_BLOCK_SIZE = 1024 * 1024  # 每次读取1MB数据

FILE_SIGNATURES = {
    "jpg": {"header": b"\xFF\xD8\xFF", "footer": b"\xFF\xD9"},  # JPEG 文件头尾
    "png": {"header": b"\x89PNG\r\n\x1A\n", "footer": b"\x49\x45\x4E\x44\xAE\x42\x60\x82"},  # PNG 文件头尾
    "pdf": {"header": b"%PDF-", "footer": b"%%EOF"},  # PDF 文件头尾
    "gif": {"header": b"GIF87a", "footer": b"\x3B"},  # GIF87a 文件头尾
    "gif89a": {"header": b"GIF89a", "footer": b"\x3B"}  # GIF89a 文件头尾
}

def find_all(data, sub):
    positions = []  # 记录所有匹配位置
    start = 0
    while True:
        pos = data.find(sub, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions

def sizeof_fmt(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Y{suffix}"

def list_disks():
    system = platform.system()
    disks = []
    if system == "Windows":
        import ctypes  # ctypes调用Windows API
        from ctypes import wintypes, windll

        # 检测PhysicalDrive0~9设备是否存在
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = -1

        CreateFile = windll.kernel32.CreateFileW
        CloseHandle = windll.kernel32.CloseHandle

        for i in range(10):
            path = f"\\\\.\\PhysicalDrive{i}"  # Windows物理磁盘设备路径
            handle = CreateFile(path,
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                None,
                                OPEN_EXISTING,
                                0,
                                None)
            if handle != INVALID_HANDLE_VALUE:
                disks.append(path)
                CloseHandle(handle)
    elif system == "Linux":
        # 读取/dev目录下的sd*和nvme*设备名
        dev_dir = "/dev"
        try:
            for d in os.listdir(dev_dir):
                if d.startswith("sd") or d.startswith("nvme"):
                    full_path = os.path.join(dev_dir, d)
                    if os.path.exists(full_path):
                        disks.append(full_path)
        except PermissionError:
            print("权限不足，不能访问 /dev 目录。请使用root权限运行。")
    else:
        print(f"未支持的平台: {system}")
    disks = list(set(disks))  # 去重
    disks.sort()
    return disks

def get_file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0

def recover_files(device_path):
    print(f"开始扫描恢复设备/文件：{device_path}")
    try:
        total_size = get_file_size(device_path)
        if total_size > 0:
            print(f"设备/文件大小: {sizeof_fmt(total_size)}")
        else:
            print("设备大小未知或无法获取。")

        file_count = 0
        offset = 0
        partial_data = b""
        max_header_len = max(len(s["header"]) for s in FILE_SIGNATURES.values())

        with open(device_path, "rb", buffering=0) as f:
            while True:
                chunk = f.read(READ_BLOCK_SIZE)
                if not chunk:
                    break
                data = partial_data + chunk

                for ftype, sig in FILE_SIGNATURES.items():
                    headers = find_all(data, sig["header"])
                    footer = sig["footer"]
                    for start_pos in headers:
                        search_start = start_pos + len(sig["header"])
                        footer_pos = data.find(footer, search_start)
                        if footer_pos == -1:
                            continue
                        end_pos = footer_pos + len(footer)
                        recovered = data[start_pos:end_pos]

                        filename = f"recovered_{file_count}.{ftype}"
                        with open(filename, "wb") as out_f:
                            out_f.write(recovered)
                        abs_offset = offset - len(partial_data) + start_pos
                        print(f"恢复文件：{filename}，偏移：{abs_offset}，大小：{sizeof_fmt(len(recovered))}")
                        file_count += 1

                        # 用零替换，避免重复扫描
                        data = data[:start_pos] + b"\x00" * (end_pos - start_pos) + data[end_pos:]

                partial_data = data[-max_header_len:]
                offset += len(chunk)

        print(f"\n恢复完成，共恢复文件数：{file_count}")
    except PermissionError:
        print("权限不足，无法访问设备或文件。请以管理员权限/Root权限运行。")
    except FileNotFoundError:
        print("指定设备或文件未找到，请检查路径是否正确。")
    except Exception as e:
        print("发生错误:", str(e))

def main():
    print("=== 简易文件恢复工具 ===\n")
    disks = list_disks()
    if not disks:
        print("未检测到可用磁盘设备，您也可以输入磁盘镜像文件路径进行恢复。")  # 无设备时提示手动输入
    else:
        print("检测到以下磁盘设备:")
        for i, d in enumerate(disks):
            print(f"[{i}] {d}")
        print("[m] 手动输入磁盘或镜像文件路径")

    choice = input("\n请输入编号选择磁盘，或输入路径手动指定文件：").strip()

    if choice.lower() == 'm':
        path = input("请输入磁盘设备路径或磁盘镜像文件路径：").strip()
    else:
        try:
            idx = int(choice)
            if idx < 0 or idx >= len(disks):
                print("选择编号超出范围。")
                return
            path = disks[idx]
        except Exception:
            print("输入无效，请输入编号或路径。")
            return

    print(f"\n选中设备/文件：{path}")
    confirm = input("确认开始扫描恢复？此操作可能耗时且不可中断。 (y/n): ").strip().lower()
    if confirm != 'y':
        print("用户取消操作。")
        return

    recover_files(path)

if __name__ == "__main__":
    main()
