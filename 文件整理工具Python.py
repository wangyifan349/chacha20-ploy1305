import os  # 提供文件和目录操作功能
import hashlib  # 提供哈希算法，用于文件重复判断
import shutil  # 提供文件移动和复制功能

root_dir = input("请输入要整理的目录路径: ").strip()  # 用户输入待整理的目录路径

# 文件类型分类映射，每个类型对应常见扩展名
file_types = {
    "图片": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
    "视频": [".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv"],
    "音频": [".mp3", ".wav", ".aac", ".flac", ".ogg"],
    "文档": [".pdf", ".docx", ".doc", ".xlsx", ".txt", ".pptx"]
}

def file_sha256(filepath):
    """计算文件的 SHA-256 哈希值，用于判断文件内容是否重复"""
    hash_sha256 = hashlib.sha256()  # 创建 SHA-256 哈希对象
    with open(filepath, "rb") as f:  # 二进制方式打开文件
        for chunk in iter(lambda: f.read(8192), b""):  # 分块读取文件，避免大文件占用内存
            hash_sha256.update(chunk)  # 更新哈希计算
    return hash_sha256.hexdigest()  # 返回十六进制字符串

def remove_duplicates(directory):
    """删除重复文件，只保留第一个出现的文件"""
    print("开始删除重复文件...")
    hashes = {}  # 保存已出现文件的哈希和路径
    for dirpath, dirnames, filenames in os.walk(directory):  # 遍历目录及子目录
        for filename in filenames:  # 遍历每个文件
            file_path = os.path.join(dirpath, filename)  # 文件完整路径
            file_hash = file_sha256(file_path)  # 计算文件 SHA-256
            if file_hash in hashes:  # 如果哈希已存在，则文件重复
                print(f"删除重复文件: {file_path}")  # 输出被删除的文件路径
                os.remove(file_path)  # 删除重复文件
            else:
                hashes[file_hash] = file_path  # 记录第一次出现的文件哈希
    print("重复文件处理完成。")  # 提示完成

def get_unique_filename(target_dir, filename):
    """生成在目标文件夹中不冲突的文件名"""
    base_name, extension = os.path.splitext(filename)  # 分离文件名和扩展名
    counter = 1  # 后缀计数
    new_name = filename  # 初始文件名
    while os.path.exists(os.path.join(target_dir, new_name)):  # 如果文件已存在
        new_name = f"{base_name}_{counter}{extension}"  # 生成带数字后缀的新文件名
        counter += 1
    return new_name  # 返回唯一文件名

def organize_files(directory):
    """按类型整理文件，移动到对应分类文件夹"""
    print("开始整理文件类型...")
    for dirpath, dirnames, filenames in os.walk(directory):  # 遍历目录及子目录
        for filename in filenames:  # 遍历每个文件
            file_path = os.path.join(dirpath, filename)  # 文件完整路径
            file_ext = os.path.splitext(filename)[1].lower()  # 获取文件扩展名并转小写
            for folder_name, extensions in file_types.items():  # 遍历文件类型
                if file_ext in extensions:  # 扩展名匹配对应类型
                    target_dir = os.path.join(directory, folder_name)  # 分类文件夹路径
                    os.makedirs(target_dir, exist_ok=True)  # 如果文件夹不存在则创建
                    unique_name = get_unique_filename(target_dir, filename)  # 获取唯一文件名，避免覆盖
                    target_path = os.path.join(target_dir, unique_name)  # 目标文件完整路径
                    print(f"移动文件 {file_path} -> {target_path}")  # 输出移动信息
                    shutil.move(file_path, target_path)  # 执行移动操作
                    break  # 匹配到类型后退出内层循环
    print("文件整理完成。")  # 提示完成

def remove_empty_dirs(directory):
    """递归删除空文件夹"""
    print("开始删除空文件夹...")
    for dirpath, dirnames, filenames in os.walk(directory, topdown=False):  # 从最深层开始遍历
        if not dirnames and not filenames:  # 如果没有子目录且没有文件
            print(f"删除空文件夹: {dirpath}")  # 输出被删除的空文件夹路径
            os.rmdir(dirpath)  # 删除空文件夹
    print("空文件夹处理完成。")  # 提示完成

def full_cleanup():
    """一键整理功能，依次执行删除重复、分类整理、删除空文件夹"""
    remove_duplicates(root_dir)  # 删除重复文件
    organize_files(root_dir)  # 按类型整理文件
    remove_empty_dirs(root_dir)  # 删除空文件夹
    print("整理完成。")  # 提示完成

def menu():
    """交互式菜单，用户可选择执行功能"""
    while True:
        print("\n请选择操作:")
        print("1 - 一键整理（删除重复 + 分类 + 删除空文件夹）")
        print("2 - 删除重复文件")
        print("3 - 按类型整理文件")
        print("4 - 删除空文件夹")
        print("0 - 退出")
        
        choice = input("输入选项数字: ").strip()  # 用户输入选项
        if choice == "1":
            full_cleanup()  # 执行一键整理
        elif choice == "2":
            remove_duplicates(root_dir)  # 执行删除重复
        elif choice == "3":
            organize_files(root_dir)  # 执行分类整理
        elif choice == "4":
            remove_empty_dirs(root_dir)  # 执行删除空文件夹
        elif choice == "0":
            print("退出程序。")  # 退出提示
            break
        else:
            print("无效输入，请重新选择。")  # 输入错误提示

if __name__ == "__main__":
    menu()  # 运行交互式菜单
