import os
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
# ---------------------------------------------------------------------------
# 支持的媒体文件扩展名
# ---------------------------------------------------------------------------
IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
VIDEO_EXT = {'.mp4', '.avi', '.mkv', '.mov', '.wmv'}
AUDIO_EXT = {'.mp3', '.wav', '.aac', '.flac', '.ogg'}
ALLOWED_EXT = IMAGE_EXT | VIDEO_EXT | AUDIO_EXT
# ---------------------------------------------------------------------------
# 生成目标目录下唯一文件名，避免覆盖已有文件
# ---------------------------------------------------------------------------
def get_unique_filename(dest_dir, filename):
    base, ext = os.path.splitext(filename)
    candidate = filename
    counter = 1
    while os.path.exists(os.path.join(dest_dir, candidate)):
        candidate = f"{base}_{counter}{ext}"
        counter += 1
    return candidate
# ---------------------------------------------------------------------------
# 定义媒体文件迁移工具的Tkinter界面
# ---------------------------------------------------------------------------
class MediaMigratorApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # 设置窗口基本属性
        self.title("多源媒体文件迁移工具")
        self.minsize(800, 600)
        self.configure(bg="#f7f7f7")

        # 存储源目录及目标目录变量
        self.source_dirs = []  # 源目录列表
        self.target_dir = tk.StringVar()

        # 创建控件及布局配置
        self.create_widgets()
        self.create_grid_config()
    # ---------------------------------------------------------------------------
    # 创建所有控件
    # ---------------------------------------------------------------------------
    def create_widgets(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("TButton", font=("Helvetica", 12), padding=6)
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("Header.TLabel", font=("Helvetica", 16, "bold"))
        # -----------------------------------------------------------------------
        # 头部标签
        # -----------------------------------------------------------------------
        header = ttk.Label(self, text="多源媒体文件迁移工具", style="Header.TLabel", background="#f7f7f7")
        header.grid(row=0, column=0, columnspan=3, pady=(15, 10), sticky="n")
        # -----------------------------------------------------------------------
        # 源目录区域
        # -----------------------------------------------------------------------
        src_frame = ttk.LabelFrame(self, text="源目录 (可添加多个)", padding=10)
        src_frame.grid(row=1, column=0, padx=15, pady=10, sticky="nsew")
        src_frame.grid_rowconfigure(0, weight=1)
        src_frame.grid_columnconfigure(0, weight=1)

        self.src_listbox = tk.Listbox(src_frame, font=("Helvetica", 11))
        self.src_listbox.grid(row=0, column=0, rowspan=4, sticky="nsew", padx=(0, 5))
        src_scrollbar = ttk.Scrollbar(src_frame, orient="vertical", command=self.src_listbox.yview)
        src_scrollbar.grid(row=0, column=1, rowspan=4, sticky="ns")
        self.src_listbox.configure(yscrollcommand=src_scrollbar.set)

        btn_add = ttk.Button(src_frame, text="添加源目录", command=self.add_source_dir)
        btn_add.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        btn_del = ttk.Button(src_frame, text="删除选中目录", command=self.delete_selected_source)
        btn_del.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        btn_count = ttk.Button(src_frame, text="统计文件", command=self.count_files)
        btn_count.grid(row=2, column=2, padx=5, pady=5, sticky="ew")
        self.count_label = ttk.Label(src_frame, text="待处理文件数：0", foreground="#006400")
        self.count_label.grid(row=3, column=2, padx=5, pady=5, sticky="ew")

        # -----------------------------------------------------------------------
        # 目标目录区域
        # -----------------------------------------------------------------------
        target_frame = ttk.LabelFrame(self, text="目标目录", padding=10)
        target_frame.grid(row=1, column=1, padx=15, pady=10, sticky="nsew")
        target_frame.grid_columnconfigure(1, weight=1)
        btn_target = ttk.Button(target_frame, text="选择目标目录", command=self.select_target_dir)
        btn_target.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(target_frame, textvariable=self.target_dir, font=("Helvetica", 11))
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # -----------------------------------------------------------------------
        # 迁移操作框架
        # -----------------------------------------------------------------------
        action_frame = ttk.Frame(self, padding=10)
        action_frame.grid(row=2, column=0, columnspan=3, padx=15, pady=10, sticky="nsew")
        self.btn_start = ttk.Button(action_frame, text="开始迁移", command=self.start_migration)
        self.btn_start.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # -----------------------------------------------------------------------
        # 状态信息区域
        # -----------------------------------------------------------------------
        status_frame = ttk.LabelFrame(self, text="状态信息", padding=10)
        status_frame.grid(row=3, column=0, columnspan=3, padx=15, pady=10, sticky="nsew")
        status_frame.grid_rowconfigure(0, weight=1)
        status_frame.grid_columnconfigure(0, weight=1)
        self.status_text = tk.Text(status_frame, font=("Helvetica", 11), state="disabled", wrap="word")
        self.status_text.grid(row=0, column=0, sticky="nsew")
        status_scroll = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_text.yview)
        status_scroll.grid(row=0, column=1, sticky="ns")
        self.status_text.configure(yscrollcommand=status_scroll.set)

    # ---------------------------------------------------------------------------
    # 设置主窗口网格配置，确保控件大小随窗口变化而变化
    # ---------------------------------------------------------------------------
    def create_grid_config(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=2)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0)

    # ---------------------------------------------------------------------------
    # 添加源目录
    # ---------------------------------------------------------------------------
    def add_source_dir(self):
        dir_path = filedialog.askdirectory(title="选择源目录")
        if dir_path and dir_path not in self.source_dirs:
            self.source_dirs.append(dir_path)
            self.src_listbox.insert("end", dir_path)
            self.log_status(f"添加源目录：{dir_path}")
        elif dir_path in self.source_dirs:
            messagebox.showinfo("提示", "该目录已存在。")

    # ---------------------------------------------------------------------------
    # 删除选中的源目录
    # ---------------------------------------------------------------------------
    def delete_selected_source(self):
        selected = list(self.src_listbox.curselection())
        if not selected:
            messagebox.showwarning("警告", "请选择要删除的目录。")
            return
        for index in reversed(selected):
            removed = self.source_dirs.pop(index)
            self.src_listbox.delete(index)
            self.log_status(f"删除源目录：{removed}")
        self.count_files()

    # ---------------------------------------------------------------------------
    # 选择目标目录
    # ---------------------------------------------------------------------------
    def select_target_dir(self):
        dir_path = filedialog.askdirectory(title="选择目标目录")
        if dir_path:
            self.target_dir.set(dir_path)
            self.log_status(f"设置目标目录：{dir_path}")

    # ---------------------------------------------------------------------------
    # 统计待处理文件数
    # ---------------------------------------------------------------------------
    def count_files(self):
        total = 0
        for dir_path in self.source_dirs:
            for current_root, dirs, files in os.walk(dir_path):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ALLOWED_EXT:
                        total += 1
        self.count_label.config(text=f"待处理文件数：{total}")
        self.log_status(f"统计完成：待处理文件数 {total}")
        return total

    # ---------------------------------------------------------------------------
    # 记录状态信息到状态文本框
    # ---------------------------------------------------------------------------
    def log_status(self, msg):
        self.status_text.config(state="normal")
        self.status_text.insert("end", msg + "\n")
        self.status_text.see("end")
        self.status_text.config(state="disabled")

    # ---------------------------------------------------------------------------
    # 点击开始迁移时的响应函数
    # ---------------------------------------------------------------------------
    def start_migration(self):
        if not self.source_dirs:
            messagebox.showerror("错误", "请添加至少一个源目录！")
            return
        if not self.target_dir.get():
            messagebox.showerror("错误", "请选择目标目录！")
            return

        total_files = self.count_files()
        if total_files == 0:
            messagebox.showinfo("提示", "没有符合条件的文件需要移动！")
            return

        confirm = messagebox.askyesno("确认", f"共计 {total_files} 个文件将被移动到:\n{self.target_dir.get()}\n是否开始？")
        if not confirm:
            return

        self.disable_buttons()
        self.log_status("开始迁移文件...")
        self.migrate_files()
        self.enable_buttons()

    # ---------------------------------------------------------------------------
    # 禁用按钮，防止操作重复
    # ---------------------------------------------------------------------------
    def disable_buttons(self):
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state="disabled")
            elif isinstance(widget, (ttk.LabelFrame, ttk.Frame)):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        child.config(state="disabled")
# ---------------------------------------------------------------------------
    # 启用按钮
    # ---------------------------------------------------------------------------
    def enable_buttons(self):
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state="normal")
            elif isinstance(widget, (ttk.LabelFrame, ttk.Frame)):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button):
                        child.config(state="normal")
    # ---------------------------------------------------------------------------
    # 遍历源目录并迁移符合条件的文件，不保留目录结构
    # ---------------------------------------------------------------------------
    def migrate_files(self):
        target_dir = self.target_dir.get()

        if not os.access(target_dir, os.W_OK):
            self.log_status(f"目标目录 {target_dir} 无写入权限，任务终止。")
            return

        total_scanned = 0
        total_moved = 0

        for dir_path in self.source_dirs:
            self.log_status(f"处理源目录：{dir_path}")
            for current_root, directories, files in os.walk(dir_path):
                for file in files:
                    total_scanned += 1
                    ext = os.path.splitext(file)[1].lower()
                    if ext in ALLOWED_EXT:
                        src_file = os.path.join(current_root, file)
                        if not os.access(src_file, os.R_OK):
                            self.log_status(f"跳过（无读取权限）：{src_file}")
                            continue
                        unique_name = get_unique_filename(target_dir, file)
                        dest_file = os.path.join(target_dir, unique_name)
                        try:
                            if not os.access(target_dir, os.W_OK):
                                self.log_status(f"目标目录 {target_dir} 无写权限，跳过 {src_file}")
                                continue
                            shutil.move(src_file, dest_file)
                            self.log_status(f"移动成功：{src_file} -> {dest_file}")
                            total_moved += 1
                        except Exception as e:
                            self.log_status(f"移动错误：{src_file} -> {dest_file}\n错误：{e}")

        summary = (f"\n扫描文件总数：{total_scanned}\n"
                   f"成功移动文件数：{total_moved}\n"
                   "迁移任务完成。")
        self.log_status(summary)
        messagebox.showinfo("迁移完成", summary)
# ---------------------------------------------------------------------------
# 主程序入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = MediaMigratorApp()
    app.mainloop()
