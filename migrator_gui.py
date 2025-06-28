#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading, shutil, os, queue, time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 类型映射
CATEGORY_MAP = {
    "图片 (jpg, png…)": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"],
    "视频 (mp4, avi…)": [".mp4", ".avi", ".mkv", ".mov", ".flv"],
    "音频 (mp3, wav…)": [".mp3", ".wav", ".aac", ".flac"],
    "文本 (txt, md…)": [".txt", ".md", ".rst"],
    "Office 文档":      [".doc", ".docx", ".odt", ".pdf"]
}

class MigratorGUI(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=10)
        self.root = root
        self.root.title("批量文件迁移工具")
        self.root.geometry("800x600")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.pack(fill=tk.BOTH, expand=True)

        self.src_dirs = []
        self.dst_dir = ""
        self.log_queue = queue.Queue()
        self._build_ui()

    def _build_ui(self):
        # === 顶部：路径选择区 ===
        frm_paths = ttk.Labelframe(self, text="路径设置", padding=10)
        frm_paths.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        frm_paths.columnconfigure(1, weight=1)

        btn_add_src = ttk.Button(frm_paths, text="添加源目录", command=self.add_src)
        btn_add_src.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.lst_src = tk.Listbox(frm_paths, height=3)
        self.lst_src.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        btn_select_dst = ttk.Button(frm_paths, text="选择目标目录", command=self.select_dst)
        btn_select_dst.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.lbl_dst = ttk.Label(frm_paths, text="未选择", foreground="gray")
        self.lbl_dst.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # === 中部：选项区 ===
        frm_opts = ttk.Labelframe(self, text="迁移选项", padding=10)
        frm_opts.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        frm_opts.columnconfigure(1, weight=1)
        frm_opts.columnconfigure(2, weight=1)

        # 文件类型
        ttk.Label(frm_opts, text="文件类型:").grid(row=0, column=0, sticky="nw")
        self.var_types = {}
        ft_frm = ttk.Frame(frm_opts)
        ft_frm.grid(row=0, column=1, columnspan=2, sticky="w")
        r = 0
        for name in CATEGORY_MAP:
            v = tk.BooleanVar(value=False)
            self.var_types[name] = v
            cb = ttk.Checkbutton(ft_frm, text=name, variable=v)
            cb.grid(row=r//2, column=r%2, sticky="w", padx=5, pady=2)
            r += 1

        # 操作模式
        ttk.Label(frm_opts, text="操作模式:").grid(row=1, column=0, sticky="w", pady=10)
        self.op_mode = tk.StringVar(value="move")
        mb = ttk.Frame(frm_opts)
        mb.grid(row=1, column=1, columnspan=2, sticky="w", pady=10)
        ttk.Radiobutton(mb, text="移动", variable=self.op_mode, value="move").pack(side="left", padx=5)
        ttk.Radiobutton(mb, text="复制", variable=self.op_mode, value="copy").pack(side="left", padx=5)

        # === 底部：按钮 + 日志 + 进度 ===
        frm_bottom = ttk.Frame(self)
        frm_bottom.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        frm_bottom.rowconfigure(1, weight=1)
        frm_bottom.columnconfigure(0, weight=1)

        self.btn_start = ttk.Button(
            frm_bottom, text="开始迁移", command=self.start_migration
        )
        self.btn_start.grid(row=0, column=0, sticky="w", pady=5)

        self.progress = ttk.Progressbar(
            frm_bottom, mode="determinate"
        )
        self.progress.grid(row=0, column=1, sticky="ew", padx=5)

        self.txt_log = tk.Text(frm_bottom, height=12, state=tk.DISABLED)
        self.txt_log.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=5)

        # 开始日志刷新循环
        self.after(100, self._flush_log)

    def add_src(self):
        d = filedialog.askdirectory(title="选择源目录")
        if d and d not in self.src_dirs:
            self.src_dirs.append(d)
            self.lst_src.insert(tk.END, d)

    def select_dst(self):
        d = filedialog.askdirectory(title="选择目标目录")
        if d:
            self.dst_dir = d
            self.lbl_dst.config(text=d, foreground="green")

    def log(self, msg):
        self.log_queue.put(msg)

    def _flush_log(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.txt_log.configure(state=tk.NORMAL)
            self.txt_log.insert(tk.END, msg + "\n")
            self.txt_log.see(tk.END)
            self.txt_log.configure(state=tk.DISABLED)
        self.after(100, self._flush_log)

    def start_migration(self):
        # 参数检查
        if not self.src_dirs:
            messagebox.showwarning("警告", "请先添加至少一个源目录。")
            return
        if not self.dst_dir:
            messagebox.showwarning("警告", "请先选择目标目录。")
            return
        exts = []
        for name, var in self.var_types.items():
            if var.get():
                exts += CATEGORY_MAP[name]
        if not exts:
            messagebox.showwarning("警告", "请至少勾选一种文件类型。")
            return

        # 禁用 UI
        self.btn_start.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.configure(state=tk.DISABLED)

        # 后台线程
        threading.Thread(
            target=self._worker, args=(exts, self.op_mode.get()), daemon=True
        ).start()

    def _unique_target(self, target: Path) -> Path:
        if not target.exists():
            return target
        stem, suf = target.stem, target.suffix
        i = 1
        while True:
            cand = target.parent / f"{stem}_{i}{suf}"
            if not cand.exists():
                return cand
            i += 1

    def _worker(self, exts, mode):
        # 先统计总文件数，用于进度条
        total = 0
        for src in self.src_dirs:
            for root, _, files in os.walk(src):
                total += sum(1 for f in files if Path(f).suffix.lower() in exts)
        count = 0
        self.progress["maximum"] = total

        # 开始迁移
        for src in self.src_dirs:
            for root, _, files in os.walk(src):
                for fn in files:
                    p = Path(root) / fn
                    if p.suffix.lower() in exts:
                        rel = p.relative_to(src)
                        tgt_dir = Path(self.dst_dir) / rel.parent
                        tgt_dir.mkdir(parents=True, exist_ok=True)
                        tgt = self._unique_target(tgt_dir / p.name)
                        try:
                            if mode == "move":
                                shutil.move(str(p), str(tgt))
                            else:
                                shutil.copy2(str(p), str(tgt))
                            self.log(f"{mode.upper()}: {p} → {tgt}")
                        except Exception as e:
                            self.log(f"错误: {p} → {tgt}, {e}")
                        count += 1
                        # 更新进度
                        self.progress["value"] = count
        self.log(f"完成：共处理 {count} 个文件。")
        self.btn_start.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    # 选择主题，可根据系统或安装的ttk主题调整
    if "clam" in style.theme_names():
        style.theme_use("clam")
    MigratorGUI(root)
    root.mainloop()
