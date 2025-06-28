#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import shutil
import os
import queue
import time
import json
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
    STATE_FILE = "migrate_state.json"
    LOG_FILE = "migrate_log.txt"

    def __init__(self, root):
        super().__init__(root, padding=10)
        self.root = root
        self.root.title("批量文件迁移工具")
        self.root.geometry("800x600")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.pack(fill=tk.BOTH, expand=True)

        # 运行时数据
        self.src_dirs = []
        self.dst_dir = ""
        self.log_queue = queue.Queue()
        self.pause_event = threading.Event()
        self.pause_event.set()            # 初始：允许运行

        # 加载历史状态
        self._load_state()
        # 构建界面
        self._build_ui()
        # 启动日志刷新
        self.after(100, self._flush_log)

        # 如果检测到未完成状态，弹框询问
        if self.processed:
            if messagebox.askyesno("检测到未完成任务",
                                   "上次迁移未完成，是否从上次位置继续？"):
                self.log("从上次中断位置继续迁移...")
            else:
                # 清除状态和日志
                self.processed.clear()
                self._save_state_file()
                self._clear_log_file()
                self.log("已重置上次状态，重新开始。")

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

        ttk.Label(frm_opts, text="操作模式:").grid(row=1, column=0, sticky="w", pady=10)
        self.op_mode = tk.StringVar(value="move")
        mb = ttk.Frame(frm_opts)
        mb.grid(row=1, column=1, columnspan=2, sticky="w", pady=10)
        ttk.Radiobutton(mb, text="移动", variable=self.op_mode, value="move").pack(side="left", padx=5)
        ttk.Radiobutton(mb, text="复制", variable=self.op_mode, value="copy").pack(side="left", padx=5)

        # === 底部：按钮 + 进度 + 日志 ===
        frm_bottom = ttk.Frame(self)
        frm_bottom.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        frm_bottom.rowconfigure(1, weight=1)
        frm_bottom.columnconfigure(1, weight=1)

        self.btn_start = ttk.Button(frm_bottom, text="开始迁移", command=self.start_migration)
        self.btn_start.grid(row=0, column=0, sticky="w", pady=5)

        self.btn_pause = ttk.Button(frm_bottom, text="暂停", command=self.toggle_pause, state=tk.DISABLED)
        self.btn_pause.grid(row=0, column=2, sticky="w", padx=5, pady=5)

        self.progress = ttk.Progressbar(frm_bottom, mode="determinate")
        self.progress.grid(row=0, column=1, sticky="ew", padx=5)

        self.txt_log = tk.Text(frm_bottom, height=12, state=tk.DISABLED)
        self.txt_log.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=5)

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
        """GUI 日志 + 写入文件"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {msg}"
        # 推送到 GUI 队列
        self.log_queue.put(line)
        # 追加到磁盘日志
        with open(self.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _flush_log(self):
        """定期把队列中的日志推到 Text 控件"""
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

        # UI 控制
        self.btn_start.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL, text="暂停")
        self.pause_event.set()
        self.progress["value"] = 0
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.configure(state=tk.DISABLED)
        # 如果是新任务，清空日志文件
        if not self.processed:
            self._clear_log_file()

        # 后台线程执行
        threading.Thread(
            target=self._worker, args=(exts, self.op_mode.get()), daemon=True
        ).start()

    def toggle_pause(self):
        """暂停/继续 切换"""
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="继续")
            self.log("已暂停迁移。")
        else:
            self.pause_event.set()
            self.btn_pause.config(text="暂停")
            self.log("继续迁移。")

    def _load_state(self):
        """加载上次已处理文件的相对路径列表"""
        self.processed = set()
        if os.path.exists(self.STATE_FILE):
            try:
                with open(self.STATE_FILE, "r", encoding="utf-8") as f:
                    lst = json.load(f)
                    self.processed = set(lst)
            except Exception:
                self.processed = set()

    def _save_state_file(self):
        """把 self.processed 集合写回磁盘"""
        with open(self.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(list(self.processed), f, ensure_ascii=False, indent=2)

    def _clear_log_file(self):
        try:
            open(self.LOG_FILE, "w", encoding="utf-8").close()
        except:
            pass

    def _unique_target(self, target: Path) -> Path:
        """碰文件名冲突时添加后缀"""
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
        """后台迁移线程"""
        # 统计总量，用于进度条
        total = 0
        for src in self.src_dirs:
            for root, _, files in os.walk(src):
                total += sum(1 for f in files
                             if Path(f).suffix.lower() in exts)
        self.progress["maximum"] = total
        count = 0

        self.log(f"开始迁移，共 {total} 个目标文件。")

        for src in self.src_dirs:
            for root, _, files in os.walk(src):
                for fn in files:
                    # 检查扩展名
                    ext = Path(fn).suffix.lower()
                    if ext not in exts:
                        continue

                    # 组相对路径，用于跳过与记录
                    rel = str(Path(root).relative_to(src) / fn)
                    # 如果已处理，直接跳过并更新进度
                    if rel in self.processed:
                        count += 1
                        self.progress["value"] = count
                        continue

                    # 等待继续（可暂停）
                    self.pause_event.wait()

                    p = Path(root) / fn
                    tgt_dir = Path(self.dst_dir) / Path(rel).parent
                    tgt_dir.mkdir(parents=True, exist_ok=True)
                    tgt = self._unique_target(tgt_dir / fn)

                    try:
                        if mode == "move":
                            shutil.move(str(p), str(tgt))
                        else:
                            shutil.copy2(str(p), str(tgt))
                        self.log(f"{mode.upper()}: {p} → {tgt}")
                    except Exception as e:
                        self.log(f"错误: {p} → {tgt}，{e}")

                    # 更新计数、进度、状态持久化
                    count += 1
                    self.progress["value"] = count
                    self.processed.add(rel)
                    self._save_state_file()

        self.log(f"迁移完成，共处理 {count} 个文件。")
        # 清除状态文件，下次算新任务
        try:
            os.remove(self.STATE_FILE)
        except:
            pass

        # 恢复 UI
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    MigratorGUI(root)
    root.mainloop()
