import re
import os
import random
import string
import threading
from typing import Tuple, Optional
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ===================== 全局常量 =====================
SHIELD_SUFFIX = ".shield"
DEFAULT_KEY_FILE = "privacy.key"
MIN_PWD_LEN = 6
MAX_PWD_LEN = 64
CHARS_SYMBOL = "!@#$%^&*()_+-="

# ===================== 加密核心工具类 =====================
class FileCrypto:
    def __init__(self, key_path: str = DEFAULT_KEY_FILE):
        self.key_path = key_path
        self.key = self.load_or_create_key()
        self.fernet = Fernet(self.key)

    def load_or_create_key(self) -> bytes:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return f.read()
        new_key = Fernet.generate_key()
        with open(self.key_path, "wb") as f:
            f.write(new_key)
        return new_key

    def export_key(self, save_path: str) -> Tuple[bool, str]:
        try:
            with open(self.key_path, "rb") as src, open(save_path, "wb") as dst:
                dst.write(src.read())
            return True, "密钥导出成功"
        except Exception as e:
            return False, f"导出失败：{str(e)}"

    def import_key(self, load_path: str) -> Tuple[bool, str]:
        try:
            with open(load_path, "rb") as f:
                new_key = f.read()
            Fernet(new_key)
            with open(self.key_path, "wb") as f:
                f.write(new_key)
            self.key = new_key
            self.fernet = Fernet(new_key)
            return True, "密钥导入成功，已切换加密器"
        except InvalidToken:
            return False, "密钥格式非法"
        except Exception as e:
            return False, f"导入失败：{str(e)}"

    def encrypt_file(self, file_path: str, backup: bool = True) -> Tuple[bool, str]:
        if not os.path.isfile(file_path):
            return False, "文件不存在"
        if file_path.endswith(SHIELD_SUFFIX):
            return False, "已是加密文件，无需重复加密"

        try:
            chunk_size = 1024 * 1024
            with open(file_path, "rb") as f_in:
                raw_data = f_in.read()
                encrypted_data = self.fernet.encrypt(raw_data)
            new_path = file_path + SHIELD_SUFFIX
            with open(new_path, "wb") as f_out:
                f_out.write(encrypted_data)
            if not backup:
                os.remove(file_path)
            return True, f"加密完成：{os.path.basename(new_path)}"
        except PermissionError:
            return False, "文件权限不足，无法读写"
        except Exception as e:
            return False, f"加密异常：{str(e)}"

    def decrypt_file(self, file_path: str, backup: bool = True) -> Tuple[bool, str]:
        if not file_path.endswith(SHIELD_SUFFIX):
            return False, f"仅支持{SHIELD_SUFFIX}加密文件"
        if not os.path.isfile(file_path):
            return False, "文件不存在"

        try:
            with open(file_path, "rb") as f_in:
                enc_data = f_in.read()
                dec_data = self.fernet.decrypt(enc_data)
            new_path = file_path[:-len(SHIELD_SUFFIX)]
            with open(new_path, "wb") as f_out:
                f_out.write(dec_data)
            if not backup:
                os.remove(file_path)
            return True, f"解密完成：{os.path.basename(new_path)}"
        except InvalidToken:
            return False, "密钥不匹配或文件已损坏"
        except PermissionError:
            return False, "文件权限不足"
        except Exception as e:
            return False, f"解密异常：{str(e)}"

# ===================== 文本隐私脱敏工具 =====================
class TextDesensitize:
    def __init__(self):
        self.rules = [
            ("手机号", re.compile(r"1[3-9]\d{9}"), lambda x: f"{x[:3]}****{x[7:]}"),
            ("身份证", re.compile(r"\d{17}[\dXx]"), lambda x: f"{x[:8]}*********{x[-1:]}"),
            ("银行卡", re.compile(r"\d{16,19}"), lambda x: f"****{x[-4:]}")
        ]

    def clean_text(self, text: str) -> str:
        res = text
        for _, pattern, mask_func in self.rules:
            match_list = pattern.findall(res)
            for match in match_list:
                res = res.replace(match, mask_func(match))
        return res

# ===================== 图片EXIF清除工具 =====================
class ImagePrivacyClear:
    IMG_SUFFIX_WHITE = (".jpg", ".jpeg", ".png", ".bmp", ".webp")

    def clear_exif(self, img_path: str, save_path: str) -> Tuple[bool, str]:
        ext = os.path.splitext(img_path)[1].lower()
        if ext not in self.IMG_SUFFIX_WHITE:
            return False, f"不支持该图片格式：{ext}"
        try:
            img = Image.open(img_path)
            pixel_data = list(img.getdata())
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(pixel_data)
            clean_img.save(save_path)
            img.close()
            clean_img.close()
            return True, "图片EXIF隐私信息已清除"
        except Exception as e:
            return False, f"处理失败：{str(e)}"

# ===================== 密码生成工具 =====================
def generate_password(
    length: int = 16,
    upper: bool = True,
    lower: bool = True,
    digit: bool = True,
    symbol: bool = True
) -> str:
    char_pool = ""
    if upper:
        char_pool += string.ascii_uppercase
    if lower:
        char_pool += string.ascii_lowercase
    if digit:
        char_pool += string.digits
    if symbol:
        char_pool += CHARS_SYMBOL
    if not char_pool:
        raise ValueError("至少勾选一类字符")
    return "".join(random.choice(char_pool) for _ in range(length))

# ===================== GUI主程序 =====================
class PrivacyApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PrivateShield 隐私卫士 v1.0")
        self.root.geometry("720x560")
        self.root.minsize(680, 520)
        self.root.update()
        x = (self.root.winfo_screenwidth() - self.root.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - self.root.winfo_height()) // 2
        self.root.geometry(f"+{x}+{y}")

        # 业务实例
        self.crypto = FileCrypto()
        self.text_tool = TextDesensitize()
        self.img_tool = ImagePrivacyClear()

        # 顶部状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = tk.Label(root, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill=tk.X, padx=5, pady=2)

        # 分页标签
        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)

        # 分页1：文件加解密
        self.tab_file = ttk.Frame(notebook)
        notebook.add(self.tab_file, text="文件加密解密")
        self.build_file_tab()

        # 分页2：文本脱敏
        self.tab_text = ttk.Frame(notebook)
        notebook.add(self.tab_text, text="文本隐私脱敏")
        self.build_text_tab()

        # 分页3：图片清理EXIF
        self.tab_img = ttk.Frame(notebook)
        notebook.add(self.tab_img, text="图片隐私清除")
        self.build_img_tab()

        # 分页4：密码生成
        self.tab_pwd = ttk.Frame(notebook)
        notebook.add(self.tab_pwd, text="高强度密码生成")
        self.build_pwd_tab()

    def set_status(self, msg: str):
        self.status_var.set(msg)

    # 文件分页
    def build_file_tab(self):
        frame_btn = ttk.Frame(self.tab_file)
        frame_btn.pack(pady=10)
        ttk.Button(frame_btn, text="加密单个文件", command=self.thread_encrypt).grid(row=0, column=0, padx=6)
        ttk.Button(frame_btn, text="解密单个文件", command=self.thread_decrypt).grid(row=0, column=1, padx=6)
        ttk.Button(frame_btn, text="导出密钥", command=self.export_key_ui).grid(row=0, column=2, padx=6)
        ttk.Button(frame_btn, text="导入密钥", command=self.import_key_ui).grid(row=0, column=3, padx=6)

    def thread_encrypt(self):
        def task():
            path = filedialog.askopenfilename(title="选择需要加密的文件")
            if not path:
                self.set_status("已取消选择")
                return
            self.set_status("正在加密...")
            ok, msg = self.crypto.encrypt_file(path, backup=False)
            self.root.after(0, lambda: self.show_tip(ok, msg))
        threading.Thread(target=task, daemon=True).start()

    def thread_decrypt(self):
        def task():
            path = filedialog.askopenfilename(
                title="选择加密文件",
                filetypes=[("加密文件", f"*{SHIELD_SUFFIX}")]
            )
            if not path:
                self.set_status("已取消选择")
                return
            self.set_status("正在解密...")
            ok, msg = self.crypto.decrypt_file(path, backup=False)
            self.root.after(0, lambda: self.show_tip(ok, msg))
        threading.Thread(target=task, daemon=True).start()

    def export_key_ui(self):
        save_path = filedialog.asksaveasfilename(
            defaultextension=".key", filetypes=[("密钥文件", "*.key")]
        )
        if not save_path:
            return
        ok, msg = self.crypto.export_key(save_path)
        self.show_tip(ok, msg)

    def import_key_ui(self):
        load_path = filedialog.askopenfilename(filetypes=[("密钥文件", "*.key")])
        if not load_path:
            return
        ok, msg = self.crypto.import_key(load_path)
        self.show_tip(ok, msg)

    # 文本脱敏分页
    def build_text_tab(self):
        ttk.Label(self.tab_text, text="原始文本：").pack(anchor="w")
        self.raw_text = scrolledtext.ScrolledText(self.tab_text, height=7)
        self.raw_text.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        frame_mid = ttk.Frame(self.tab_text)
        frame_mid.pack(pady=3)
        ttk.Button(frame_mid, text="一键脱敏", command=self.desensitize_ui).grid(row=0, column=0, padx=4)
        ttk.Button(frame_mid, text="复制结果", command=self.copy_result).grid(row=0, column=1, padx=4)

        ttk.Label(self.tab_text, text="脱敏结果：").pack(anchor="w")
        self.clean_text = scrolledtext.ScrolledText(self.tab_text, height=7)
        self.clean_text.pack(fill=tk.BOTH, expand=True)

    def desensitize_ui(self):
        raw = self.raw_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("提示", "请输入待脱敏文本")
            return
        res = self.text_tool.clean_text(raw)
        self.clean_text.delete("1.0", tk.END)
        self.clean_text.insert("1.0", res)
        self.set_status("文本脱敏完成")

    def copy_result(self):
        text = self.clean_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("提示", "暂无脱敏结果")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status("结果已复制到剪贴板")

    # 图片清理分页
    def build_img_tab(self):
        frame_btn = ttk.Frame(self.tab_img)
        frame_btn.pack(pady=15)
        ttk.Button(frame_btn, text="选择图片清除EXIF", command=self.clear_img_exif_ui).pack()

    def clear_img_exif_ui(self):
        img_path = filedialog.askopenfilename(
            filetypes=[("图片", "*.jpg;*.jpeg;*.png;*.bmp;*.webp")]
        )
        if not img_path:
            self.set_status("已取消选择")
            return
        save_path = filedialog.asksaveasfilename(
            defaultextension=".jpg", filetypes=[("JPG图片", "*.jpg")]
        )
        if not save_path:
            self.set_status("已取消保存")
            return
        ok, msg = self.img_tool.clear_exif(img_path, save_path)
        self.show_tip(ok, msg)

    # 密码生成分页
    def build_pwd_tab(self):
        frame_top = ttk.Frame(self.tab_pwd)
        frame_top.pack(pady=12)
        ttk.Label(frame_top, text="密码长度：").grid(row=0, column=0)
        self.pwd_len_entry = ttk.Entry(frame_top, width=10)
        self.pwd_len_entry.insert(0, "16")
        self.pwd_len_entry.grid(row=0, column=1, padx=6)
        ttk.Button(frame_top, text="生成密码", command=self.gen_pwd_ui).grid(row=0, column=2, padx=6)
        self.pwd_out = ttk.Entry(frame_top, width=42)
        self.pwd_out.grid(row=0, column=3, padx=6)
        ttk.Button(frame_top, text="复制密码", command=self.copy_pwd).grid(row=0, column=4, padx=6)

    def gen_pwd_ui(self):
        try:
            length = int(self.pwd_len_entry.get())
            if not (MIN_PWD_LEN <= length <= MAX_PWD_LEN):
                messagebox.showerror("错误", f"长度范围 {MIN_PWD_LEN} ~ {MAX_PWD_LEN}")
                return
            pwd = generate_password(length)
            self.pwd_out.delete(0, tk.END)
            self.pwd_out.insert(0, pwd)
            self.set_status("密码生成成功")
        except ValueError:
            messagebox.showerror("错误", "请输入有效数字长度")

    def copy_pwd(self):
        pwd = self.pwd_out.get().strip()
        if not pwd:
            messagebox.showinfo("提示", "请先生成密码")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self.set_status("密码已复制剪贴板")

    def show_tip(self, success: bool, msg: str):
        self.set_status(msg)
        if success:
            messagebox.showinfo("操作成功", msg)
        else:
            messagebox.showerror("操作失败", msg)

if __name__ == "__main__":
    main_window = tk.Tk()
    app = PrivacyApp(main_window)
    main_window.mainloop()