#!/usr/bin/env python3
"""
File Encryptor — AES-256-GCM
-----------------------------
Encrypts any file using the modern, strong AES-256 algorithm in GCM mode
(authenticated encryption — protects against both reading and tampering).

The key is never stored anywhere — it is derived from your password every
time, using PBKDF2-HMAC-SHA256 with 600,000 iterations (protection against
brute-force and rainbow-table attacks) and a unique random salt per file.

The file is encrypted "in place" — the name and extension stay the same,
only the file's content is replaced with the encrypted version. So the
program can tell an encrypted file apart from a normal one, a small MAGIC
header is added at the start.

Encrypted file format:
    [5 bytes MAGIC][16 bytes salt][12 bytes nonce][ciphertext + auth tag]

If someone enters the wrong password, or the file gets corrupted or
tampered with, decryption simply fails with an error (GCM verifies
integrity), and the original (encrypted) file content stays untouched.

Run:
    python file_encryptor.py
"""

import base64
import os
import secrets
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Window icon, embedded directly as base64 GIF data — no separate file needed.
# GIF is used instead of PNG because older bundled Tcl/Tk versions on some
# Windows Python installs can't decode PNG via tk.PhotoImage, but every
# version supports GIF.
ICON_B64 = (
    "R0lGODlhQABAAIYAAH19fXt7e3l5eXh4eHd3d3Z2dnV1dXR0dHNzc3FxcXBwcG9vb25ubm1tbWxsbGtra2hoaGdnZ2ZmZmVlZWRkZGJiYmFhYWBgYF9fX1tbW1lZWVhYWFdXV1ZWVlVVVVRUVFNTU1JSUlFRUU9PT0hISEVFRURERENDQ0JCQkFBQT4+Pj09PTw8PDs7Ozk5OTg4ODY2NjU1NTQ0NDIyMjExMTAwMC8vLy4uLi0tLSwsLCoqKigoKCcnJyYmJiUlJSQkJCMjIyIiIiEhISAgIB8fHxsbGxoaGhkZGRcXFxYWFhUVFRQUFBMTExISEhEREQ8PDw4ODg0NDQwMDAsLCwoKCgkJCQgICAcHBwYGBgUFBQQEBAMDAwICAgEBAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAF8ALAAAAABAAEAAQAj/AL8IHEiwoMGDCBMqXMgw4YIWS7xInEjxiYaGGBHO8LKFYscRX4xw6UKxpMQtJE1q8RKB4AYjGWMSNNBlpZeVAr1wMclxZw6ZQBl66XKFYM8uMIMqbTglyUCJLgr+0NllyxYaS7Ma5ODlipcMBB9k6NDBggCCMSSC0Mq2rdu3SiFswTJRC5ecNnnq5eilSUIrQJVgybJFS0cvGw7ynVjVi8AQeyVm8XIELkMcHDt++NKjsc67lrXy8FKlYJOdLwx6YRGabQmrQ71Q+MKgyGerrTNKtFuyi++UEmtKzE28uPHjyAdCSU3Qw5cgJw0D51mV5I6FCJaSWHzT8RedkSOv/zywVUdQIF121pWY+AuM2CZTiniaF3yHLwW8WFia4MSJBwu9dxhJS+REl14dPZHcQFeMxJdAwpnUwoIKSbETFALpwBFJflHI0GSAFbQFF5N5qJAHXUhBUBclGlQTFyuYyNB7vEnWwBcQTOGAjAh1VJgWV1hxRRZa8JYCj9+pd9hEV0hBhXoSceFgUTISMER4EiUxAZJcdunll2CGqVUDGYQAwgUAfAlDFSX9aFiRhgUnQXEoSGRCCE909UUGhWFZ0kpOKITEnErdZFV63nXnZ5te4ICQd0GBt54BX3Q03V4jUlRVFqotxd1uXsB0g6LUqRdDDvAN1UWHOXm6JBcd+eJQkAyIasqFFgOpgMWlqd6wVH1e2JAQE6l2NMAXdRKGoBcKJueBoisBeBqUJU2GhImKdgQhsI11saOMEHgxGU7fAeebil9OtdIPeIFHhJgI6BTiF9JpK6ZE8+bUmAlhRpQvhHRlR9CxPK7gBRUEWXBTswRVYK+JDHgxL2Ze3DjTUB2ZJ6ZAIOwmJUkbGwgeQQqAh8GXFXhxIKONcYnqQD5Edh+ONZj48U5akJCQATHfxEUUHjLhWVU1MlaYelp0gZWJSkRp2Me+SXm0ROh6KcIMQyTBRBJCzDBCACGHLfbYXQYEADs="
)

MAGIC = b"XENC1"
SALT_SIZE = 16 
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000
KEY_SIZE = 32 


def derive_key(password: str, salt: bytes) -> bytes:
    """Turns a password into a 256-bit key via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def is_encrypted(filepath: str) -> bool:
    """Checks whether a file is already encrypted by this program (MAGIC header)."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(len(MAGIC))
        return header == MAGIC
    except OSError:
        return False


def _atomic_replace(filepath: str, data: bytes) -> None:
    """Writes data to a temporary file next to the original, then atomically
    replaces the original with it. If something fails mid-write, the
    original file stays intact."""
    directory = os.path.dirname(os.path.abspath(filepath)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, filepath)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def encrypt_file(filepath: str, password: str) -> str:
    if is_encrypted(filepath):
        raise ValueError("This file is already encrypted.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    _atomic_replace(filepath, MAGIC + salt + nonce + ciphertext)
    return filepath


def decrypt_file(filepath: str, password: str) -> str:
    if not is_encrypted(filepath):
        raise ValueError("This file is not encrypted (no marker found).")

    with open(filepath, "rb") as f:
        raw = f.read()

    body = raw[len(MAGIC):]
    salt = body[:SALT_SIZE]
    nonce = body[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = body[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    _atomic_replace(filepath, plaintext)
    return filepath


class EncryptorApp:
    def __init__(self, root):
        self.root = root
        root.title("🔒 File Encryptor — AES-256-GCM")
        root.geometry("420x260")
        root.resizable(False, False)

        try:
            icon_image = tk.PhotoImage(data=ICON_B64)
            root.iconphoto(True, icon_image)
            self._icon_image = icon_image
        except Exception as e:
            print(f"Could not load window icon: {e}")

        tk.Label(
            root, text="🔒 File Encryptor", font=("Segoe UI", 16, "bold")
        ).pack(pady=(20, 5))

        tk.Label(
            root,
            text="AES-256-GCM  •  PBKDF2  •  600,000 iterations",
            font=("Segoe UI", 9),
            fg="gray",
        ).pack(pady=(0, 20))

        tk.Button(
            root,
            text="📁  Encrypt File",
            width=28,
            height=2,
            command=self.handle_encrypt,
        ).pack(pady=8)

        tk.Button(
            root,
            text="🔓  Decrypt File",
            width=28,
            height=2,
            command=self.handle_decrypt,
        ).pack(pady=8)

        tk.Label(
            root,
            text="Encrypts the file \"in place\" — the name stays the same.\n"
                 "The password is never stored. Forget it and it's gone for good.",
            font=("Segoe UI", 8),
            fg="gray",
            justify="center",
        ).pack(pady=(15, 0))

    def ask_password(self, prompt="Enter password:"):
        return simpledialog.askstring(
            "Password", prompt, show="*", parent=self.root
        )

    def handle_encrypt(self):
        filepath = filedialog.askopenfilename(title="Choose a file to encrypt")
        if not filepath:
            return

        password = self.ask_password("Choose a password for encryption:")
        if not password:
            return
        password_confirm = self.ask_password("Confirm password:")
        if password != password_confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        try:
            encrypt_file(filepath, password)
            messagebox.showinfo(
                "Done", f"File encrypted (in place):\n{filepath}"
            )
        except ValueError as e:
            messagebox.showwarning("Notice", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt file:\n{e}")

    def handle_decrypt(self):
        filepath = filedialog.askopenfilename(title="Choose an encrypted file")
        if not filepath:
            return

        password = self.ask_password("Enter password to decrypt:")
        if not password:
            return

        try:
            decrypt_file(filepath, password)
            messagebox.showinfo(
                "Done", f"File decrypted (in place):\n{filepath}"
            )
        except ValueError as e:
            messagebox.showwarning("Notice", str(e))
        except Exception:
            messagebox.showerror(
                "Error",
                "Failed to decrypt file.\n"
                "Wrong password, or the file is corrupted/tampered with.",
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
