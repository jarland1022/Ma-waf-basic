#!/usr/bin/env python3
"""生成管理员 bcrypt 哈希，写入 api.yaml 的 admin_pass_hash。"""
import getpass
import sys

try:
    import bcrypt
except ImportError:
    # 无 bcrypt 时用 hashlib+提示；生产请 pip install bcrypt
    import hashlib, secrets
    pw = getpass.getpass("password: ") if sys.stdin.isatty() else sys.stdin.read().strip()
    salt = secrets.token_hex(16)
    print("WARN: bcrypt 未安装，输出 sha256(salt+pw) 仅供开发，生产请安装 bcrypt", file=sys.stderr)
    print(f"sha256${salt}${hashlib.sha256((salt+pw).encode()).hexdigest()}")
    sys.exit(0)

pw = getpass.getpass("password: ") if sys.stdin.isatty() else sys.stdin.read().strip()
print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())
