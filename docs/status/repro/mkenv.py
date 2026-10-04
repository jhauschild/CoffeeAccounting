"""Create .env from .env.example in the current directory (the README's `cp .env.example .env`) and set values:

    python mkenv.py KEY=VALUE [KEY=VALUE ...]

Fails when a key is not in .env.example. Used by acceptance_up.sh.
"""
import re
import sys

text = open(".env.example", encoding="utf-8").read()
for kv in sys.argv[1:]:
    key, value = kv.split("=", 1)
    text, n = re.subn(rf"^#?\s*{re.escape(key)}=.*$", lambda _m, k=key, v=value: f"{k}={v}", text, count=1, flags=re.M)
    if not n:
        text += f"\n{key}={value}\n"
open(".env", "w", encoding="utf-8").write(text)
