# hashlib md5 crypt password (CWE-328, absichtlich verwundbar)
import hashlib


def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()
