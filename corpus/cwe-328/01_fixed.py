# bcrypt password hash (CWE-328, fix)
import bcrypt


def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
