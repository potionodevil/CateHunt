# JWT secret aus Umgebung (CWE-798, fix)
import hmac
import os


def sign(payload: str) -> str:
    secret = os.environ["JWT_SECRET"]
    return hmac.new(secret.encode(), payload.encode(), "sha256").hexdigest()
