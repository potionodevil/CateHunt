# Hardcoded JWT secret (CWE-798, absichtlich verwundbar)
JWT_SECRET = "supersecret123"


def sign(payload: str) -> str:
    import hmac
    return hmac.new(JWT_SECRET.encode(), payload.encode(), "sha256").hexdigest()
