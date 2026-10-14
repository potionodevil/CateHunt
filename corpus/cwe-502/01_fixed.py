# Sicheres Parsen ohne pickle (CWE-502, Fix)
import json


def load_session(data: bytes):
    return json.loads(data.decode("utf-8"))
