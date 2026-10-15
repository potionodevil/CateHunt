# Testprojekt-Sample (absichtlich verwundbar, nur fuer Offline-Tests).
# CWE-94 Code-Injection: eval auf User-Input.


def calc(expr: str):
    return eval(expr)
