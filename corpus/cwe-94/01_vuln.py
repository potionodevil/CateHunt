# Copyright (c) 2026 R.S. - Alle Rechte vorbehalten. Kopieren oder Veraendern ohne Genehmigung nicht erlaubt.
# Code Injection (CWE-94, absichtlich verwundbar): eval auf User-Input.
def calc(expr: str):
    return eval(expr)
