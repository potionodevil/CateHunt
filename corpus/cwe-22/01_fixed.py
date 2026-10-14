# Copyright (c) 2026 R.S. - Alle Rechte vorbehalten. Kopieren oder Veraendern ohne Genehmigung nicht erlaubt.
# Path Traversal Fix (CWE-22): kanonisieren + Allowlist (commonpath-Nachweis am Sink).
import os

BASE_DIR = "/var/app/data"


def read_doc(filename: str) -> bytes:
    base = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("unguelter Pfad")
    with open(path, "rb") as f:
        return f.read()
