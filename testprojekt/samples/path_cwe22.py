# Testprojekt-Sample (absichtlich verwundbar, nur fuer Offline-Tests).
# CWE-22 Path-Traversal: User-Input unnormalisiert in Dateipfad.
import os

BASE_DIR = "/var/app/data"


def read_doc(filename: str) -> bytes:
    path = os.path.join(BASE_DIR, filename)
    with open(path, "rb") as f:
        return f.read()
