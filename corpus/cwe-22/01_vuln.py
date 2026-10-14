# Copyright (c) 2026 R.S. - Alle Rechte vorbehalten. Kopieren oder Veraendern ohne Genehmigung nicht erlaubt.
# Path Traversal (CWE-22, absichtlich verwundbar): user input unnormalisiert in Dateipfad.
import os

BASE_DIR = "/var/app/data"


def read_doc(filename: str) -> bytes:
    path = os.path.join(BASE_DIR, filename)
    with open(path, "rb") as f:
        return f.read()
