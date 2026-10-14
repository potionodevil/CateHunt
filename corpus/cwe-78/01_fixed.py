# Copyright (c) 2026 R.S. - Alle Rechte vorbehalten. Kopieren oder Veraendern ohne Genehmigung nicht erlaubt.
# Command Injection Fix (CWE-78): Argv-Liste ohne Shell (Sink nicht mehr erreichbar fuer Metazeichen).
import subprocess


def ping(host: str) -> str:
    result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True)
    return result.stdout
