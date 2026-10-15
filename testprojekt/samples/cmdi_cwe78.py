# Testprojekt-Sample (absichtlich verwundbar, nur fuer Offline-Tests).
# CWE-78 Command-Injection: f-String in shell=True.
import subprocess


def ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout
