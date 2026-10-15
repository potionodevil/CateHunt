# Testprojekt-Sample (harmlos): Referenz fuer "kein Befund".
# Erwartung: Stufe 1 clean, keine Signale, deterministisch confirm/E1
# (Fallback schliesst nie, auch nicht bei sauberem Code).


def add(a: int, b: int) -> int:
    return a + b
