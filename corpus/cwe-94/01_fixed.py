# Copyright (c) 2026 R.S. - Alle Rechte vorbehalten. Kopieren oder Veraendern ohne Genehmigung nicht erlaubt.
# Code Injection Fix (CWE-94): Allowlist-Dispatch statt eval (kein Code-Sink mehr).
import ast
import operator

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}


def calc(expr: str):
    tree = ast.parse(expr, mode="eval")
    node = tree.body
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS and isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
        return _OPS[type(node.op)](node.left.value, node.right.value)
    raise ValueError("nur einfache Zahlenausdruecke erlaubt")
