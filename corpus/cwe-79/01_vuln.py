# Reflected XSS (CWE-79, absichtlich verwundbar)
from flask import request


def profile():
    name = request.args.get("name", "")
    return "<h1>Hallo " + name + "</h1>"
