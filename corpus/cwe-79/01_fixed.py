# Escaped Output (CWE-79, Fix)
from flask import request
from markupsafe import escape


def profile():
    name = request.args.get("name", "")
    return "<h1>Hallo " + escape(name) + "</h1>"
