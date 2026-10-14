# SQL-Injection (CWE-89, absichtlich verwundbar)
import sqlite3

db = sqlite3.connect("app.db")


def find_user(name: str):
    return db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
