# Testprojekt-Sample (absichtlich verwundbar, nur fuer Offline-Tests).
# CWE-89 SQL-Injection: String-Konkatenation statt parametrisierter Query.
import sqlite3

db = sqlite3.connect("app.db")


def find_user(name: str):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query).fetchall()
