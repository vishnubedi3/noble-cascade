"""INTENTIONALLY VULNERABLE, SYNTHETIC FIXTURE. Never import or deploy.

The Noble Cascade verifier reads this file as inert text. Its isolated in-memory
SQLite test reproduces the SQL shape without calling the function below.
"""


def lookup_by_name(conn, name):
    # CWE-89: variable interpolation into SQL; fixture only, never executed.
    return conn.execute(f"SELECT name FROM users WHERE name = '{name}'").fetchall()
