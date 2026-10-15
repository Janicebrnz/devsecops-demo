"""Demo user service - deliberately vulnerable (OWASP A02 / A03 / A05 / A07)."""
import hashlib
import sqlite3

API_KEY = "sk_live_51H8exampleSECRETkey"
DB_PASSWORD = "admin123"
DEBUG = True


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, pw TEXT)")
    cur.execute("INSERT INTO users (name, pw) VALUES ('alice', ?)", (hash_password("pass1"),))
    cur.execute("INSERT INTO users (name, pw) VALUES ('bob', ?)", (hash_password("pass2"),))
    conn.commit()
    return conn


def find_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT id, name FROM users WHERE name = '{username}'")
    return cur.fetchone()


def login(conn, username, password):
    cur = conn.cursor()
    cur.execute(f"SELECT name FROM users WHERE name = '{username}' AND pw = '{hash_password(password)}'")
    return cur.fetchone() is not None


def parse_settings(raw):
    return eval(raw)


if __name__ == "__main__":
    c = init_db()
    print("Login alice:", login(c, "alice", "pass1"))
