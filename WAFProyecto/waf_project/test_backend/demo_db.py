"""
Vulnerable SQLite DB setup for the demo backend.
Creates and seeds a fake database with users, products, and orders.
This DB is intentionally queried WITHOUT parameterization to demo SQLi.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vuln_demo.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_demo_db():
    """Create tables and seed fake data if they don't exist."""
    conn = get_conn()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            role     TEXT DEFAULT 'user',
            created  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Products table
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            price    REAL,
            category TEXT,
            stock    INTEGER DEFAULT 10
        )
    """)

    # Orders table
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            product_id INTEGER,
            amount     INTEGER,
            total      REAL,
            status     TEXT DEFAULT 'pending'
        )
    """)

    # Seed users (only if empty)
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ("admin",   "S3cr3t@Admin2024!",  "admin@shopvuln.local",   "admin"),
            ("alice",   "alice_pass_123",     "alice@shopvuln.local",   "user"),
            ("bob",     "hunter2",            "bob@shopvuln.local",     "user"),
            ("charlie", "qwerty456",          "charlie@shopvuln.local", "user"),
            ("dbadmin", "Sup3rDB_Pass!",      "dba@shopvuln.local",     "admin"),
        ]
        c.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)", users
        )

    # Seed products (only if empty)
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        products = [
            ("Laptop Pro X", 1299.99, "electronics", 5),
            ("Wireless Mouse", 29.99, "electronics", 50),
            ("Python Book",   49.99, "books", 30),
            ("USB-C Hub",     39.99, "electronics", 20),
            ("Mechanical Keyboard", 89.99, "electronics", 15),
            ("Coffee Mug",    12.99, "home", 100),
            ("Webcam HD",     79.99, "electronics", 8),
            ("Monitor 4K",  499.99, "electronics", 3),
        ]
        c.executemany(
            "INSERT INTO products (name, price, category, stock) VALUES (?,?,?,?)", products
        )

    conn.commit()
    conn.close()
    print(f"[DemoDB] SQLite initialized at {DB_PATH}")
