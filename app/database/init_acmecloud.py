from .db import get_acmecloud_connection


SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('customer', 'analyst', 'administrator')),
    customer_id INTEGER,
    email TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_admin INTEGER NOT NULL DEFAULT 0,
    auth_policy TEXT NOT NULL DEFAULT 'secure',
    created_at TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    order_number TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    FOREIGN KEY (actor_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_users_customer_id
ON users(customer_id);

CREATE INDEX IF NOT EXISTS idx_orders_customer_id
ON orders(customer_id);

CREATE INDEX IF NOT EXISTS idx_audit_actor_id
ON audit_events(actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp
ON audit_events(timestamp);
"""


def initialize_acmecloud_database():
    connection = get_acmecloud_connection()

    try:
        connection.executescript(SCHEMA)

        columns = connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()

        column_names = {column["name"] for column in columns}

        if "auth_policy" not in column_names:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN auth_policy TEXT NOT NULL DEFAULT 'secure'
                """
            )

        connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_acmecloud_database()
    print("AcmeCloud database initialized successfully.")
