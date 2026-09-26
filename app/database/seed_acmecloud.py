from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

from .db import get_acmecloud_connection


def seed_database():
    connection = get_acmecloud_connection()

    try:
        now = datetime.now(timezone.utc).isoformat()

        customers = [
            (
                101,
                "Alice Rao",
                "alice@example.test",
                "+91-9000000101",
                "Bengaluru, Karnataka",
                now,
            ),
            (
                102,
                "Bob Mehta",
                "bob@example.test",
                "+91-9000000102",
                "Mumbai, Maharashtra",
                now,
            ),
        ]

        connection.executemany(
            """
            INSERT OR IGNORE INTO customers
            (id, name, email, phone, address, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            customers,
        )

        users = [
            (
                1,
                "admin",
                generate_password_hash("AdminLabPass!2026"),
                "administrator",
                None,
                "admin@example.test",
                1,
                1,
                "secure",
                now,
            ),
            (
                2,
                "analyst",
                generate_password_hash("AnalystLabPass!2026"),
                "analyst",
                None,
                "analyst@example.test",
                1,
                0,
                "secure",
                now,
            ),
            (
                101,
                "alice",
                generate_password_hash("AliceLabPass!2026"),
                "customer",
                101,
                "alice@example.test",
                1,
                0,
                "secure",
                now,
            ),
            (
                102,
                "bob",
                generate_password_hash("BobLabPass!2026"),
                "customer",
                102,
                "bob@example.test",
                1,
                0,
                "secure",
                now,
            ),
            (
                900,
                "api2_lab",
                generate_password_hash("Api2LabPass!2026"),
                "customer",
                101,
                "api2-lab@example.test",
                1,
                0,
                "weak_lab",
                now,
            ),
        ]

        connection.executemany(
            """
            INSERT OR IGNORE INTO users
            (
                id,
                username,
                password_hash,
                role,
                customer_id,
                email,
                is_active,
                is_admin,
                auth_policy,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            users,
        )

        orders = [
            (
                1001,
                101,
                "AC-ORD-1001",
                "processing",
                2499.00,
                "Enterprise security assessment package",
                now,
            ),
            (
                1002,
                101,
                "AC-ORD-1002",
                "completed",
                899.00,
                "Cloud monitoring subscription",
                now,
            ),
            (
                1003,
                102,
                "AC-ORD-1003",
                "processing",
                1499.00,
                "API integration package",
                now,
            ),
        ]

        connection.executemany(
            """
            INSERT OR IGNORE INTO orders
            (id, customer_id, order_number, status, amount, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            orders,
        )

        audit_events = [
            (
                1,
                "system.initialization",
                "acmecloud",
                now,
                "bootstrap-001",
            ),
            (
                2,
                "user.login",
                "user:analyst",
                now,
                "bootstrap-002",
            ),
        ]

        connection.executemany(
            """
            INSERT INTO audit_events
            (actor_id, action, resource, timestamp, correlation_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            audit_events,
        )

        connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":
    seed_database()
    print("AcmeCloud lab data seeded successfully.")
