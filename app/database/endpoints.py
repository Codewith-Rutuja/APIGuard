from .db import get_apiguard_connection
from ..utils import utc_now


def save_endpoint(
    scan_id,
    method,
    path,
    source="manual",
    authenticated=False,
):
    connection = get_apiguard_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO endpoints (
                scan_id,
                path,
                method,
                source,
                authenticated,
                discovered_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                path,
                method.upper(),
                source,
                int(authenticated),
                utc_now(),
            ),
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()


def get_endpoints(scan_id):
    connection = get_apiguard_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_id,
                path,
                method,
                source,
                authenticated,
                discovered_at
            FROM endpoints
            WHERE scan_id = ?
            ORDER BY path, method
            """,
            (scan_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def find_endpoint(scan_id, method, path):
    connection = get_apiguard_connection()

    try:
        row = connection.execute(
            """
            SELECT id
            FROM endpoints
            WHERE scan_id = ?
              AND method = ?
              AND path = ?
            LIMIT 1
            """,
            (scan_id, method.upper(), path),
        ).fetchone()

        return row["id"] if row else None

    finally:
        connection.close()


def get_or_create_endpoint(
    scan_id,
    method,
    path,
    source="scanner",
    authenticated=False,
):
    existing_id = find_endpoint(
        scan_id=scan_id,
        method=method,
        path=path,
    )

    if existing_id is not None:
        return existing_id

    return save_endpoint(
        scan_id=scan_id,
        method=method,
        path=path,
        source=source,
        authenticated=authenticated,
    )


def get_scan_inventory(scan_id):
    connection = get_apiguard_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                e.id,
                e.scan_id,
                e.path,
                e.method,
                e.source,
                e.authenticated,
                e.discovered_at,
                t.name AS target_name,
                t.base_url,
                t.environment,
                t.scope
            FROM endpoints e
            JOIN scans s
                ON s.id = e.scan_id
            JOIN targets t
                ON t.id = s.target_id
            WHERE e.scan_id = ?
            ORDER BY e.path, e.method
            """,
            (scan_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
