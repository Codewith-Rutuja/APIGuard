from .db import get_apiguard_connection


def update_scan_status(scan_id, status, completed_at=None):
    connection = get_apiguard_connection()

    try:
        connection.execute(
            """
            UPDATE scans
            SET status = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (
                status,
                completed_at,
                scan_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()
