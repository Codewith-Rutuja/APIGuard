from .db import get_apiguard_connection


def get_recent_scans(limit=20):
    connection = get_apiguard_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                scans.id,
                targets.name AS target_name,
                targets.base_url,
                scans.status,
                scans.started_at,
                scans.completed_at,
                scans.scanner_version
            FROM scans
            JOIN targets
                ON targets.id = scans.target_id
            ORDER BY scans.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
