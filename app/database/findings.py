from .db import get_apiguard_connection
from ..utils import utc_now


def save_finding(scan_id, finding, endpoint_id=None, status="Open"):
    connection = get_apiguard_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO findings (
                scan_id,
                endpoint_id,
                finding_key,
                title,
                description,
                severity,
                owasp_category,
                evidence,
                impact,
                remediation,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                endpoint_id,
                finding.finding_id,
                finding.title,
                finding.description,
                finding.severity,
                finding.owasp_category,
                finding.evidence,
                finding.impact,
                finding.remediation,
                status,
                utc_now(),
            ),
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()
