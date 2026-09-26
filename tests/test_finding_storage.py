from app.database import get_apiguard_connection
from app.database.findings import save_finding
from app.engine.finding import Finding


def test_save_finding():
    connection = get_apiguard_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO targets (
                name,
                base_url,
                environment,
                scope,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "BOLA Storage Test",
                "http://127.0.0.1:5000",
                "controlled-lab",
                "/api/v1/orders/*",
                "2026-09-25T00:00:00Z",
            ),
        )

        target_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO scans (
                target_id,
                status,
                started_at,
                scanner_version
            )
            VALUES (?, ?, ?, ?)
            """,
            (target_id, "completed", "2026-09-25T00:00:00Z", "APIGuard-0.1.0"),
        )

        scan_id = cursor.lastrowid
        connection.commit()

    finally:
        connection.close()

    finding = Finding(
        finding_id="APG-TEST-001",
        title="BOLA Storage Test",
        description="Database persistence test.",
        severity="High",
        owasp_category="API1:2023",
        endpoint="/api/v1/orders/1003",
        method="GET",
        evidence="Test evidence",
        impact="Test impact",
        remediation="Test remediation",
    )

    finding_id = save_finding(scan_id, finding)

    assert finding_id is not None

    connection = get_apiguard_connection()

    try:
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["owasp_category"] == "API1:2023"
    assert row["severity"] == "High"
