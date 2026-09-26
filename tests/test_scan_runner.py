from app.database import get_apiguard_connection
from app.scanner.config import ScanTarget
from app.scanner.runner import run_bola_scan


def test_bola_scan_runner():
    target = ScanTarget(
        base_url="http://127.0.0.1:5000",
        username="alice",
        password="AliceLabPass!2026",
        customer_id=101,
    )

    findings = run_bola_scan(
        target=target,
        order_id=1003,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.finding_id == "APG-BOLA-001"
    assert finding.owasp_category == "API1:2023"
    assert finding.severity == "High"

    connection = get_apiguard_connection()

    try:
        row = connection.execute(
            """
            SELECT finding_key, title, severity, owasp_category
            FROM findings
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["finding_key"] == "APG-BOLA-001"
    assert row["severity"] == "High"
    assert row["owasp_category"] == "API1:2023"
