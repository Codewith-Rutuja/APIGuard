import pytest

from app.database import get_apiguard_connection
from app.scanner.config import ScanTarget
from app.scanner.runner import run_bola_scan


def test_scan_is_marked_failed_when_authentication_fails():
    target = ScanTarget(
        base_url="http://127.0.0.1:5000",
        username="alice",
        password="WrongPasswordForLab",
        customer_id=101,
    )

    with pytest.raises(RuntimeError):
        run_bola_scan(target=target, order_id=1003)

    connection = get_apiguard_connection()

    try:
        row = connection.execute(
            """
            SELECT status, completed_at
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["status"] == "failed"
    assert row["completed_at"] is not None
