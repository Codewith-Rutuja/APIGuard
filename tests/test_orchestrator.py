import pytest

from app.scanner.orchestrator import (
    ScanContext,
    SecurityCheck,
)


def test_scan_context_defaults():
    context = ScanContext(
        scan_id=47,
        base_url="http://127.0.0.1:5000",
    )

    assert context.scan_id == 47
    assert context.base_url == "http://127.0.0.1:5000"
    assert context.endpoints == []
    assert context.findings == []
    assert context.authenticated is False
    assert context.auth_token is None


def test_security_check_requires_implementation():
    check = SecurityCheck()

    with pytest.raises(NotImplementedError):
        check.run(
            ScanContext(
                scan_id=47,
                base_url="http://127.0.0.1:5000",
            )
        )
