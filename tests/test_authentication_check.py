from app.scanner.authentication import AuthenticationCheck
from app.scanner.http_client import APIClient
from app.scanner.orchestrator import ScanContext


def test_authentication_bypass_is_detected():
    client = APIClient("http://127.0.0.1:5000")

    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )
    context.client = client

    check = AuthenticationCheck(
        username="api2_lab",
        invalid_password="APIGuard-LAB-BYPASS-2026",
    )

    finding = check.run(context)

    assert finding is not None
    assert finding.finding_id == "APG-AUTH-001"
    assert finding.owasp_category == "API2:2023"
    assert finding.severity == "High"
    assert finding.method == "POST"
    assert finding.endpoint == "/api/v1/auth/login"


def test_secure_account_does_not_trigger_authentication_finding():
    client = APIClient("http://127.0.0.1:5000")

    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )
    context.client = client

    check = AuthenticationCheck(
        username="alice",
        invalid_password="APIGuard-LAB-BYPASS-2026",
    )

    finding = check.run(context)

    assert finding is None
