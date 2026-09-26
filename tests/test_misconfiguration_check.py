from app.scanner.http_client import APIClient
from app.scanner.misconfiguration import SecurityMisconfigurationCheck
from app.scanner.orchestrator import ScanContext


def test_security_misconfiguration_is_detected():
    client = APIClient("http://127.0.0.1:5000")

    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )
    context.client = client

    check = SecurityMisconfigurationCheck()

    finding = check.run(context)

    assert finding is not None
    assert finding.finding_id == "APG-CONFIG-001"
    assert finding.owasp_category == "API8:2023"
    assert finding.method == "GET"
    assert finding.endpoint == "/api/v1/health"


def test_secure_headers_do_not_trigger_finding():
    class MockClient:
        def request(self, method, path):
            return {
                "response": {
                    "status_code": 200,
                    "headers": {
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                    },
                    "body": "{}",
                }
            }

    context = ScanContext(
        scan_id=1,
        base_url="http://example.test",
    )
    context.client = MockClient()

    check = SecurityMisconfigurationCheck()

    finding = check.run(context)

    assert finding is None
