from app.scanner.checks import BOLACheck
from app.scanner.orchestrator import ScanContext


class FakeClient:
    def request(self, method, path, headers=None, json=None):
        return {
            "response": {
                "status_code": 200,
                "body": (
                    '{"order": {'
                    '"id": 1003, '
                    '"customer_id": 102, '
                    '"order_number": "AC-ORD-1003"'
                    '}}'
                ),
            }
        }


def test_bola_check_detects_cross_customer_access():
    context = ScanContext(
        scan_id=47,
        base_url="http://127.0.0.1:5000",
    )

    context.client = FakeClient()
    context.authenticated = True
    context.auth_token = "test-token"
    context.customer_id = 101

    check = BOLACheck(order_id=1003)

    finding = check.run(context)

    assert finding is not None
    assert finding.finding_id == "APG-BOLA-001"
    assert finding.severity == "High"
    assert finding.owasp_category == "API1:2023"


def test_bola_check_ignores_owned_object():
    class OwnedObjectClient:
        def request(self, method, path, headers=None, json=None):
            return {
                "response": {
                    "status_code": 200,
                    "body": (
                        '{"order": {'
                        '"id": 1001, '
                        '"customer_id": 101'
                        '}}'
                    ),
                }
            }

    context = ScanContext(
        scan_id=47,
        base_url="http://127.0.0.1:5000",
    )

    context.client = OwnedObjectClient()
    context.authenticated = True
    context.auth_token = "test-token"
    context.customer_id = 101

    check = BOLACheck(order_id=1001)

    finding = check.run(context)

    assert finding is None
