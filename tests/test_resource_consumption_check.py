from app.scanner.orchestrator import ScanContext
from app.scanner.resource_consumption import ResourceConsumptionCheck


class MockClient:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code

    def request(self, method, path, headers=None, json=None):
        return {
            "request": {
                "method": method,
                "url": f"http://test{path}",
                "headers": headers or {},
                "json": json,
            },
            "response": {
                "status_code": self.status_code,
                "headers": {"Content-Type": "application/json"},
                "body": self.body,
            },
        }


def build_context(body, status_code=200):
    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )

    context.client = MockClient(body, status_code)
    context.authenticated = True
    context.auth_token = "test-token"
    context.customer_id = 101

    return context


def test_resource_consumption_detects_unrestricted_limit():
    context = build_context(
        """
        {
            "count": 0,
            "limit": 100000,
            "orders": []
        }
        """
    )

    finding = ResourceConsumptionCheck().run(context)

    assert finding is not None
    assert finding.finding_id == "APG-RESOURCE-001"
    assert finding.owasp_category == "API4:2023"
    assert finding.endpoint == "/api/v1/orders"
    assert finding.severity == "Medium"


def test_resource_consumption_allows_enforced_limit():
    context = build_context(
        """
        {
            "count": 20,
            "limit": 20,
            "orders": []
        }
        """
    )

    finding = ResourceConsumptionCheck().run(context)

    assert finding is None


def test_resource_consumption_ignores_failed_request():
    context = build_context(
        '{"error": "unauthorized"}',
        status_code=401,
    )

    finding = ResourceConsumptionCheck().run(context)

    assert finding is None
