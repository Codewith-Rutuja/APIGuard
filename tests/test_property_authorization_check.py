from app.scanner.orchestrator import ScanContext
from app.scanner.property_authorization import PropertyAuthorizationCheck


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


def build_context(body):
    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )

    context.client = MockClient(body)
    context.authenticated = True
    context.auth_token = "test-token"
    context.customer_id = 101

    return context


def test_property_authorization_detects_restricted_properties():
    context = build_context(
        """
        {
            "user": {
                "id": 101,
                "username": "alice",
                "email": "alice@example.test",
                "customer_id": 101,
                "role": "customer",
                "is_admin": false
            }
        }
        """
    )

    finding = PropertyAuthorizationCheck().run(context)

    assert finding is not None
    assert finding.finding_id == "APG-PROP-001"
    assert finding.owasp_category == "API3:2023"
    assert finding.endpoint == "/api/v1/profile"
    assert "is_admin" in finding.evidence


def test_property_authorization_allows_public_profile_properties():
    context = build_context(
        """
        {
            "user": {
                "id": 101,
                "username": "alice",
                "email": "alice@example.test",
                "customer_id": 101
            }
        }
        """
    )

    finding = PropertyAuthorizationCheck().run(context)

    assert finding is None


def test_property_authorization_secure_profile_has_no_finding():
    context = build_context(
        """
        {
            "user": {
                "id": 101,
                "username": "alice",
                "email": "alice@example.test",
                "customer_id": 101
            }
        }
        """
    )

    finding = PropertyAuthorizationCheck().run(context)

    assert finding is None
