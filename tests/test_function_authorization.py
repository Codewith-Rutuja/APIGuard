from app.scanner.function_authorization import FunctionAuthorizationCheck


class FakeClient:
    def request(self, method, path, headers=None, **kwargs):
        return {
            "response": {
                "status_code": 200,
                "body": '{"service":"AcmeCloud Admin API"}',
            }
        }


class FakeContext:
    authenticated = True
    auth_token = "test-token"
    client = FakeClient()


def test_function_authorization_detects_admin_access():
    finding = FunctionAuthorizationCheck().run(FakeContext())

    assert finding is not None
    assert finding.finding_id == "APG-FUNC-001"
    assert finding.owasp_category == "API5:2023"
    assert finding.severity == "High"
