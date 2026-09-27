from app.scanner.business_flow import BusinessFlowCheck


class FakeClient:
    def request(self, method, path, headers=None, **kwargs):
        return {
            "response": {
                "status_code": 200,
                "body": '{"status":"accepted"}',
            }
        }


class FakeContext:
    authenticated = True
    auth_token = "test-token"
    client = FakeClient()


def test_business_flow_detects_unrestricted_cancellation():
    finding = BusinessFlowCheck().run(FakeContext())

    assert finding is not None
    assert finding.finding_id == "APG-FLOW-001"
    assert finding.owasp_category == "API6:2023"
    assert finding.severity == "High"
