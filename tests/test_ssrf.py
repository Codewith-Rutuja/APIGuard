from app.scanner.ssrf import SSRFCheck


class FakeClient:
    def request(self, method, path, headers=None, **kwargs):
        return {
            "response": {
                "status_code": 200,
                "body": '{"status":"fetched","upstream_status":200}',
            }
        }


class FakeContext:
    client = FakeClient()


def test_ssrf_detects_server_side_request():
    finding = SSRFCheck().run(FakeContext())

    assert finding is not None
    assert finding.finding_id == "APG-SSRF-001"
    assert finding.owasp_category == "API7:2023"
    assert finding.severity == "High"
