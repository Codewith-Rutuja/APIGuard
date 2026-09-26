from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class SecurityMisconfigurationCheck(SecurityCheck):
    name = "Security Misconfiguration"

    REQUIRED_HEADERS = (
        "X-Content-Type-Options",
        "X-Frame-Options",
    )

    def __init__(self, path="/api/v1/health"):
        self.path = path

    def run(self, context):
        response = context.client.request(
            "GET",
            self.path,
        )["response"]

        if response["status_code"] != 200:
            return None

        headers = {
            key.lower(): value
            for key, value in response["headers"].items()
        }

        missing_headers = [
            header
            for header in self.REQUIRED_HEADERS
            if header.lower() not in headers
        ]

        if not missing_headers:
            return None

        category = get_category("API8")

        severity = classify_severity(
            exploitability=1,
            data_sensitivity=1,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-CONFIG-001",
            title=category["name"],
            description=(
                "The API response is missing recommended security "
                "headers that help reduce common client-side attack risks."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint=self.path,
            method="GET",
            evidence=(
                "Missing security headers: "
                + ", ".join(missing_headers)
            ),
            impact=(
                "Missing response security controls may increase exposure "
                "to browser-side content interpretation and framing risks."
            ),
            remediation=(
                "Configure appropriate security response headers and "
                "verify their presence through automated security tests."
            ),
        )
