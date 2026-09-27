from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class SSRFCheck(SecurityCheck):
    name = "Server Side Request Forgery"

    def run(self, context):
        response = context.client.request(
            "POST",
            "/api/v1/internal/fetch",
            headers={
                "Content-Type": "application/json",
            },
            json={
                "url": "http://127.0.0.1:5000/api/v1/health",
            },
        )["response"]

        if response["status_code"] != 200:
            return None

        category = get_category("API7")

        severity = classify_severity(
            exploitability=2,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-SSRF-001",
            title=category["name"],
            description=(
                "The API server performs an outbound HTTP request to a "
                "client-supplied URL without validating the destination."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/internal/fetch",
            method="POST",
            evidence=(
                "The server accepted a client-supplied URL and returned "
                "the upstream HTTP status."
            ),
            impact=(
                "An attacker may cause the server to access unintended "
                "internal or external resources."
            ),
            remediation=(
                "Restrict outbound destinations using an allowlist, "
                "validate and normalize URLs, block private and loopback "
                "addresses, and apply network-level egress controls."
            ),
        )
