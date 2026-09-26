import json

from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class AuthenticationCheck(SecurityCheck):
    name = "Broken Authentication"

    def __init__(self, username, invalid_password):
        self.username = username
        self.invalid_password = invalid_password

    def run(self, context):
        response = context.client.request(
            "POST",
            "/api/v1/auth/login",
            headers={"Content-Type": "application/json"},
            json={
                "username": self.username,
                "password": self.invalid_password,
            },
        )["response"]

        # A successful authentication response to an invalid
        # credential indicates a potential authentication bypass.
        if response["status_code"] != 200:
            return None

        try:
            body = json.loads(response["body"])
        except (json.JSONDecodeError, TypeError):
            return None

        if not body.get("access_token"):
            return None

        category = get_category("API2")

        severity = classify_severity(
            exploitability=3,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-AUTH-001",
            title=category["name"],
            description=(
                "The API accepted an invalid credential and issued "
                "an authentication token."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/auth/login",
            method="POST",
            evidence=(
                f"Authentication succeeded for username={self.username} "
                "using an intentionally invalid credential."
            ),
            impact=(
                "An attacker may obtain an authenticated session "
                "without possessing the legitimate account password."
            ),
            remediation=(
                "Reject invalid credentials using strict server-side "
                "credential verification and issue tokens only after "
                "successful authentication."
            ),
        )
