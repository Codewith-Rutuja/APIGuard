import json

from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class ResourceConsumptionCheck(SecurityCheck):
    name = "Unrestricted Resource Consumption"

    def __init__(self, test_limit=100000):
        self.test_limit = test_limit

    def run(self, context):
        if not context.authenticated or not context.auth_token:
            return None

        response = context.client.request(
            "GET",
            f"/api/v1/orders?limit={self.test_limit}",
            headers={
                "Authorization": f"Bearer {context.auth_token}",
            },
        )["response"]

        if response["status_code"] != 200:
            return None

        try:
            body = json.loads(response["body"])
        except (json.JSONDecodeError, TypeError):
            return None

        accepted_limit = body.get("limit")

        if accepted_limit != self.test_limit:
            return None

        category = get_category("API4")

        severity = classify_severity(
            exploitability=2,
            data_sensitivity=1,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-RESOURCE-001",
            title=category["name"],
            description=(
                "The API accepted an excessively large collection limit "
                "without enforcing a server-side resource boundary."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/orders",
            method="GET",
            evidence=(
                f"The API accepted limit={self.test_limit} and returned "
                "HTTP 200 without enforcing a maximum server-side limit."
            ),
            impact=(
                "An attacker may request disproportionately large result "
                "sets, increasing database, memory, CPU, or network usage."
            ),
            remediation=(
                "Enforce a server-side maximum page size regardless of "
                "client-supplied limit values and apply appropriate "
                "pagination and resource controls."
            ),
        )
