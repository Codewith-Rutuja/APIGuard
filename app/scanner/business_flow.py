from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class BusinessFlowCheck(SecurityCheck):
    name = "Sensitive Business Flow Protection"

    def run(self, context):
        if not context.authenticated or not context.auth_token:
            return None

        response = context.client.request(
            "POST",
            "/api/v1/orders/1001/cancel",
            headers={
                "Authorization": f"Bearer {context.auth_token}",
                "Content-Type": "application/json",
            },
        )["response"]

        if response["status_code"] != 200:
            return None

        category = get_category("API6")

        severity = classify_severity(
            exploitability=2,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-FLOW-001",
            title=category["name"],
            description=(
                "A sensitive order cancellation workflow accepted a "
                "request without enforcing an appropriate business-state control."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/orders/{order_id}/cancel",
            method="POST",
            evidence=(
                "The authenticated customer account received HTTP 200 "
                "from the order cancellation workflow."
            ),
            impact=(
                "Abuse of sensitive business workflows may allow unauthorized "
                "or excessive actions that affect business operations."
            ),
            remediation=(
                "Enforce server-side business rules, state transitions, "
                "authorization, and appropriate anti-automation controls "
                "for sensitive business workflows."
            ),
        )
