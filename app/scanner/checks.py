import json

from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class BOLACheck(SecurityCheck):
    name = "Broken Object Level Authorization"

    def __init__(self, order_id):
        self.order_id = order_id

    def run(self, context):
        if not context.authenticated or not context.auth_token:
            return None

        headers = {
            "Authorization": f"Bearer {context.auth_token}"
        }

        response = context.client.request(
            "GET",
            f"/api/v1/orders/{self.order_id}",
            headers=headers,
        )["response"]

        if response["status_code"] != 200:
            return None

        try:
            body = json.loads(response["body"])
            order = body.get("order", {})
        except (json.JSONDecodeError, TypeError):
            return None

        returned_customer_id = order.get("customer_id")

        if returned_customer_id is None:
            return None

        if returned_customer_id == context.customer_id:
            return None

        category = get_category("API1")

        severity = classify_severity(
            exploitability=3,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-BOLA-001",
            title=category["name"],
            description=(
                "An authenticated customer was able to retrieve "
                "an order belonging to another customer."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint=f"/api/v1/orders/{self.order_id}",
            method="GET",
            evidence=(
                f"Authenticated customer_id={context.customer_id} "
                f"received order_id={self.order_id} owned by "
                f"customer_id={returned_customer_id}."
            ),
            impact=(
                "An attacker may access unauthorized customer "
                "order information by modifying an object identifier."
            ),
            remediation=(
                "Enforce server-side object ownership checks before "
                "returning order data."
            ),
        )
