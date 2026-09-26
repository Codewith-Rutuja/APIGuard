import json

from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity


def check_order_authorization(client, token, order_id, authenticated_customer_id):
    headers = {"Authorization": f"Bearer {token}"}

    result = client.request(
        "GET",
        f"/api/v1/orders/{order_id}",
        headers=headers,
    )

    response = result["response"]

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

    if returned_customer_id == authenticated_customer_id:
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
            "An authenticated customer was able to retrieve an order "
            "belonging to another customer."
        ),
        severity=severity,
        owasp_category=category["id"],
        endpoint=f"/api/v1/orders/{order_id}",
        method="GET",
        evidence=(
            f"Authenticated customer_id={authenticated_customer_id} "
            f"received order_id={order_id} owned by customer_id="
            f"{returned_customer_id}."
        ),
        impact=(
            "An attacker may access unauthorized customer order "
            "information by modifying an object identifier."
        ),
        remediation=(
            "Enforce server-side object ownership checks before "
            "returning order data."
        ),
    )
