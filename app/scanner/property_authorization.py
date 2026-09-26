from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class PropertyAuthorizationCheck(SecurityCheck):
    name = "Broken Object Property Level Authorization"

    RESTRICTED_PROPERTIES = {
        "is_admin",
        "is_active",
        "role",
    }

    def run(self, context):
        if not context.authenticated or not context.auth_token:
            return None

        response = context.client.request(
            "GET",
            "/api/v1/profile",
            headers={
                "Authorization": f"Bearer {context.auth_token}",
            },
        )["response"]

        if response["status_code"] != 200:
            return None

        body = response.get("body", "")

        try:
            import json
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None

        user = data.get("user", {})

        exposed_properties = sorted(
            property_name
            for property_name in self.RESTRICTED_PROPERTIES
            if property_name in user
        )

        if not exposed_properties:
            return None

        category = get_category("API3")

        severity = classify_severity(
            exploitability=2,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-PROP-001",
            title=category["name"],
            description=(
                "An authenticated customer profile response exposes "
                "internal authorization properties that should not be "
                "returned to the customer."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/profile",
            method="GET",
            evidence=(
                "Restricted properties exposed in the authenticated "
                "profile response: "
                + ", ".join(exposed_properties)
            ),
            impact=(
                "Exposure of internal authorization metadata may reveal "
                "security-sensitive account state and implementation "
                "details to unprivileged users."
            ),
            remediation=(
                "Apply property-level response authorization and return "
                "only fields explicitly permitted for the authenticated "
                "user role."
            ),
        )
