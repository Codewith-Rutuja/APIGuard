from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


class FunctionAuthorizationCheck(SecurityCheck):
    name = "Broken Function Level Authorization"

    def run(self, context):
        if not context.authenticated or not context.auth_token:
            return None

        response = context.client.request(
            "GET",
            "/api/v1/admin/users",
            headers={
                "Authorization": f"Bearer {context.auth_token}",
            },
        )["response"]

        if response["status_code"] != 200:
            return None

        category = get_category("API5")

        severity = classify_severity(
            exploitability=2,
            data_sensitivity=2,
            authorization_impact=2,
        )

        return Finding(
            finding_id="APG-FUNC-001",
            title=category["name"],
            description=(
                "An authenticated non-administrator account was able to "
                "access an administrator-only API function."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint="/api/v1/admin/users",
            method="GET",
            evidence=(
                "Customer account 'alice' received HTTP 200 from the "
                "administrator-only user management endpoint."
            ),
            impact=(
                "A lower-privileged user may access administrative "
                "functionality that should be restricted by role."
            ),
            remediation=(
                "Enforce server-side role authorization on administrative "
                "functions and require the administrator role before "
                "processing the request."
            ),
        )
