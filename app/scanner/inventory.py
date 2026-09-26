import re

from ..engine.finding import Finding
from ..engine.owasp import get_category
from ..engine.severity import classify_severity
from .orchestrator import SecurityCheck


def path_matches_template(observed_path, declared_path):
    """
    Compare an observed concrete path against an OpenAPI-style path template.

    Example:
        /orders/1003
        matches
        /orders/{order_id}
    """

    observed_parts = observed_path.strip("/").split("/")
    declared_parts = declared_path.strip("/").split("/")

    if len(observed_parts) != len(declared_parts):
        return False

    for observed, declared in zip(observed_parts, declared_parts):
        if declared.startswith("{") and declared.endswith("}"):
            continue

        if observed != declared:
            return False

    return True


class InventoryCheck(SecurityCheck):
    name = "Improper Inventory Management"

    def __init__(self, observed_paths):
        self.observed_paths = observed_paths

    def run(self, context):
        if not self.observed_paths:
            return None

        declared_paths = {
            endpoint["path"]
            for endpoint in context.openapi_endpoints
        }

        undocumented = []

        for observed_path in self.observed_paths:
            matched = any(
                path_matches_template(
                    observed_path,
                    declared_path,
                )
                for declared_path in declared_paths
            )

            if not matched:
                undocumented.append(observed_path)

        undocumented = sorted(set(undocumented))

        if not undocumented:
            return None

        category = get_category("API9")

        severity = classify_severity(
            exploitability=1,
            data_sensitivity=2,
            authorization_impact=1,
        )

        return Finding(
            finding_id="APG-INVENTORY-001",
            title=category["name"],
            description=(
                "A reachable API endpoint was observed outside the "
                "declared API inventory."
            ),
            severity=severity,
            owasp_category=category["id"],
            endpoint=undocumented[0],
            method="GET",
            evidence=(
                "Undocumented reachable endpoint(s): "
                + ", ".join(undocumented)
            ),
            impact=(
                "Undocumented or unmanaged endpoints may bypass normal "
                "security review, monitoring, lifecycle management, "
                "or access-control validation."
            ),
            remediation=(
                "Maintain an authoritative API inventory and ensure "
                "deployed endpoints are documented, reviewed, monitored, "
                "and included in the API security lifecycle."
            ),
        )
