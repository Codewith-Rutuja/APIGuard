import json

from ..database import get_apiguard_connection
from ..database.endpoints import get_or_create_endpoint
from ..database.findings import save_finding
from ..database.evidence import save_evidence
from ..database.scans import update_scan_status
from ..utils import utc_now
from .authentication import AuthenticationCheck
from .misconfiguration import SecurityMisconfigurationCheck
from .property_authorization import PropertyAuthorizationCheck
from .resource_consumption import ResourceConsumptionCheck
from .checks import BOLACheck
from .config import ScanTarget
from .http_client import APIClient
from .inventory import InventoryCheck
from .orchestrator import ScanContext
from .openapi_discovery import fetch_openapi_endpoints
from .surface_discovery import discover_observed_surface


def create_scan(target):
    connection = get_apiguard_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO targets (
                name,
                base_url,
                environment,
                scope,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "AcmeCloud API",
                target.base_url,
                "controlled-lab",
                "/api/v1/*",
                utc_now(),
            ),
        )

        target_id = cursor.lastrowid

        cursor = connection.execute(
            """
            INSERT INTO scans (
                target_id,
                status,
                started_at,
                scanner_version
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                target_id,
                "running",
                utc_now(),
                "APIGuard-0.1.0",
            ),
        )

        scan_id = cursor.lastrowid
        connection.commit()

        return scan_id

    finally:
        connection.close()


def run_security_scan(target: ScanTarget, order_id: int):
    client = APIClient(target.base_url)

    scan_id = create_scan(target)

    try:
        # ---------------------------------------------------------
        # Phase 1: API discovery
        # ---------------------------------------------------------
        discovered_endpoints = fetch_openapi_endpoints(
            target.base_url
        )

        from .orchestrator import ScanContext

        context = ScanContext(
            scan_id=scan_id,
            base_url=target.base_url,
        )

        context.client = client
        context.openapi_endpoints = discovered_endpoints

        for discovered in discovered_endpoints:
            get_or_create_endpoint(
                scan_id=scan_id,
                method=discovered["method"],
                path=discovered["path"],
                source="openapi",
                authenticated=discovered["auth_required"],
            )

        # ---------------------------------------------------------
        # Phase 2: endpoint references used by security checks
        # ---------------------------------------------------------
        order_endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="GET",
            path="/orders/{order_id}",
            source="openapi",
            authenticated=True,
        )

        auth_endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="POST",
            path="/auth/login",
            source="openapi",
            authenticated=False,
        )

        # ---------------------------------------------------------
        # Phase 3: authentication
        # ---------------------------------------------------------
        login_result = client.request(
            "POST",
            "/api/v1/auth/login",
            headers={
                "Content-Type": "application/json",
            },
            json={
                "username": target.username,
                "password": target.password,
            },
        )

        if login_result["response"]["status_code"] != 200:
            raise RuntimeError(
                "Authentication failed during security scan."
            )

        token = json.loads(
            login_result["response"]["body"]
        )["access_token"]

        # ---------------------------------------------------------
        # Phase 4: security-check context
        # ---------------------------------------------------------
        context.authenticated = True
        context.auth_token = token
        context.customer_id = target.customer_id

        # ---------------------------------------------------------
        # Phase 5: BOLA detection
        # ---------------------------------------------------------
        bola_check = BOLACheck(
            order_id=order_id,
        )

        bola_finding = bola_check.run(context)

        if bola_finding is not None:
            finding_id = save_finding(
                scan_id,
                bola_finding,
                endpoint_id=order_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{bola_finding.method} {bola_finding.endpoint}",
                response_data=bola_finding.evidence,
                expected_behavior="The API should enforce object-level authorization for the requested resource.",
                observed_behavior=bola_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 6: authentication bypass detection
        # ---------------------------------------------------------
        auth_check = AuthenticationCheck(
            username=target.authentication_test_username,
            invalid_password=target.authentication_test_password,
        )

        auth_finding = auth_check.run(context)

        if auth_finding is not None:
            finding_id = save_finding(
                scan_id,
                auth_finding,
                endpoint_id=auth_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{auth_finding.method} {auth_finding.endpoint}",
                response_data=auth_finding.evidence,
                expected_behavior="Authentication should require valid credentials and reject unauthorized authentication attempts.",
                observed_behavior=auth_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 7: broken object property level authorization detection
        # ---------------------------------------------------------
        property_check = PropertyAuthorizationCheck()

        property_finding = property_check.run(context)

        profile_endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="GET",
            path="/profile",
            source="openapi",
            authenticated=True,
        )

        if property_finding is not None:
            finding_id = save_finding(
                scan_id,
                property_finding,
                endpoint_id=profile_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{property_finding.method} {property_finding.endpoint}",
                response_data=property_finding.evidence,
                expected_behavior="The API should expose only properties authorized for the requesting client.",
                observed_behavior=property_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 8: unrestricted resource consumption detection
        # ---------------------------------------------------------
        resource_check = ResourceConsumptionCheck(
            test_limit=100000,
        )

        resource_finding = resource_check.run(context)

        orders_collection_endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="GET",
            path="/orders",
            source="openapi",
            authenticated=True,
        )

        if resource_finding is not None:
            finding_id = save_finding(
                scan_id,
                resource_finding,
                endpoint_id=orders_collection_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{resource_finding.method} {resource_finding.endpoint}",
                response_data=resource_finding.evidence,
                expected_behavior="The API should enforce server-side resource limits regardless of client-supplied values.",
                observed_behavior=resource_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 8: security misconfiguration detection
        # ---------------------------------------------------------
        misconfiguration_check = SecurityMisconfigurationCheck(
            path="/api/v1/health",
        )

        misconfiguration_finding = misconfiguration_check.run(context)

        health_endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="GET",
            path="/health",
            source="openapi",
            authenticated=False,
        )

        if misconfiguration_finding is not None:
            finding_id = save_finding(
                scan_id,
                misconfiguration_finding,
                endpoint_id=health_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{misconfiguration_finding.method} {misconfiguration_finding.endpoint}",
                response_data=misconfiguration_finding.evidence,
                expected_behavior="Security-relevant HTTP configuration should include appropriate protective controls.",
                observed_behavior=misconfiguration_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 9: active API surface discovery and inventory validation
        # ---------------------------------------------------------
        observed_endpoints = discover_observed_surface(
            client
        )

        observed_paths = [
            endpoint.path
            for endpoint in observed_endpoints
        ]

        inventory_check = InventoryCheck(
            observed_paths=observed_paths
        )

        inventory_finding = inventory_check.run(context)

        if inventory_finding is not None:
            inventory_endpoint_id = get_or_create_endpoint(
                scan_id=scan_id,
                method=inventory_finding.method,
                path=inventory_finding.endpoint,
                source="active-discovery",
                authenticated=False,
            )

            finding_id = save_finding(
                scan_id,
                inventory_finding,
                endpoint_id=inventory_endpoint_id,
            )
            save_evidence(
                finding_id,
                request_data=f"{inventory_finding.method} {inventory_finding.endpoint}",
                response_data=inventory_finding.evidence,
                expected_behavior="All reachable API endpoints should be documented and governed in the API inventory.",
                observed_behavior=inventory_finding.evidence,
            )

        # ---------------------------------------------------------
        # Phase 9: complete scan
        # ---------------------------------------------------------
        update_scan_status(
            scan_id,
            "completed",
            utc_now(),
        )

        findings = []

        if bola_finding is not None:
            findings.append(bola_finding)

        if auth_finding is not None:
            findings.append(auth_finding)

        if property_finding is not None:
            findings.append(property_finding)

        if resource_finding is not None:
            findings.append(resource_finding)

        if misconfiguration_finding is not None:
            findings.append(misconfiguration_finding)

        if inventory_finding is not None:
            findings.append(inventory_finding)

        return findings

    except Exception:
        update_scan_status(
            scan_id,
            "failed",
            utc_now(),
        )
        raise


def run_bola_scan(target: ScanTarget, order_id: int):
    """Run only the BOLA check for backward compatibility."""

    client = APIClient(target.base_url)
    scan_id = create_scan(target)

    try:
        endpoint_id = get_or_create_endpoint(
            scan_id=scan_id,
            method="GET",
            path="/orders/{order_id}",
            source="openapi",
            authenticated=True,
        )

        result = client.request(
            "POST",
            "/api/v1/auth/login",
            headers={
                "Content-Type": "application/json",
            },
            json={
                "username": target.username,
                "password": target.password,
            },
        )

        if result["response"]["status_code"] != 200:
            raise RuntimeError(
                "Authentication failed during security scan."
            )

        token = json.loads(
            result["response"]["body"]
        )["access_token"]

        context = ScanContext(
            scan_id=scan_id,
            base_url=target.base_url,
        )

        context.client = client
        context.authenticated = True
        context.auth_token = token
        context.customer_id = target.customer_id

        check = BOLACheck(order_id=order_id)
        finding = check.run(context)

        findings = []

        if finding is not None:
            save_finding(
                scan_id,
                finding,
                endpoint_id=endpoint_id,
            )
            findings.append(finding)

        update_scan_status(
            scan_id,
            "completed",
            utc_now(),
        )

        return findings

    except Exception:
        update_scan_status(
            scan_id,
            "failed",
            utc_now(),
        )
        raise
