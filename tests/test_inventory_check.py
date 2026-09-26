from app.scanner.inventory import InventoryCheck, path_matches_template
from app.scanner.orchestrator import ScanContext


def test_parameterized_path_matches_openapi_template():
    assert path_matches_template(
        "/orders/1003",
        "/orders/{order_id}",
    )


def test_inventory_detects_undocumented_endpoint():
    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )

    context.openapi_endpoints = [
        {"path": "/health"},
        {"path": "/profile"},
        {"path": "/orders/{order_id}"},
    ]

    check = InventoryCheck(
        observed_paths=[
            "/health",
            "/profile",
            "/orders/1003",
            "/internal/debug",
        ]
    )

    finding = check.run(context)

    assert finding is not None
    assert finding.finding_id == "APG-INVENTORY-001"
    assert finding.owasp_category == "API9:2023"
    assert finding.endpoint == "/internal/debug"


def test_inventory_does_not_flag_documented_parameterized_endpoint():
    context = ScanContext(
        scan_id=1,
        base_url="http://127.0.0.1:5000",
    )

    context.openapi_endpoints = [
        {"path": "/orders/{order_id}"},
    ]

    check = InventoryCheck(
        observed_paths=["/orders/1003"]
    )

    finding = check.run(context)

    assert finding is None
