from app.database import get_apiguard_connection
from app.database.endpoints import get_endpoints, save_endpoint


def test_endpoint_storage():
    connection = get_apiguard_connection()

    try:
        scan = connection.execute(
            """
            SELECT id
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()

    assert scan is not None

    endpoint_id = save_endpoint(
        scan_id=scan["id"],
        method="GET",
        path="/api/v1/orders/{order_id}",
        source="manual",
        authenticated=True,
    )

    assert endpoint_id is not None

    endpoints = get_endpoints(scan["id"])

    matching = [
        endpoint
        for endpoint in endpoints
        if endpoint["id"] == endpoint_id
    ]

    assert len(matching) == 1

    endpoint = matching[0]

    assert endpoint["method"] == "GET"
    assert endpoint["path"] == "/api/v1/orders/{order_id}"
    assert endpoint["source"] == "manual"
    assert endpoint["authenticated"] == 1


def test_get_or_create_endpoint_reuses_existing_endpoint():
    from app.database.endpoints import get_or_create_endpoint

    connection = get_apiguard_connection()

    try:
        scan = connection.execute(
            """
            SELECT id
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()

    assert scan is not None

    first_id = get_or_create_endpoint(
        scan_id=scan["id"],
        method="GET",
        path="/api/v1/orders/{order_id}",
        source="scanner",
        authenticated=True,
    )

    second_id = get_or_create_endpoint(
        scan_id=scan["id"],
        method="GET",
        path="/api/v1/orders/{order_id}",
        source="scanner",
        authenticated=True,
    )

    assert first_id == second_id


def test_scan_inventory_includes_target_context():
    from app.database.endpoints import get_scan_inventory

    connection = get_apiguard_connection()

    try:
        scan = connection.execute(
            """
            SELECT id
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        connection.close()

    assert scan is not None

    inventory = get_scan_inventory(scan["id"])

    assert isinstance(inventory, list)
    assert len(inventory) >= 1

    endpoint = inventory[0]

    assert endpoint["target_name"] == "AcmeCloud API"
    assert endpoint["base_url"] == "http://127.0.0.1:5000"
    assert endpoint["environment"] == "controlled-lab"
    assert "path" in endpoint
    assert "method" in endpoint
