import json

from app.scanner.bola import check_order_authorization
from app.scanner.config import ScanTarget
from app.scanner.http_client import APIClient


def login(client, username, password):
    result = client.request(
        "POST",
        "/api/v1/auth/login",
        headers={"Content-Type": "application/json"},
        json={
            "username": username,
            "password": password,
        },
    )

    assert result["response"]["status_code"] == 200

    return json.loads(
        result["response"]["body"]
    )["access_token"]


def test_bola_detection():
    target = ScanTarget(
        base_url="http://127.0.0.1:5000",
        username="alice",
        password="AliceLabPass!2026",
        customer_id=101,
    )

    client = APIClient(target.base_url)

    token = login(
        client,
        target.username,
        target.password,
    )

    finding = check_order_authorization(
        client=client,
        token=token,
        order_id=1003,
        authenticated_customer_id=target.customer_id,
    )

    assert finding is not None
    assert finding.finding_id == "APG-BOLA-001"
    assert finding.owasp_category == "API1:2023"
    assert finding.severity == "High"


def test_bola_detector_allows_owned_order():
    from app.scanner.bola import check_order_authorization
    from app.scanner.config import ScanTarget
    from app.scanner.http_client import APIClient

    target = ScanTarget(
        base_url="http://127.0.0.1:5000",
        username="alice",
        password="AliceLabPass!2026",
        customer_id=101,
    )

    client = APIClient(target.base_url)

    login = client.request(
        "POST",
        "/api/v1/auth/login",
        headers={"Content-Type": "application/json"},
        json={
            "username": target.username,
            "password": target.password,
        },
    )

    import json

    token = json.loads(
        login["response"]["body"]
    )["access_token"]

    finding = check_order_authorization(
        client=client,
        token=token,
        order_id=1001,
        authenticated_customer_id=101,
    )

    assert finding is None
