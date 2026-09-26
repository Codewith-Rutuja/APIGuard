from app.scanner.openapi_discovery import discover_openapi_endpoints


def test_discover_openapi_endpoints():
    spec = {
        "openapi": "3.0.3",
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "Authenticate a user",
                    "tags": ["Authentication"],
                }
            },
            "/profile": {
                "get": {
                    "summary": "Get authenticated profile",
                    "security": [{"bearerAuth": []}],
                    "tags": ["Identity"],
                }
            },
            "/orders/{order_id}": {
                "get": {
                    "summary": "Retrieve an order",
                    "security": [{"bearerAuth": []}],
                    "tags": ["Orders"],
                }
            },
        },
    }

    endpoints = discover_openapi_endpoints(
        spec,
        "http://127.0.0.1:5000",
    )

    assert len(endpoints) == 3

    login = next(
        item for item in endpoints
        if item["path"] == "/auth/login"
    )

    profile = next(
        item for item in endpoints
        if item["path"] == "/profile"
    )

    order = next(
        item for item in endpoints
        if item["path"] == "/orders/{order_id}"
    )

    assert login["method"] == "POST"
    assert login["auth_required"] is False

    assert profile["method"] == "GET"
    assert profile["auth_required"] is True

    assert order["method"] == "GET"
    assert order["auth_required"] is True
    assert order["tags"] == ["Orders"]


def test_discovery_ignores_non_operation_fields():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                },
                "parameters": [
                    {
                        "name": "unused",
                        "in": "query",
                    }
                ],
            }
        },
    }

    endpoints = discover_openapi_endpoints(
        spec,
        "http://127.0.0.1:5000",
    )

    assert len(endpoints) == 1
    assert endpoints[0]["method"] == "GET"
    assert endpoints[0]["path"] == "/health"
