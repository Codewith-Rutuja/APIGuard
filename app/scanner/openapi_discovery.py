import requests
from urllib.parse import urljoin


def normalize_api_path(path, server_url):
    server_path = server_url.rstrip("/")

    if server_path and server_path != "/" and path.startswith(server_path + "/"):
        return path[len(server_path):]

    if server_path and path == server_path:
        return "/"

    return path


def discover_openapi_endpoints(spec, base_url):
    endpoints = []

    server_url = spec.get("servers", [{}])[0].get("url", "/")

    if not server_url.endswith("/"):
        server_url += "/"

    for path, path_item in spec.get("paths", {}).items():
        normalized_path = normalize_api_path(
            path,
            server_url,
        )

        for method, operation in path_item.items():
            if method.lower() not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            }:
                continue

            if not isinstance(operation, dict):
                continue

            security = operation.get(
                "security",
                spec.get("security", []),
            )

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": normalized_path,
                    "url": urljoin(
                        base_url.rstrip("/") + "/",
                        server_url.lstrip("/") + path.lstrip("/"),
                    ),
                    "auth_required": bool(security),
                    "summary": operation.get("summary", ""),
                    "tags": operation.get("tags", []),
                }
            )

    return endpoints


def fetch_openapi_endpoints(
    base_url,
    spec_path="/api/v1/openapi.json",
):
    url = urljoin(
        base_url.rstrip("/") + "/",
        spec_path.lstrip("/"),
    )

    response = requests.get(
        url,
        timeout=5,
    )

    response.raise_for_status()

    return discover_openapi_endpoints(
        response.json(),
        base_url,
    )
