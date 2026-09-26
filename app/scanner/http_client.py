import requests


class APIClient:
    """Controlled HTTP client used by APIGuard security checks."""

    def __init__(self, base_url, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method, path, headers=None, json=None):
        url = f"{self.base_url}{path}"

        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            json=json,
            timeout=self.timeout,
        )

        return {
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": headers or {},
                "json": json,
            },
            "response": {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            },
        }
