from dataclasses import dataclass

from .http_client import APIClient


@dataclass
class ObservedEndpoint:
    path: str
    method: str
    status_code: int


DEFAULT_CANDIDATE_PATHS = [
    "/api/v1/health",
    "/api/v1/profile",
    "/api/v1/orders/1003",
    "/api/v1/internal/debug",
    "/api/v1/admin/users",
    "/api/v1/audit/events",
]


def normalize_observed_path(path):
    """
    Convert a discovered API URL into the inventory path format.
    """

    prefix = "/api/v1"

    if path.startswith(prefix):
        normalized = path[len(prefix):]
        return normalized or "/"

    return path


def discover_observed_surface(
    client: APIClient,
    candidate_paths=None,
):
    """
    Probe a controlled candidate set and return reachable API paths.

    Candidate paths should come from an authorized scope, seed list,
    crawler, or other approved discovery source.
    """

    paths = candidate_paths or DEFAULT_CANDIDATE_PATHS
    observed = []

    for path in paths:
        response = client.request(
            "GET",
            path,
        )["response"]

        status_code = response["status_code"]

        if status_code not in {404, 405}:
            observed.append(
                ObservedEndpoint(
                    path=normalize_observed_path(path),
                    method="GET",
                    status_code=status_code,
                )
            )

    return observed
