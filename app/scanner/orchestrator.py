from dataclasses import dataclass, field


@dataclass
class ScanContext:
    scan_id: int
    base_url: str
    client: object | None = None
    endpoints: list = field(default_factory=list)
    openapi_endpoints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    authenticated: bool = False
    auth_token: str | None = None
    customer_id: int | None = None


class SecurityCheck:
    """Base contract for APIGuard security checks."""

    name = "Unnamed Security Check"

    def run(self, context):
        raise NotImplementedError(
            "Security checks must implement run()."
        )
