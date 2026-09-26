from dataclasses import dataclass


@dataclass
class ScanTarget:
    base_url: str
    username: str
    password: str
    customer_id: int

    # Dedicated controlled-lab identity used only for
    # authentication security testing.
    authentication_test_username: str = "api2_lab"
    authentication_test_password: str = "APIGuard-LAB-BYPASS-2026"
    authentication_test_valid_password: str = "Api2LabPass!2026"
