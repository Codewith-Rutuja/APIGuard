from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Config:
    SECRET_KEY = "apiguard-lab-development-key"
    JWT_EXPIRATION_MINUTES = 30
    API_PREFIX = "/api/v1"
    PROJECT_ROOT = PROJECT_ROOT

    # Controlled APIGuard API3 laboratory mode.
    # True  = intentionally expose restricted profile properties.
    # False = return only customer-authorized profile properties.
    PROFILE_EXPOSE_INTERNAL_METADATA = False
