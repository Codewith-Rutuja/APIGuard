import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

APIGUARD_DB = PROJECT_ROOT / "data" / "apiguard.db"
ACMECLOUD_DB = PROJECT_ROOT / "lab" / "acmecloud.db"


def get_apiguard_connection():
    """Return a SQLite connection for APIGuard assessment data."""
    APIGUARD_DB.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(APIGUARD_DB)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def get_acmecloud_connection():
    """Return a SQLite connection for the AcmeCloud lab API."""
    ACMECLOUD_DB.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(ACMECLOUD_DB)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection
