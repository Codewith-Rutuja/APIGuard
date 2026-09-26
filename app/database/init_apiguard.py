from .db import get_apiguard_connection


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    environment TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    scanner_version TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    source TEXT NOT NULL,
    authenticated INTEGER NOT NULL DEFAULT 0,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    endpoint_id INTEGER,
    finding_key TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    owasp_category TEXT,
    cwe TEXT,
    evidence TEXT,
    impact TEXT,
    remediation TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    request_data TEXT,
    response_data TEXT,
    expected_behavior TEXT,
    observed_behavior TEXT,
    captured_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS test_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    test_case TEXT NOT NULL,
    endpoint_id INTEGER,
    status TEXT NOT NULL,
    details TEXT,
    executed_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_target_id
ON scans(target_id);

CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id
ON endpoints(scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id
ON findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_severity
ON findings(severity);

CREATE INDEX IF NOT EXISTS idx_findings_status
ON findings(status);

CREATE INDEX IF NOT EXISTS idx_evidence_finding_id
ON evidence(finding_id);

CREATE INDEX IF NOT EXISTS idx_test_runs_scan_id
ON test_runs(scan_id);
"""


def initialize_apiguard_database():
    connection = get_apiguard_connection()

    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_apiguard_database()
    print("APIGuard database initialized successfully.")
