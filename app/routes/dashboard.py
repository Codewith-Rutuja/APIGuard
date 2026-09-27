from flask import Blueprint, render_template, redirect

from ..database import get_apiguard_connection
from ..scanner.config import ScanTarget
from ..scanner.runner import run_security_scan


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/")
def dashboard():
    connection = get_apiguard_connection()

    try:
        scans = connection.execute(
            """
            SELECT
                scans.id,
                scans.status,
                scans.started_at,
                scans.completed_at,
                scans.scanner_version,
                targets.name AS target_name,
                targets.environment
            FROM scans
            JOIN targets ON targets.id = scans.target_id
            ORDER BY scans.id DESC
            LIMIT 8
            """
        ).fetchall()

        findings = connection.execute(
            """
            SELECT
                findings.id,
                findings.finding_key,
                findings.title,
                findings.severity,
                findings.owasp_category,
                findings.endpoint_id,
                findings.status,
                findings.created_at,
                endpoints.method,
                endpoints.path,
                endpoints.source
            FROM findings
            LEFT JOIN endpoints
                ON endpoints.id = findings.endpoint_id
            ORDER BY
                CASE findings.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                findings.id DESC
            LIMIT 20
            """
        ).fetchall()

        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) AS low
            FROM findings
            """
        ).fetchone()

        latest_scan = connection.execute(
            """
            SELECT id
            FROM scans
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        if latest_scan:
            inventory = connection.execute(
                """
                SELECT
                    path,
                    method,
                    source,
                    authenticated
                FROM endpoints
                WHERE scan_id = ?
                ORDER BY path, method
                """,
                (latest_scan["id"],),
            ).fetchall()
        else:
            inventory = []

        owasp = connection.execute(
            """
            SELECT
                owasp_category,
                COUNT(*) AS count
            FROM findings
            WHERE owasp_category IS NOT NULL
            GROUP BY owasp_category
            ORDER BY count DESC
            """
        ).fetchall()

    finally:
        connection.close()

    return render_template(
        "dashboard.html",
        scans=scans,
        findings=findings,
        summary=summary,
        inventory=inventory,
        owasp=owasp,
    )


@dashboard_bp.get("/findings/<int:finding_id>")
def finding_detail(finding_id):
    connection = get_apiguard_connection()

    try:
        finding = connection.execute(
            """
            SELECT
                findings.id,
                findings.finding_key,
                findings.title,
                findings.description,
                findings.severity,
                findings.owasp_category,
                findings.cwe,
                findings.evidence,
                findings.impact,
                findings.remediation,
                findings.status,
                findings.created_at,
                endpoints.method,
                endpoints.path,
                targets.name AS target_name,
                targets.environment
            FROM findings
            LEFT JOIN endpoints
                ON endpoints.id = findings.endpoint_id
            JOIN scans
                ON scans.id = findings.scan_id
            JOIN targets
                ON targets.id = scans.target_id
            WHERE findings.id = ?
            """,
            (finding_id,),
        ).fetchone()

        if finding is None:
            return "Finding not found", 404

        evidence = connection.execute(
            """
            SELECT
                request_data,
                response_data,
                expected_behavior,
                observed_behavior,
                captured_at
            FROM evidence
            WHERE finding_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (finding_id,),
        ).fetchone()

    finally:
        connection.close()

    return render_template(
        "finding_detail.html",
        finding=finding,
        evidence=evidence,
    )


@dashboard_bp.get("/findings")
def findings_page():
    connection = get_apiguard_connection()
    try:
        findings = connection.execute(
            """
            SELECT
                findings.id,
                findings.finding_key,
                findings.title,
                findings.severity,
                findings.owasp_category,
                findings.status,
                findings.created_at,
                endpoints.method,
                endpoints.path
            FROM findings
            LEFT JOIN endpoints
                ON endpoints.id = findings.endpoint_id
            ORDER BY findings.id DESC
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template(
        "workspace_page.html",
        page_title="Security findings",
        page_subtitle="Findings requiring analyst review",
        section="findings",
        findings=findings,
    )


@dashboard_bp.get("/owasp")
def owasp_page():
    connection = get_apiguard_connection()
    try:
        owasp = connection.execute(
            """
            SELECT
                owasp_category,
                COUNT(*) AS count
            FROM findings
            WHERE owasp_category IS NOT NULL
            GROUP BY owasp_category
            ORDER BY owasp_category
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template(
        "workspace_page.html",
        page_title="OWASP API Security coverage",
        page_subtitle="Findings mapped to the OWASP API Security Top 10",
        section="owasp",
        owasp=owasp,
    )


@dashboard_bp.get("/reports")
def reports_page():
    connection = get_apiguard_connection()
    try:
        scans = connection.execute(
            """
            SELECT
                scans.id,
                scans.status,
                scans.started_at,
                scans.completed_at,
                scans.scanner_version,
                targets.name AS target_name,
                targets.environment
            FROM scans
            JOIN targets ON targets.id = scans.target_id
            ORDER BY scans.id DESC
            LIMIT 20
            """
        ).fetchall()
    finally:
        connection.close()

    return render_template(
        "workspace_page.html",
        page_title="Security reports",
        page_subtitle="Assessment reporting and evidence review",
        section="reports",
        scans=scans,
    )


@dashboard_bp.get("/configuration")
def configuration_page():
    return render_template(
        "workspace_page.html",
        page_title="Scanner configuration",
        page_subtitle="Current controlled-lab assessment configuration",
        section="configuration",
    )


@dashboard_bp.get("/run-assessment")
def run_assessment():
    target = ScanTarget(
        base_url="http://127.0.0.1:5000",
        username="alice",
        password="AliceLabPass!2026",
        customer_id=101,
    )

    run_security_scan(target, order_id=1003)

    return redirect("/")
