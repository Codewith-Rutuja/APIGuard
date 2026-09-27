from flask import Blueprint, jsonify

internal_bp = Blueprint("internal", __name__)


@internal_bp.get("/internal/debug")
def debug_information():
    return jsonify({
        "service": "AcmeCloud API",
        "environment": "controlled-lab",
        "debug": True,
        "message": "Internal diagnostic endpoint.",
    })


@internal_bp.post("/internal/fetch")
def internal_fetch():
    from flask import request
    import requests

    target_url = request.json.get("url", "http://127.0.0.1:5000/api/v1/health")

    # Controlled API7 lab behavior:
    # The server makes a request to a client-supplied URL.
    response = requests.get(target_url, timeout=3)

    return jsonify(
        {
            "status": "fetched",
            "target": target_url,
            "upstream_status": response.status_code,
        }
    )
