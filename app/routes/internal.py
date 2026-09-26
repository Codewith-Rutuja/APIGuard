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
