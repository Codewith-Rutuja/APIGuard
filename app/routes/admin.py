from flask import Blueprint, jsonify

from ..security.auth import require_authentication


admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/admin/users")
@require_authentication
def list_admin_users():
    """
    Controlled API5 lab endpoint.

    Intentionally missing require_role("administrator") so APIGuard
    can demonstrate Broken Function Level Authorization.
    """
    return jsonify(
        {
            "service": "AcmeCloud Admin API",
            "function": "list_users",
            "access": "administrator-only",
            "users": [
                {"id": 1, "username": "admin"},
                {"id": 2, "username": "analyst"},
                {"id": 101, "username": "alice"},
                {"id": 102, "username": "bob"},
            ],
        }
    )
