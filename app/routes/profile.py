from flask import Blueprint, current_app, g, jsonify

from ..database import get_acmecloud_connection
from ..security.auth import require_authentication


profile_bp = Blueprint("profile", __name__)


@profile_bp.get("/profile")
@require_authentication
def get_profile():
    user_id = int(g.current_user["sub"])

    connection = get_acmecloud_connection()

    try:
        user = connection.execute(
            """
            SELECT
                id,
                username,
                role,
                customer_id,
                email,
                is_active,
                is_admin,
                created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    finally:
        connection.close()

    if not user:
        return jsonify(
            {
                "error": "user_not_found",
                "message": "Authenticated user no longer exists.",
            }
        ), 404

    user_response = {
        "id": user["id"],
        "username": user["username"],
        "customer_id": user["customer_id"],
        "email": user["email"],
    }

    # Controlled APIGuard API3 laboratory mode.
    # Internal authorization metadata is exposed only when the
    # deliberate vulnerable-lab flag is enabled.
    if current_app.config["PROFILE_EXPOSE_INTERNAL_METADATA"]:
        user_response.update(
            {
                "role": user["role"],
                "is_active": bool(user["is_active"]),
                "is_admin": bool(user["is_admin"]),
                "created_at": user["created_at"],
            }
        )

    return jsonify({"user": user_response})
