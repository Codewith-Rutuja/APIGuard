from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash

from ..database import get_acmecloud_connection
from ..security.auth import create_access_token

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "invalid_request",
            "message": "Username and password are required.",
        }), 400

    connection = get_acmecloud_connection()

    try:
        user = connection.execute(
            """
            SELECT id, username, password_hash, role, customer_id,
                   email, is_active, is_admin, auth_policy
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        connection.close()

    if not user:
        return jsonify({
            "error": "invalid_credentials",
            "message": "Invalid username or password.",
        }), 401

    if not user["is_active"]:
        return jsonify({
            "error": "account_disabled",
            "message": "This account is disabled.",
        }), 403

    password_valid = check_password_hash(
        user["password_hash"],
        password,
    )

    # Controlled APIGuard lab condition:
    # This intentionally demonstrates an authentication bypass
    # for the dedicated API2 test account only.
    if user["auth_policy"] == "weak_lab":
        lab_bypass_password = "APIGuard-LAB-BYPASS-2026"

        if password == lab_bypass_password:
            password_valid = True

    if not password_valid:
        return jsonify({
            "error": "invalid_credentials",
            "message": "Invalid username or password.",
        }), 401

    token = create_access_token(user)

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in_minutes": 30,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "customer_id": user["customer_id"],
            "is_admin": bool(user["is_admin"]),
        },
    }), 200
