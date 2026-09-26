from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request


def create_access_token(user):
    """Create a signed JWT for an authenticated AcmeCloud user."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(
        minutes=current_app.config["JWT_EXPIRATION_MINUTES"]
    )

    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "customer_id": user["customer_id"],
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        current_app.config["SECRET_KEY"],
        algorithm="HS256",
    )


def decode_access_token(token):
    """Validate and decode a signed JWT."""
    return jwt.decode(
        token,
        current_app.config["SECRET_KEY"],
        algorithms=["HS256"],
    )


def get_bearer_token():
    """Extract a Bearer token from the Authorization header."""
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        return None

    return authorization[7:].strip()


def require_authentication(view_function):
    """Require a valid JWT before executing a protected route."""

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        token = get_bearer_token()

        if not token:
            return jsonify(
                {
                    "error": "authentication_required",
                    "message": "A Bearer token is required.",
                }
            ), 401

        try:
            claims = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify(
                {
                    "error": "token_expired",
                    "message": "The access token has expired.",
                }
            ), 401
        except jwt.InvalidTokenError:
            return jsonify(
                {
                    "error": "invalid_token",
                    "message": "The access token is invalid.",
                }
            ), 401

        g.current_user = claims
        return view_function(*args, **kwargs)

    return wrapped_view


def require_role(*allowed_roles):
    """Require an authenticated user with one of the specified roles."""

    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            current_user = getattr(g, "current_user", None)

            if not current_user:
                return jsonify(
                    {
                        "error": "authentication_required",
                        "message": "Authentication is required.",
                    }
                ), 401

            if current_user.get("role") not in allowed_roles:
                return jsonify(
                    {
                        "error": "forbidden",
                        "message": "You do not have permission to access this resource.",
                    }
                ), 403

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator
