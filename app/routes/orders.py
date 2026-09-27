from flask import Blueprint, g, jsonify

from ..database import get_acmecloud_connection
from ..security.auth import require_authentication


orders_bp = Blueprint("orders", __name__)


@orders_bp.get("/orders/<int:order_id>")
@require_authentication
def get_order(order_id):
    connection = get_acmecloud_connection()

    try:
        order = connection.execute(
            """
            SELECT
                id,
                customer_id,
                order_number,
                status,
                amount,
                description,
                created_at
            FROM orders
            WHERE id = ?
            """,
            (order_id,),
        ).fetchone()
    finally:
        connection.close()

    if not order:
        return jsonify(
            {
                "error": "order_not_found",
                "message": "The requested order does not exist.",
            }
        ), 404

    return jsonify(
        {
            "order": {
                "id": order["id"],
                "customer_id": order["customer_id"],
                "order_number": order["order_number"],
                "status": order["status"],
                "amount": order["amount"],
                "description": order["description"],
                "created_at": order["created_at"],
            }
        }
    )


@orders_bp.get("/orders")
@require_authentication
def list_orders():
    from flask import request

    limit = request.args.get("limit", "20")

    try:
        limit = int(limit)
    except ValueError:
        return jsonify(
            {
                "error": "invalid_limit",
                "message": "The limit parameter must be an integer.",
            }
        ), 400

    if limit < 1:
        return jsonify(
            {
                "error": "invalid_limit",
                "message": "The limit parameter must be greater than zero.",
            }
        ), 400

    connection = get_acmecloud_connection()

    try:
        orders = connection.execute(
            """
            SELECT
                id,
                customer_id,
                order_number,
                status,
                amount,
                description,
                created_at
            FROM orders
            ORDER BY id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        connection.close()

    return jsonify(
        {
            "count": len(orders),
            "limit": limit,
            "orders": [
                {
                    "id": order["id"],
                    "customer_id": order["customer_id"],
                    "order_number": order["order_number"],
                    "status": order["status"],
                    "amount": order["amount"],
                    "description": order["description"],
                    "created_at": order["created_at"],
                }
                for order in orders
            ],
        }
    )


@orders_bp.post("/orders/<int:order_id>/cancel")
@require_authentication
def cancel_order(order_id):
    connection = get_acmecloud_connection()

    try:
        order = connection.execute(
            """
            SELECT id, status
            FROM orders
            WHERE id = ?
            """,
            (order_id,),
        ).fetchone()
    finally:
        connection.close()

    if not order:
        return jsonify(
            {
                "error": "order_not_found",
                "message": "The requested order does not exist.",
            }
        ), 404

    # Controlled API6 lab behavior:
    # The endpoint does not enforce a business-state restriction
    # before allowing the cancellation workflow.
    return jsonify(
        {
            "message": "Order cancellation accepted.",
            "order_id": order_id,
            "previous_status": order["status"],
            "new_status": "cancelled",
        }
    ), 200
