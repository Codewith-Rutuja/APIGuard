from flask import Blueprint, jsonify


openapi_bp = Blueprint("openapi", __name__)


@openapi_bp.get("/openapi.json")
def openapi_spec():
    return jsonify(
        {
            "openapi": "3.0.3",
            "info": {
                "title": "AcmeCloud API",
                "version": "1.0.0",
                "description": "Controlled enterprise-style API security lab.",
            },
            "servers": [
                {
                    "url": "/api/v1",
                }
            ],
            "paths": {
                "/auth/login": {
                    "post": {
                        "summary": "Authenticate a user",
                        "tags": ["Authentication"],
                    }
                },
                "/profile": {
                    "get": {
                        "summary": "Get authenticated user profile",
                        "tags": ["Identity"],
                        "security": [{"bearerAuth": []}],
                    }
                },
                "/orders": {
                    "get": {
                        "summary": "List customer orders",
                        "tags": ["Orders"],
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": False,
                                "schema": {
                                    "type": "integer",
                                    "minimum": 1,
                                },
                            }
                        ],
                    }
                },
                "/orders/{order_id}": {
                    "get": {
                        "summary": "Retrieve an order",
                        "tags": ["Orders"],
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {
                                    "type": "integer",
                                },
                            }
                        ],
                    }
                },
                "/health": {
                    "get": {
                        "summary": "API health check",
                        "tags": ["System"],
                    }
                },
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT",
                    }
                }
            },
        }
    )
