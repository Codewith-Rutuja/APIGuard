from flask import Flask

from .config import Config
from .routes.auth import auth_bp
from .routes.admin import admin_bp
from .routes.dashboard import dashboard_bp
from .routes.health import health_bp
from .routes.internal import internal_bp
from .routes.openapi import openapi_bp
from .routes.orders import orders_bp
from .routes.profile import profile_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(health_bp, url_prefix="/api/v1")
    app.register_blueprint(internal_bp, url_prefix="/api/v1")
    app.register_blueprint(auth_bp, url_prefix="/api/v1")
    app.register_blueprint(admin_bp, url_prefix="/api/v1")
    app.register_blueprint(profile_bp, url_prefix="/api/v1")
    app.register_blueprint(orders_bp, url_prefix="/api/v1")
    app.register_blueprint(openapi_bp, url_prefix="/api/v1")

    return app
