from __future__ import annotations

from flask import Flask
from flask_cors import CORS

from back.config import Config
from back.routes.auth import auth_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = Config.SECRET_KEY

    CORS(
        app,
        resources={r"/api/*": {"origins": Config.FRONTEND_ORIGIN}},
        supports_credentials=True,
    )

    # Blueprints
    app.register_blueprint(auth_bp)

    return app


__all__ = ["create_app"]

