"""App factory Flask pour HardenOS."""
from flask import Flask
from flask_migrate import Migrate

from app.config import get_config
from app.utils.db import db
from app.utils.jwt import jwt, register_jwt_callbacks

migrate = Migrate()


def create_app(config_name: str | None = None) -> Flask:
    """Construit et configure l'application Flask."""
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    register_jwt_callbacks()

    # Modèles : importés pour enregistrer les tables sur db.metadata
    # (nécessaire à l'autogénération Alembic).
    from app import models  # noqa: F401

    # Blueprints
    from app.controllers import register_blueprints

    register_blueprints(app)

    # Commandes CLI (flask create-admin ...)
    from app.cli import register_cli

    register_cli(app)

    return app
