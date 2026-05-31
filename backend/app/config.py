"""Configurations Flask (dev / prod / test).

Lit les variables d'environnement (chargées depuis .env via python-dotenv)
et construit l'URL de connexion PostgreSQL.
"""
import os
from datetime import timedelta

from dotenv import load_dotenv

# Charge automatiquement le fichier .env situé à la racine de backend/
load_dotenv()


def _build_database_uri() -> str:
    """Construit postgresql://USER:PASSWORD@HOST:PORT/DB depuis l'environnement."""
    user = os.getenv("POSTGRES_USER", "hardenos")
    password = os.getenv("POSTGRES_PASSWORD", "")
    host = os.getenv("POSTGRES_HOST", "10.220.0.11")
    port = os.getenv("POSTGRES_PORT", "5432")
    db_name = os.getenv("POSTGRES_DB", "hardenos")
    return f"postgresql://{user}:{password}@{host}:{port}/{db_name}"


class BaseConfig:
    """Configuration commune à tous les environnements."""

    SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = _build_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT — clé de signature dédiée si fournie, sinon dérivée de SECRET_KEY.
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "604800"))
    )


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = True


_CONFIG_BY_NAME = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None = None) -> type[BaseConfig]:
    """Retourne la classe de config selon FLASK_ENV (défaut : development)."""
    name = name or os.getenv("FLASK_ENV", "development")
    return _CONFIG_BY_NAME.get(name, DevelopmentConfig)
