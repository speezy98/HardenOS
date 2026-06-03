"""Logique métier d'authentification : vérification des identifiants,
génération des tokens, création d'utilisateur.

Le contrôleur (controllers/auth.py) se contente d'appeler ce service.
"""
from datetime import datetime

from flask_jwt_extended import create_access_token, create_refresh_token

from app.models.user import User, UserRole, UserStatus
from app.utils.db import db


class AuthError(Exception):
    """Erreur métier d'authentification (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _tokens_for(user: User) -> dict:
    """Crée access + refresh tokens pour un utilisateur.

    Le rôle est embarqué dans les claims pour permettre la vérification de
    privilèges (role_required) sans requête base à chaque appel. L'identité
    (sub) est l'id utilisateur sous forme de chaîne (exigence flask-jwt-extended).
    """
    identity = str(user.id)
    claims = {"role": user.role.value}
    return {
        "access_token": create_access_token(identity=identity, additional_claims=claims),
        "refresh_token": create_refresh_token(identity=identity, additional_claims=claims),
    }


def authenticate(email: str, password: str) -> dict:
    """Vérifie les identifiants et renvoie tokens + infos utilisateur.

    Lève AuthError(401) avec un message générique en cas d'échec, sans révéler
    si c'est l'email ou le mot de passe qui est en cause (anti-énumération).
    """
    generic_error = AuthError("Identifiants invalides", 401)

    user = db.session.scalar(db.select(User).filter_by(email=email))
    if user is None:
        raise generic_error
    if user.status != UserStatus.active:
        # Même message générique : on ne divulgue pas l'état du compte.
        raise generic_error
    if not user.check_password(password):
        raise generic_error

    user.last_login_at = datetime.utcnow()
    db.session.commit()

    return {**_tokens_for(user), "user": user.to_dict()}


def issue_access_token(user_id: str) -> str:
    """Génère un nouvel access token pour un utilisateur (flux refresh)."""
    user = db.session.get(User, int(user_id))
    if user is None or user.status != UserStatus.active:
        raise AuthError("Utilisateur introuvable ou inactif", 401)
    return create_access_token(
        identity=str(user.id), additional_claims={"role": user.role.value}
    )


def create_admin(email: str, password: str) -> User:
    """Crée un utilisateur admin actif. Lève AuthError(409) si l'email existe."""
    existing = db.session.scalar(db.select(User).filter_by(email=email))
    if existing is not None:
        raise AuthError(f"Un utilisateur avec l'email {email} existe déjà", 409)

    user = User(email=email, role=UserRole.admin, status=UserStatus.active)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user
