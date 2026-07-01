"""Gestion du compte de l'utilisateur COURANT (self-service).

Ces opérations agissent UNIQUEMENT sur l'utilisateur identifié par le JWT
(current_user_id). Elles ne permettent JAMAIS :
- de modifier le compte d'un autre utilisateur ;
- de changer son propre rôle (réservé aux endpoints admin) ;
- de changer son propre statut (actif/révoqué).

Les actions sensibles (changement d'email, de mot de passe) exigent une
RE-CONFIRMATION du mot de passe actuel : un token volé seul ne suffit pas à
détourner le compte.

Le contrôleur (controllers/account.py) reste mince : il appelle ce service et
mappe les AccountError vers des réponses HTTP.
"""
import re

from app.models.user import User
from app.utils.db import db

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MIN_PASSWORD_LEN = 8


class AccountError(Exception):
    """Erreur métier "mon compte" (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _current_user(current_user_id: int) -> User:
    """Charge l'utilisateur courant depuis son id JWT (jamais un id du corps)."""
    user = db.session.get(User, current_user_id)
    if user is None:
        raise AccountError("Utilisateur introuvable", 404)
    return user


def _email_taken_by_other(email: str, user_id: int) -> bool:
    """True si l'email est déjà utilisé par un AUTRE utilisateur."""
    other = db.session.scalar(db.select(User).filter_by(email=email))
    return other is not None and other.id != user_id


def get_account(current_user_id: int) -> dict:
    """Infos publiques du compte courant (jamais le mot de passe, même haché)."""
    return _current_user(current_user_id).to_dict()


def change_email(current_user_id: int, data: dict) -> User:
    """Change l'email du compte COURANT après re-confirmation du mot de passe.

    Corps attendu : { new_email, current_password }.
    """
    user = _current_user(current_user_id)

    current_password = data.get("current_password")
    new_email = (data.get("new_email") or "").strip().lower()

    # Re-authentification : le mot de passe actuel est obligatoire et doit être bon.
    if not current_password or not user.check_password(current_password):
        raise AccountError("Mot de passe actuel incorrect", 403)

    if not new_email or not _EMAIL_RE.match(new_email):
        raise AccountError("Nouvel email invalide ou manquant", 400)
    if _email_taken_by_other(new_email, user.id):
        raise AccountError(f"L'email {new_email} est déjà utilisé", 409)

    user.email = new_email
    db.session.commit()
    return user


def change_password(current_user_id: int, data: dict) -> User:
    """Change le mot de passe du compte COURANT après re-confirmation de l'ancien.

    Corps attendu : { current_password, new_password }.
    """
    user = _current_user(current_user_id)

    current_password = data.get("current_password")
    new_password = data.get("new_password") or ""

    # Re-authentification : l'ancien mot de passe est obligatoire et doit être bon.
    if not current_password or not user.check_password(current_password):
        raise AccountError("Mot de passe actuel incorrect", 403)

    if len(new_password) < _MIN_PASSWORD_LEN:
        raise AccountError(
            f"Le nouveau mot de passe doit contenir au moins {_MIN_PASSWORD_LEN} caractères",
            400,
        )
    if new_password == current_password:
        raise AccountError(
            "Le nouveau mot de passe doit être différent de l'actuel", 400
        )

    user.set_password(new_password)  # bcrypt
    db.session.commit()
    return user
