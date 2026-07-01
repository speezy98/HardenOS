"""Administration des utilisateurs (réservé aux admins).

Logique métier : validation, hachage bcrypt (via User.set_password), et
GARDE-FOUS de sécurité :
- un admin ne peut ni se supprimer ni se révoquer lui-même ;
- on ne peut pas supprimer / révoquer / rétrograder le DERNIER admin actif.

Le contrôleur (controllers/users.py) reste mince : il appelle ce service et mappe
les UserError vers des réponses HTTP.
"""
import re

from app.models.user import User, UserRole, UserStatus
from app.utils.db import db

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserError(Exception):
    """Erreur métier utilisateurs (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# --- Helpers -----------------------------------------------------------------


def _get_user(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if user is None:
        raise UserError("Utilisateur introuvable", 404)
    return user


def _parse_role(value: str) -> UserRole:
    try:
        return UserRole(value)
    except ValueError:
        allowed = ", ".join(r.value for r in UserRole)
        raise UserError(f"Rôle invalide : '{value}'. Attendu : {allowed}.", 400)


def _email_taken_by_other(email: str, user_id: int | None) -> bool:
    """True si l'email est déjà utilisé par un AUTRE utilisateur."""
    other = db.session.scalar(db.select(User).filter_by(email=email))
    return other is not None and other.id != user_id


def _active_admin_count() -> int:
    """Nombre d'administrateurs ACTIFS dans le système."""
    return db.session.scalar(
        db.select(db.func.count())
        .select_from(User)
        .filter(User.role == UserRole.admin, User.status == UserStatus.active)
    )


def _is_last_active_admin(user: User) -> bool:
    """True si `user` est le SEUL administrateur actif restant."""
    return (
        user.role == UserRole.admin
        and user.status == UserStatus.active
        and _active_admin_count() <= 1
    )


# --- Opérations CRUD ---------------------------------------------------------


def list_users() -> list[dict]:
    """Liste tous les utilisateurs (jamais le mot de passe, même haché)."""
    users = db.session.scalars(db.select(User).order_by(User.id)).all()
    return [u.to_dict() for u in users]


def create_user(data: dict) -> User:
    """Crée un utilisateur : email unique, rôle valide, mot de passe présent."""
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")
    role_value = data.get("role")

    if not email or not _EMAIL_RE.match(email):
        raise UserError("Email invalide ou manquant", 400)
    if not password:
        raise UserError("Mot de passe initial requis", 400)
    if not role_value:
        raise UserError("Rôle requis", 400)
    role = _parse_role(role_value)

    if _email_taken_by_other(email, None):
        raise UserError(f"L'email {email} est déjà utilisé", 409)

    user = User(email=email, role=role, status=UserStatus.active)
    user.set_password(password)  # bcrypt
    db.session.add(user)
    db.session.commit()
    return user


def update_user(user_id: int, data: dict) -> User:
    """Modifie un utilisateur : rôle, email, et/ou réinitialisation du mot de passe.

    GARDE-FOU : rétrograder le dernier admin actif vers un rôle non-admin est refusé.
    """
    user = _get_user(user_id)

    if "email" in data:
        email = (data["email"] or "").strip().lower()
        if not email or not _EMAIL_RE.match(email):
            raise UserError("Email invalide", 400)
        if _email_taken_by_other(email, user.id):
            raise UserError(f"L'email {email} est déjà utilisé", 409)
        user.email = email

    if "role" in data:
        new_role = _parse_role(data["role"])
        # Empêche de retirer le dernier administrateur actif du système.
        if new_role != UserRole.admin and _is_last_active_admin(user):
            raise UserError(
                "Impossible : il doit rester au moins un administrateur actif", 409
            )
        user.role = new_role

    if data.get("password"):
        user.set_password(data["password"])  # réinitialisation (bcrypt)

    db.session.commit()
    return user


def set_user_status(
    user_id: int, new_status: UserStatus, *, current_user_id: int
) -> User:
    """Révoque / réactive un utilisateur (change son statut).

    GARDE-FOUS (pour la révocation) :
    - un admin ne peut pas se révoquer lui-même ;
    - on ne peut pas révoquer le dernier admin actif.
    """
    user = _get_user(user_id)

    if new_status == UserStatus.revoked:
        if user.id == current_user_id:
            raise UserError("Vous ne pouvez pas révoquer votre propre compte", 409)
        if _is_last_active_admin(user):
            raise UserError(
                "Impossible : il doit rester au moins un administrateur actif", 409
            )

    user.status = new_status
    db.session.commit()
    return user


def delete_user(user_id: int, *, current_user_id: int) -> None:
    """Supprime définitivement un utilisateur.

    GARDE-FOUS :
    - un admin ne peut pas se supprimer lui-même ;
    - on ne peut pas supprimer le dernier admin actif.
    """
    user = _get_user(user_id)

    if user.id == current_user_id:
        raise UserError("Vous ne pouvez pas supprimer votre propre compte", 409)
    if _is_last_active_admin(user):
        raise UserError(
            "Impossible : il doit rester au moins un administrateur actif", 409
        )

    db.session.delete(user)
    db.session.commit()
