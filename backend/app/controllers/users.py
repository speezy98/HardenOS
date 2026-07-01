"""Contrôleur d'administration des utilisateurs — Blueprint /api/users.

TOUTES les routes sont réservées aux admins (role_required admin) : un auditor
ou un readonly reçoit 403.
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity

from app.models.user import UserStatus
from app.services.users import (
    UserError,
    create_user,
    delete_user,
    list_users,
    set_user_status,
    update_user,
)
from app.utils.auth import role_required

users_bp = Blueprint("users", __name__, url_prefix="/api/users")


@users_bp.get("")
@role_required("admin")
def list_all():
    """Liste tous les utilisateurs (sans mot de passe, même haché)."""
    return jsonify(list_users()), 200


@users_bp.post("")
@role_required("admin")
def create():
    """Crée un utilisateur. Corps : { email, role, password }."""
    data = request.get_json(silent=True) or {}
    try:
        user = create_user(data)
    except UserError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(user.to_dict()), 201


@users_bp.patch("/<int:user_id>")
@users_bp.put("/<int:user_id>")
@role_required("admin")
def update(user_id: int):
    """Modifie un utilisateur : role, email, et/ou password (réinitialisation)."""
    data = request.get_json(silent=True) or {}
    try:
        user = update_user(user_id, data)
    except UserError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(user.to_dict()), 200


@users_bp.post("/<int:user_id>/revoke")
@role_required("admin")
def revoke(user_id: int):
    """Révoque (désactive) un utilisateur : il ne peut plus se connecter."""
    current_user_id = int(get_jwt_identity())
    try:
        user = set_user_status(
            user_id, UserStatus.revoked, current_user_id=current_user_id
        )
    except UserError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(user.to_dict()), 200


@users_bp.post("/<int:user_id>/reactivate")
@role_required("admin")
def reactivate(user_id: int):
    """Réactive un compte révoqué (repasse en statut actif)."""
    current_user_id = int(get_jwt_identity())
    try:
        user = set_user_status(
            user_id, UserStatus.active, current_user_id=current_user_id
        )
    except UserError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(user.to_dict()), 200


@users_bp.delete("/<int:user_id>")
@role_required("admin")
def delete(user_id: int):
    """Supprime définitivement un utilisateur."""
    current_user_id = int(get_jwt_identity())
    try:
        delete_user(user_id, current_user_id=current_user_id)
    except UserError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify({"message": "Utilisateur supprimé"}), 200
