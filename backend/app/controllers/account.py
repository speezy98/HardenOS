"""Contrôleur "MON COMPTE" — Blueprint /api/account.

Accessible à TOUT utilisateur authentifié (admin, auditor, readonly). Ces routes
agissent uniquement sur le compte de l'utilisateur COURANT, identifié par le JWT
(get_jwt_identity) — jamais via un id passé dans l'URL ou le corps.

Le rôle et le statut ne sont PAS modifiables ici : tout champ "role"/"status"
envoyé dans le corps est simplement ignoré (le service ne le lit pas).
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.services.account import (
    AccountError,
    change_email,
    change_password,
    get_account,
)

account_bp = Blueprint("account", __name__, url_prefix="/api/account")


@account_bp.get("")
@jwt_required()
def show():
    """Infos du compte de l'utilisateur courant (sans mot de passe, même haché)."""
    current_user_id = int(get_jwt_identity())
    try:
        account = get_account(current_user_id)
    except AccountError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(account), 200


@account_bp.patch("/email")
@jwt_required()
def update_email():
    """Change l'email du compte courant. Corps : { new_email, current_password }."""
    current_user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    try:
        user = change_email(current_user_id, data)
    except AccountError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(user.to_dict()), 200


@account_bp.patch("/password")
@jwt_required()
def update_password():
    """Change le mot de passe du compte courant.

    Corps : { current_password, new_password }.
    """
    current_user_id = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    try:
        change_password(current_user_id, data)
    except AccountError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify({"message": "Mot de passe mis à jour"}), 200
