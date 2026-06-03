"""Contrôleur d'authentification — Blueprint /api/auth."""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from app.models.user import User
from app.services.auth import AuthError, authenticate, issue_access_token
from app.utils.auth import role_required
from app.utils.db import db
from app.utils.jwt import revoke_token

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/login")
def login():
    """Authentifie un utilisateur et retourne access + refresh tokens."""
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email et password requis"}), 400

    try:
        result = authenticate(email, password)
    except AuthError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    return jsonify(result), 200


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    """Génère un nouvel access token à partir d'un refresh token valide."""
    try:
        access_token = issue_access_token(get_jwt_identity())
    except AuthError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify({"access_token": access_token}), 200


@auth_bp.post("/logout")
@jwt_required()
def logout():
    """Révoque l'access token courant (ajout du jti à la blocklist)."""
    revoke_token(get_jwt()["jti"])
    return jsonify({"message": "Déconnexion réussie"}), 200


@auth_bp.get("/me")
@jwt_required()
def me():
    """Retourne les informations de l'utilisateur authentifié (sans le hash)."""
    user = db.session.get(User, int(get_jwt_identity()))
    if user is None:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    return jsonify(user.to_dict()), 200


@auth_bp.get("/admin-check")
@role_required("admin")
def admin_check():
    """Route de démonstration : accessible uniquement aux admins."""
    return jsonify({"message": "Accès admin confirmé"}), 200
