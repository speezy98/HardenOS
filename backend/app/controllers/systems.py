"""Contrôleur des systèmes — Blueprint /api/systems.

Règles de rôle :
- GET (liste, détail)      : tout utilisateur authentifié (readonly inclus)
- POST, PUT               : auditor et admin
- DELETE                  : admin uniquement
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
import secrets
import requests
from app.services.reachability import check_system_status
from app.services.systems import (
    SystemError,
    create_system,
    delete_system,
    get_system,
    list_systems,
    set_ssh_credentials,
    update_system,
)
from app.utils.auth import role_required

systems_bp = Blueprint("systems", __name__, url_prefix="/api/systems")


@systems_bp.get("")
@jwt_required()
def list_all():
    """Liste tous les systèmes (sans credentials)."""
    return jsonify(list_systems()), 200


@systems_bp.get("/<int:system_id>")
@jwt_required()
def detail(system_id: int):
    """Détail d'un système (sans credentials)."""
    try:
        system = get_system(system_id)
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(system.to_dict()), 200


@systems_bp.get("/<int:system_id>/status")
@jwt_required()
def status(system_id: int):
    """Teste la joignabilité d'un système et met à jour son statut.

    Linux (agentless) : connexion TCP sur le port 22 (voir reachability.py pour
    le choix TCP vs ICMP). Windows (agent) : non testé (reachable=null).
    Renvoie { reachable, status, method, checked_port } et le système à jour.
    """
    try:
        system = get_system(system_id)
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    result = check_system_status(system)
    return jsonify({**result, "system": system.to_dict()}), 200


@systems_bp.post("")
@role_required("auditor")
def create():
    """Crée un système (auditor / admin)."""
    data = request.get_json(silent=True) or {}
    try:
        system = create_system(data)
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(system.to_dict()), 201


@systems_bp.put("/<int:system_id>")
@role_required("auditor")
def update(system_id: int):
    """Met à jour un système (auditor / admin)."""
    data = request.get_json(silent=True) or {}
    try:
        system = update_system(system_id, data)
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(system.to_dict()), 200


@systems_bp.put("/<int:system_id>/credentials")
@role_required("auditor")
def set_credentials(system_id: int):
    """Enregistre/met à jour les credentials SSH d'un système (auditor / admin).

    Corps JSON : { "ssh_user": str, "ssh_password": str }. Chiffrés avant stockage.
    Ne renvoie jamais le secret : seulement has_credentials.
    """
    data = request.get_json(silent=True) or {}
    try:
        system = set_ssh_credentials(
            system_id, data.get("ssh_user"), data.get("ssh_password")
        )
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(system.to_dict()), 200


@systems_bp.delete("/<int:system_id>")
@role_required("admin")
def delete(system_id: int):
    """Supprime un système (admin uniquement)."""
    try:
        delete_system(system_id)
    except SystemError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify({"message": "Système supprimé"}), 200
