"""Contrôleur Health — vérification de disponibilité de l'API."""
from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.get("/api/health")
def health():
    """Retourne l'état de santé de l'API."""
    return jsonify({"status": "ok"})
