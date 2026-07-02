"""Contrôleur de comparaison d'audits — Blueprint /api/comparison.

Lecture seule : comme les autres endpoints GET d'audit, ces routes sont
accessibles à tout utilisateur authentifié (readonly inclus). Toute la logique
et les validations vivent dans services/comparison.py ; ce contrôleur se contente
d'appeler le service et de mapper les ComparisonError vers des réponses HTTP.
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from app.services.comparison import (
    ComparisonError,
    compare_audits,
    list_comparable_systems,
    list_done_audits,
)

comparison_bp = Blueprint("comparison", __name__, url_prefix="/api/comparison")


@comparison_bp.get("/systems")
@jwt_required()
def comparable_systems():
    """Systèmes comparables : ceux ayant au moins deux audits terminés."""
    return jsonify(list_comparable_systems()), 200


@comparison_bp.get("/systems/<int:system_id>/audits")
@jwt_required()
def system_done_audits(system_id: int):
    """Audits terminés d'un système (pour choisir les deux à comparer)."""
    try:
        audits = list_done_audits(system_id)
    except ComparisonError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(audits), 200


@comparison_bp.get("")
@jwt_required()
def compare():
    """Compare deux audits d'une même machine.

    Paramètres de requête (requis) : audit_a (avant), audit_b (après).
    """
    audit_a = request.args.get("audit_a", type=int)
    audit_b = request.args.get("audit_b", type=int)
    if audit_a is None or audit_b is None:
        return jsonify({"error": "paramètres audit_a et audit_b requis"}), 400

    try:
        result = compare_audits(audit_a, audit_b)
    except ComparisonError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(result), 200
