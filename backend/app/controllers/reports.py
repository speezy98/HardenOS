"""Contrôleur des rapports d'audit — Blueprint /api/reports.

Lecture seule : accessible à tout utilisateur authentifié (readonly inclus),
comme les autres endpoints GET d'audit. Toute la logique d'assemblage vit dans
services/reports.py ; ce contrôleur appelle le service et mappe les ReportError.
"""
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from app.services.reports import ReportError, build_report

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@reports_bp.get("/<int:audit_id>")
@jwt_required()
def get_report(audit_id: int):
    """Rapport complet d'un audit : identité, synthèse, compteurs, contrôles+remediation."""
    try:
        report = build_report(audit_id)
    except ReportError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    return jsonify(report), 200
