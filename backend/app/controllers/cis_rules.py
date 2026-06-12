"""Contrôleur des référentiels CIS — Blueprint /api/cis-rules.

Expose ce que HardenOS sait auditer, dérivé des fichiers YAML réellement
présents dans backend/cis_rules/. Sert au formulaire d'ajout de machine côté
frontend (liste des familles / OS / versions proposables).
"""
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from app.services.rules_loader import list_available_families

cis_rules_bp = Blueprint("cis_rules", __name__, url_prefix="/api/cis-rules")


@cis_rules_bp.get("/available")
@jwt_required()
def available():
    """Liste les familles/OS auditables (dérivées des YAML présents).

    Réponse : liste d'objets par famille avec os_type, connection_mode,
    requires_ssh, ruleset appliqué, source du benchmark, et la liste des
    OS/versions proposés.
    """
    return jsonify(list_available_families()), 200
