"""Contrôleur des audits — Blueprint /api/audits.

Règles de rôle :
- POST (déclencher un audit) : auditor et admin
- GET (détail, liste)        : tout utilisateur authentifié (readonly inclus)
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.models.audit import Audit
from app.services.audit_engine import AuditError
from app.services.audit_service import start_audit
from app.utils.auth import role_required
from app.utils.db import db

audits_bp = Blueprint("audits", __name__, url_prefix="/api/audits")


@audits_bp.post("")
@role_required("auditor")
def create():
    """Déclenche un audit sur un système (auditor / admin).

    Corps JSON :
      - system_id (int, requis)
      - ssh_user, ssh_password (str) : credentials SSH si le système n'en a pas.
      - save_credentials (bool) : chiffre et enregistre les credentials fournis.
      - use_stub (bool) : mode démo/test — exécute le bouchon en SYNCHRONE.
      - seed (int) : graine de reproductibilité du bouchon (avec use_stub).

    Audit RÉEL (Linux + SSH) : exécution ASYNCHRONE. Retourne 202 + l'audit en
    status=running ; suivre l'avancement via GET /api/audits/<id>.
    Mode bouchon : exécution synchrone, retourne 201 + l'audit terminé.
    """
    data = request.get_json(silent=True) or {}
    system_id = data.get("system_id")
    if system_id is None:
        return jsonify({"error": "system_id requis"}), 400

    use_stub = bool(data.get("use_stub", False))
    triggered_by = int(get_jwt_identity())

    try:
        audit = start_audit(
            system_id=system_id,
            triggered_by=triggered_by,
            use_stub=use_stub,
            seed=data.get("seed"),
            ssh_user=data.get("ssh_user"),
            ssh_password=data.get("ssh_password"),
            save_credentials=bool(data.get("save_credentials", False)),
        )
    except AuditError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    # Bouchon synchrone -> 201 (terminé) ; SSH asynchrone -> 202 (en cours).
    http_status = 201 if use_stub else 202
    return jsonify(audit.to_summary()), http_status


@audits_bp.get("/<int:audit_id>")
@jwt_required()
def detail(audit_id: int):
    """Détail d'un audit avec la liste complète de ses résultats."""
    audit = db.session.get(Audit, audit_id)
    if audit is None:
        return jsonify({"error": "Audit introuvable"}), 404
    return jsonify(audit.to_dict()), 200


@audits_bp.get("")
@jwt_required()
def list_for_system():
    """Liste (résumé) les audits d'un système, du plus récent au plus ancien.

    Paramètre de requête : system_id (requis).
    """
    system_id = request.args.get("system_id", type=int)
    if system_id is None:
        return jsonify({"error": "paramètre system_id requis"}), 400

    audits = db.session.scalars(
        db.select(Audit)
        .filter_by(system_id=system_id)
        .order_by(Audit.created_at.desc(), Audit.id.desc())
    ).all()
    return jsonify([a.to_summary() for a in audits]), 200
