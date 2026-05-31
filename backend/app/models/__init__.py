"""Agrège tous les modèles SQLAlchemy.

Importer ce paquet garantit que toutes les tables sont enregistrées sur
`db.metadata` — indispensable pour que l'autogénération Alembic les voie.
"""
from app.models.audit import Audit
from app.models.audit_result import AuditResult
from app.models.remediation_log import RemediationLog
from app.models.snapshot import Snapshot
from app.models.system import System
from app.models.user import User

__all__ = [
    "User",
    "System",
    "Audit",
    "AuditResult",
    "Snapshot",
    "RemediationLog",
]
