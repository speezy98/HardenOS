"""Modèle RemediationLog (table remediation_logs).

Conservé même si l'audit lié est supprimé (audit_id -> NULL via
ON DELETE SET NULL) pour préserver la traçabilité de sécurité.
"""
import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.db import db


class RemediationMode(enum.Enum):
    dryrun = "dryrun"
    apply = "apply"
    rollback = "rollback"


class ScriptType(enum.Enum):
    bash = "bash"
    powershell = "powershell"
    ansible = "ansible"


class RemediationStatus(enum.Enum):
    success = "success"
    error = "error"


class RemediationLog(db.Model):
    __tablename__ = "remediation_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[int | None] = mapped_column(
        ForeignKey("audits.id", ondelete="SET NULL"), nullable=True
    )
    executed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    mode: Mapped[RemediationMode] = mapped_column(
        Enum(RemediationMode, name="remediation_mode"), nullable=False
    )
    script_type: Mapped[ScriptType] = mapped_column(
        Enum(ScriptType, name="script_type"), nullable=False
    )
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus, name="remediation_status"), nullable=False
    )
    # Script d'annulation ciblé (rollback individuel) — capturé côté agent
    # avant la remédiation. NULL si hors périmètre (bulk, familles autres
    # que registre) ou si la capture a échoué : pas de rollback individuel
    # proposé pour cette ligne, seul le rollback global reste disponible.
    undo_script: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    audit = relationship("Audit", back_populates="remediation_logs")
    executed_by_user = relationship("User", back_populates="remediation_logs")

    def __repr__(self) -> str:
        return f"<RemediationLog {self.id} {self.control_id} {self.status}>"
