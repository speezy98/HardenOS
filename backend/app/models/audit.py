"""Modèle Audit (table audits)."""
import enum
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.dates import utc_isoformat
from app.utils.db import db


class AuditStatus(enum.Enum):
    pending = "pending"
    running = "running"
    done = "done"
    error = "error"


class RiskLevel(enum.Enum):
    low = "low"
    moderate = "moderate"
    high = "high"
    critical = "critical"


class CisLevel(enum.Enum):
    L1 = "L1"
    L2 = "L2"


class Audit(db.Model):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("systems.id", ondelete="CASCADE"), nullable=False
    )
    triggered_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[AuditStatus] = mapped_column(
        Enum(AuditStatus, name="audit_status"),
        nullable=False,
        default=AuditStatus.pending,
    )
    score_global: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[RiskLevel | None] = mapped_column(
        Enum(RiskLevel, name="risk_level"), nullable=True
    )
    cis_level: Mapped[CisLevel] = mapped_column(
        Enum(CisLevel, name="cis_level"),
        nullable=False,
        default=CisLevel.L1,
    )
    # Scores des 6 domaines : access, network, logging, crypto, updates, services
    scores_by_domain: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Raison courte et NON sensible d'un audit en échec (jamais de credentials/hôte).
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    system = relationship("System", back_populates="audits")
    triggered_by_user = relationship("User", back_populates="audits")
    results = relationship(
        "AuditResult",
        back_populates="audit",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    snapshots = relationship(
        "Snapshot",
        back_populates="audit",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    remediation_logs = relationship("RemediationLog", back_populates="audit")

    def to_summary(self) -> dict:
        """Résumé d'un audit (sans la liste des résultats) — pour les listes."""
        return {
            "id": self.id,
            "system_id": self.system_id,
            "triggered_by": self.triggered_by,
            "status": self.status.value,
            "score_global": self.score_global,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "cis_level": self.cis_level.value,
            "scores_by_domain": self.scores_by_domain,
            "error_message": self.error_message,
            "started_at": utc_isoformat(self.started_at),
            "finished_at": utc_isoformat(self.finished_at),
            "created_at": utc_isoformat(self.created_at),
        }

    def to_dict(self) -> dict:
        """Détail complet d'un audit, résultats inclus."""
        return {
            **self.to_summary(),
            "results": [r.to_dict() for r in self.results],
        }

    def __repr__(self) -> str:
        return f"<Audit {self.id} system={self.system_id} {self.status}>"
