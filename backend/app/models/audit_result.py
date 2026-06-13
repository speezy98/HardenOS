"""Modèle AuditResult (table audit_results)."""
import enum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.db import db


class Domain(enum.Enum):
    access = "access"
    network = "network"
    logging = "logging"
    crypto = "crypto"
    updates = "updates"
    services = "services"


class CisLevelResult(enum.Enum):
    L1 = "L1"
    L2 = "L2"


class ResultStatus(enum.Enum):
    passed = "pass"
    fail = "fail"
    warn = "warn"
    na = "na"


class AuditResult(db.Model):
    __tablename__ = "audit_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[int] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False
    )
    control_id: Mapped[str] = mapped_column(String(50), nullable=False)
    # Titre du contrôle figé au moment de l'audit
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    domain: Mapped[Domain] = mapped_column(
        Enum(Domain, name="domain"), nullable=False
    )
    cis_level: Mapped[CisLevelResult] = mapped_column(
        Enum(CisLevelResult, name="cis_level_result"), nullable=False
    )
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[ResultStatus] = mapped_column(
        Enum(ResultStatus, name="result_status"), nullable=False
    )
    actual_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    audit = relationship("Audit", back_populates="results")

    def to_dict(self) -> dict:
        """Représentation publique d'un résultat de contrôle."""
        return {
            "id": self.id,
            "control_id": self.control_id,
            "title": self.title,
            "domain": self.domain.value,
            "cis_level": self.cis_level.value,
            "weight": self.weight,
            "status": self.status.value,
            "actual_value": self.actual_value,
            "expected_value": self.expected_value,
        }

    def __repr__(self) -> str:
        return f"<AuditResult {self.id} {self.control_id} {self.status}>"
