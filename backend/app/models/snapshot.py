"""Modèle Snapshot (table snapshots)."""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.db import db


class Snapshot(db.Model):
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[int] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False
    )
    system_id: Mapped[int] = mapped_column(
        ForeignKey("systems.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    audit = relationship("Audit", back_populates="snapshots")
    system = relationship("System", back_populates="snapshots")

    def __repr__(self) -> str:
        return f"<Snapshot {self.id} {self.name}>"
