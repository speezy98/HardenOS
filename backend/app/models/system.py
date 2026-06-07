"""Modèle System (table systems)."""
import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.dates import utc_isoformat
from app.utils.db import db


class OsType(enum.Enum):
    linux = "linux"
    windows = "windows"


class ConnectionMode(enum.Enum):
    agentless = "agentless"
    agent = "agent"


class SystemStatus(enum.Enum):
    online = "online"
    offline = "offline"


class System(db.Model):
    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os_type: Mapped[OsType] = mapped_column(Enum(OsType, name="os_type"), nullable=False)
    os_version: Mapped[str] = mapped_column(String(255), nullable=False)
    # Famille CIS ('debian' | 'rhel' | 'windows') : choisit EXPLICITEMENT le
    # référentiel appliqué (cf. rules_loader). os_version reste un libellé
    # informatif. Nullable pour les systèmes créés avant ce champ (repli sur la
    # résolution par os_version).
    os_family: Mapped[str | None] = mapped_column(String(32), nullable=True)
    connection_mode: Mapped[ConnectionMode] = mapped_column(
        Enum(ConnectionMode, name="connection_mode"),
        nullable=False,
        default=ConnectionMode.agentless,
    )
    # Credentials SSH chiffrés (Fernet — implémenté dans une branche ultérieure)
    ssh_credentials_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_token: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Exécuter les commandes d'audit via sudo (-S, mot de passe sur stdin) quand
    # le compte SSH n'est pas root mais sudoer. Défaut : False (exécution directe).
    use_sudo: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    status: Mapped[SystemStatus] = mapped_column(
        Enum(SystemStatus, name="system_status"),
        nullable=False,
        default=SystemStatus.offline,
    )
    last_audit_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    # Suppression d'un système -> cascade sur audits et snapshots
    audits = relationship(
        "Audit",
        back_populates="system",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    snapshots = relationship(
        "Snapshot",
        back_populates="system",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_dict(self) -> dict:
        """Représentation publique d'un système.

        N'expose JAMAIS `ssh_credentials_enc` ni les credentials en clair :
        seulement le booléen `has_credentials`.
        """
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type.value,
            "os_version": self.os_version,
            "os_family": self.os_family,
            "connection_mode": self.connection_mode.value,
            "status": self.status.value,
            "use_sudo": self.use_sudo,
            "has_credentials": self.ssh_credentials_enc is not None,
            "has_agent_token": self.agent_token is not None,
            "last_audit_at": utc_isoformat(self.last_audit_at),
            "created_at": utc_isoformat(self.created_at),
        }

    def __repr__(self) -> str:
        return f"<System {self.id} {self.hostname}>"
