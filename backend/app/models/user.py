"""Modèle User (table users)."""
import enum
from datetime import datetime

import bcrypt
from sqlalchemy import DateTime, Enum, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.utils.dates import utc_isoformat
from app.utils.db import db


class UserRole(enum.Enum):
    admin = "admin"
    auditor = "auditor"
    readonly = "readonly"


class UserStatus(enum.Enum):
    active = "active"
    inactive = "inactive"
    revoked = "revoked"


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"),
        nullable=False,
        default=UserStatus.active,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    # Relations inverses (sans cascade : on n'efface pas l'historique via l'utilisateur)
    audits = relationship("Audit", back_populates="triggered_by_user")
    remediation_logs = relationship("RemediationLog", back_populates="executed_by_user")

    def set_password(self, password: str) -> None:
        """Hache le mot de passe avec bcrypt et le stocke dans password_hash."""
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self.password_hash = hashed.decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Vérifie un mot de passe en clair contre le hash bcrypt stocké."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def to_dict(self) -> dict:
        """Représentation publique de l'utilisateur (JAMAIS le hash)."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role.value,
            "status": self.status.value,
            "last_login_at": utc_isoformat(self.last_login_at),
            "created_at": utc_isoformat(self.created_at),
        }

    def __repr__(self) -> str:
        return f"<User {self.id} {self.email}>"
