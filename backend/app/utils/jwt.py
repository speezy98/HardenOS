"""Instance JWTManager partagée et blocklist de tokens révoqués.

La blocklist est un simple set Python en mémoire : volontairement minimal
pour le développement. Elle est PERDUE au redémarrage du serveur et n'est pas
partagée entre plusieurs processus/workers. En production, la remplacer par
Redis ou une table en base (voir « Limitations connues » du README backend).
"""
from flask_jwt_extended import JWTManager

jwt = JWTManager()

# jti (identifiants uniques) des tokens révoqués via logout.
_blocklist: set[str] = set()


def revoke_token(jti: str) -> None:
    """Ajoute le jti d'un token à la blocklist (appelé au logout)."""
    _blocklist.add(jti)


def is_token_revoked(jti: str) -> bool:
    """Indique si un jti a été révoqué."""
    return jti in _blocklist


def register_jwt_callbacks() -> None:
    """Enregistre les callbacks JWT (vérification de la blocklist)."""

    @jwt.token_in_blocklist_loader
    def _check_if_revoked(jwt_header, jwt_payload) -> bool:
        return is_token_revoked(jwt_payload["jti"])
