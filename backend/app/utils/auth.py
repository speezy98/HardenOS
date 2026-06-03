"""Helpers d'autorisation réutilisables.

`role_required` protège une route : il exige un access token valide ET un
rôle au moins égal au rôle minimum demandé, selon la hiérarchie :

    readonly < auditor < admin

Un admin a donc accès à toute route exigeant auditor ou readonly.
"""
from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt, verify_jwt_in_request

from app.models.user import UserRole

# Plus le rang est élevé, plus le rôle a de droits.
_ROLE_RANK = {
    UserRole.readonly.value: 1,
    UserRole.auditor.value: 2,
    UserRole.admin.value: 3,
}


def role_required(min_role: str):
    """Décorateur : exige un token valide et un rôle >= min_role (sinon 403)."""
    required_rank = _ROLE_RANK[min_role]

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Lève automatiquement 401 si le token est absent/invalide/révoqué.
            verify_jwt_in_request()
            user_role = get_jwt().get("role")
            if _ROLE_RANK.get(user_role, 0) < required_rank:
                return (
                    jsonify({"error": "Accès refusé : privilèges insuffisants"}),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator
