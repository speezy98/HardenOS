"""Sérialisation des credentials SSH (user + password) dans la colonne chiffrée.

Le secret stocké dans `systems.ssh_credentials_enc` est un JSON
{"user": ..., "password": ...} chiffré via Fernet. On reste rétro-compatible
avec l'ancien format (une simple chaîne chiffrée) en la traitant comme un
mot de passe sans utilisateur connu.

Aucune de ces fonctions n'expose le secret en clair via l'API : elles ne sont
appelées qu'en interne (scanner, stockage).
"""
import json

from app.utils.crypto import decrypt, encrypt


def encrypt_credentials(user: str, password: str) -> str:
    """Chiffre un couple (user, password) en un token Fernet (JSON chiffré)."""
    payload = json.dumps({"user": user, "password": password})
    return encrypt(payload)


def decrypt_credentials(token: str) -> dict:
    """Déchiffre le token et retourne {"user": str|None, "password": str}.

    Rétro-compatible : si le contenu n'est pas un JSON {user,password}, on le
    considère comme un mot de passe brut (user inconnu).
    """
    raw = decrypt(token)
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "password" in data:
            return {"user": data.get("user"), "password": data["password"]}
    except (json.JSONDecodeError, ValueError):
        pass
    return {"user": None, "password": raw}
