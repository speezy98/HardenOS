"""Chiffrement symétrique des secrets au repos (Fernet).

Utilisé pour chiffrer les credentials SSH avant stockage en base. La clé est
lue depuis la variable d'environnement FERNET_KEY (générée une fois et placée
dans le .env local) :

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Le déchiffrement n'est destiné qu'à un usage interne futur (le scanner, au
moment de se connecter à la machine cible). Il ne doit JAMAIS alimenter une
réponse d'API.
"""
import os

from cryptography.fernet import Fernet, InvalidToken


class CryptoError(Exception):
    """Erreur de configuration ou d'opération de chiffrement."""


def _get_fernet() -> Fernet:
    """Construit l'instance Fernet à partir de FERNET_KEY.

    Lue paresseusement (et non au chargement du module) pour ne pas casser le
    démarrage de l'app quand le chiffrement n'est pas sollicité, et pour rester
    testable.
    """
    key = os.getenv("FERNET_KEY")
    if not key:
        raise CryptoError(
            "FERNET_KEY absente : impossible de (dé)chiffrer les credentials. "
            "Générez-en une et placez-la dans le .env."
        )
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:  # clé malformée
        raise CryptoError(f"FERNET_KEY invalide : {exc}") from exc


def encrypt(plaintext: str) -> str:
    """Chiffre une chaîne et retourne le token Fernet (str)."""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(token: str) -> str:
    """Déchiffre un token Fernet et retourne la chaîne d'origine.

    Réservé à un usage interne (scanner). Ne jamais exposer le résultat via l'API.
    """
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        # Cause la plus fréquente : FERNET_KEY ne correspond pas à celle
        # utilisée au moment du chiffrement (clé changée entre-temps, ou
        # credentials chiffrés sur un autre environnement/backend). Sans ce
        # rattrapage, l'exception remonte non gérée jusqu'à Flask, qui répond
        # avec une page d'erreur générique (pas de JSON exploitable) — côté
        # frontend, ça s'affiche comme "backend injoignable", trompeur.
        raise CryptoError(
            "Impossible de déchiffrer les identifiants stockés : FERNET_KEY "
            "actuelle ne correspond pas à celle utilisée pour les chiffrer "
            "(clé changée, ou credentials importés d'un autre environnement). "
            "Il faut ré-enregistrer les identifiants SSH de ce système."
        ) from exc
