"""Traduction des exceptions SSH/réseau en messages courts, FR et NON sensibles.

Aucun message produit ici ne contient de credentials (user/password) ni d'hôte :
seuls le type d'erreur et une formulation générique sont exposés, à la fois pour
l'API (audits.error_message) et pour éviter toute fuite dans les logs.
"""
import socket

import paramiko


def safe_ssh_error_message(exc: Exception) -> str:
    """Mappe une exception de connexion SSH vers un message court et sûr."""
    # Authentification refusée (mauvais identifiants).
    if isinstance(exc, paramiko.AuthenticationException):
        return "Authentification SSH refusée"

    # Connexion refusée / aucun service en écoute.
    if isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
        return "Connexion refusée par l'hôte"
    if isinstance(exc, ConnectionRefusedError):
        return "Connexion refusée par l'hôte"

    # Délais / hôte injoignable.
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Hôte injoignable (délai de connexion dépassé)"
    if isinstance(exc, socket.gaierror):
        return "Hôte injoignable (résolution réseau impossible)"
    if isinstance(exc, OSError):
        # errno 65 (no route), 51 (network down)... message générique sans détail.
        return "Hôte injoignable (erreur réseau)"

    # Autre erreur côté SSH : on ne donne que le type, jamais le contenu.
    if isinstance(exc, paramiko.SSHException):
        return f"Erreur SSH : {type(exc).__name__}"

    # Erreur inattendue : type seulement.
    return f"Erreur lors de l'audit : {type(exc).__name__}"
