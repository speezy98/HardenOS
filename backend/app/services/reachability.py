"""Vérification de joignabilité d'une machine (à la consultation, pas en fond).

Choix de méthode — TCP plutôt que ping ICMP :
- Le ping ICMP est fréquemment bloqué par les pare-feux (règles ICMP drop),
  ce qui donnerait de faux « hors ligne » sur des machines pourtant joignables.
- Un test TCP sur le port cible est plus REPRÉSENTATIF :
    · Linux (agentless) : port 22 — si SSH accepte, la machine est prête à l'audit.
    · Windows (agent)   : port 8585 — si l'agent écoute, la machine est prête à l'audit.
- Aucune authentification n'est tentée : on ouvre puis referme la socket
  (poignée de main TCP uniquement). Aucun credential n'est utilisé ni exposé.
"""
import socket

from app.models.system import ConnectionMode, OsType, SystemStatus
from app.utils.db import db

# Port SSH standard testé pour les machines Linux agentless.
_SSH_PORT = 22
# Port de l'agent HardenOS sur les machines Windows.
_AGENT_PORT = 8585
# Timeout court (s) : on ne bloque pas la requête HTTP de consultation.
_CONNECT_TIMEOUT = 3.0


def tcp_reachable(host: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> bool:
    """True si une connexion TCP à (host, port) aboutit dans le délai imparti.

    Ouvre puis referme immédiatement la socket (pas d'échange applicatif).
    Toute erreur (refus, timeout, hôte injoignable, DNS) -> False.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_system_status(system) -> dict:
    """Teste la joignabilité d'un système et met à jour son `status` en base.

    Retourne un dict : { reachable: bool, status: 'online'|'offline',
    method: str, checked_port: int }.

    - Linux (agentless) : test TCP sur le port 22.
    - Windows (agent)   : test TCP sur le port 8585 (agent HardenOS).
    Dans les deux cas, met à jour system.status en base (online/offline).
    """
    if system.os_type == OsType.windows or system.connection_mode == ConnectionMode.agent:
        if not system.ip_address:
            return {
                "reachable": False,
                "status": SystemStatus.offline.value,
                "method": f"tcp:{_AGENT_PORT}",
                "checked_port": _AGENT_PORT,
            }

        reachable = tcp_reachable(system.ip_address, _AGENT_PORT)
        system.status = SystemStatus.online if reachable else SystemStatus.offline
        db.session.commit()

        return {
            "reachable": reachable,
            "status": system.status.value,
            "method": f"tcp:{_AGENT_PORT}",
            "checked_port": _AGENT_PORT,
        }

    # Linux agentless : test TCP sur le port SSH.
    reachable = tcp_reachable(system.ip_address, _SSH_PORT)
    system.status = SystemStatus.online if reachable else SystemStatus.offline
    db.session.commit()

    return {
        "reachable": reachable,
        "status": system.status.value,
        "method": f"tcp:{_SSH_PORT}",
        "checked_port": _SSH_PORT,
    }
