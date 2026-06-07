"""Logique métier des systèmes : validation, chiffrement des credentials, CRUD.

Le contrôleur (controllers/systems.py) reste mince : il appelle ce service et
mappe les SystemError vers des réponses HTTP.
"""
import os
import secrets
import socket

import requests

from app.models.system import ConnectionMode, OsType, System, SystemStatus
from app.utils.crypto import encrypt
from app.utils.db import db

_AGENT_PORT = 8585
_AGENT_SETUP_TIMEOUT = 5


def _read_ca_cert() -> str | None:
    """Lit le certificat public de la CA (AGENT_CA_CERT), pour le pousser à
    l'agent lors du /setup — c'est un fichier public, pas un secret, donc
    aucune contrainte de confidentialité à le transmettre ici."""
    ca_path = os.environ.get("AGENT_CA_CERT")
    if ca_path and os.path.isfile(ca_path):
        with open(ca_path, encoding="utf-8") as f:
            return f.read()
    return None


def _post_setup(ip_address: str, payload: dict) -> requests.Response:
    """POST /setup à l'agent, en essayant HTTPS d'abord puis HTTP en repli.

    L'agent cible peut être soit réellement neuf (jamais appairé, encore en
    HTTP), soit déjà passé en HTTPS lors d'un appairage précédent (ex. une
    machine supprimée côté backend mais dont l'agent tourne toujours, avec
    son certificat local intact) : impossible de savoir lequel à l'avance,
    donc on sonde. Une réponse HTTP obtenue (même une erreur, ex. 409 agent
    déjà configuré) est authoritative et n'entraîne PAS de repli HTTP —
    seul un échec de connexion (agent qui ne parle pas ce protocole) le fait.
    """
    ca_path = os.environ.get("AGENT_CA_CERT")
    verify = ca_path if ca_path and os.path.isfile(ca_path) else None

    if verify:
        try:
            resp = requests.post(
                f"https://{ip_address}:{_AGENT_PORT}/setup",
                json=payload,
                verify=verify,
                timeout=_AGENT_SETUP_TIMEOUT,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pass  # agent probablement neuf (encore en HTTP) : on retente en HTTP
        else:
            resp.raise_for_status()
            return resp

    resp = requests.post(
        f"http://{ip_address}:{_AGENT_PORT}/setup",
        json=payload,
        timeout=_AGENT_SETUP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp


class SystemError(Exception):
    """Erreur métier des systèmes (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# Champ JSON acceptant le credential SSH en clair (chiffré avant stockage).
CREDENTIALS_FIELD = "ssh_credentials"

_REQUIRED_FIELDS = ("hostname", "ip_address", "os_type", "os_version")


def _parse_enum(enum_cls, value, field: str):
    """Convertit une valeur en membre d'enum, ou lève SystemError(400)."""
    try:
        return enum_cls(value)
    except ValueError:
        allowed = ", ".join(e.value for e in enum_cls)
        raise SystemError(
            f"Valeur invalide pour '{field}' : '{value}'. Attendu : {allowed}.", 400
        )


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def list_systems() -> list[dict]:
    """Retourne tous les systèmes sérialisés (sans credentials)."""
    systems = db.session.scalars(db.select(System).order_by(System.id)).all()
    return [s.to_dict() for s in systems]


def get_system(system_id: int) -> System:
    """Retourne un système ou lève SystemError(404)."""
    system = db.session.get(System, system_id)
    if system is None:
        raise SystemError("Système introuvable", 404)
    return system


def create_system(data: dict) -> System:
    """Crée un système après validation.

    Windows : vérifie que l'agent répond sur :8585, génère un agent_token,
    crée l'entrée en base puis pousse la config à l'agent via POST /setup.
    Si l'agent ne répond pas au /setup, l'entrée est supprimée (rollback).
    """
    missing = [f for f in _REQUIRED_FIELDS if not data.get(f)]
    if missing:
        raise SystemError(
            f"Champs obligatoires manquants : {', '.join(missing)}", 400
        )

    os_type = _parse_enum(OsType, data["os_type"], "os_type")
    connection_mode = _parse_enum(
        ConnectionMode, data.get("connection_mode", ConnectionMode.agentless.value),
        "connection_mode",
    )

    ip_address = data["ip_address"]

    # Windows : vérifier joignabilité avant de créer l'entrée
    if os_type == OsType.windows:
        if not _tcp_reachable(ip_address, _AGENT_PORT):
            raise SystemError(
                f"L'agent Windows n'est pas joignable sur {ip_address}:{_AGENT_PORT}. "
                "Vérifiez que l'agent HardenOS est démarré sur la machine cible.",
                503,
            )

    system = System(
        hostname=data["hostname"],
        ip_address=ip_address,
        os_type=os_type,
        os_version=data["os_version"],
        connection_mode=connection_mode,
        status=SystemStatus.online,
        # Envoyé par le formulaire (AddMachineModal) mais jamais lu jusqu'ici :
        # sans ça, cocher « Utiliser sudo » restait sans effet et les contrôles
        # Linux nécessitant root (sshd -T, aa-status, /etc/audit...) échouaient.
        use_sudo=bool(data.get("use_sudo", False)),
    )

    credentials = data.get(CREDENTIALS_FIELD)
    if credentials:
        system.ssh_credentials_enc = encrypt(credentials)

    if os_type == OsType.windows:
        agent_token = secrets.token_urlsafe(32)
        system.agent_token = agent_token
        db.session.add(system)
        db.session.commit()

        setup_payload = {"system_id": system.id, "agent_token": agent_token}
        ca_cert_pem = _read_ca_cert()
        if ca_cert_pem:
            # Permet à l'agent de vérifier le backend en HTTPS sans qu'un
            # admin ait à copier ca.crt à la main sur la machine cible.
            setup_payload["ca_cert"] = ca_cert_pem

        try:
            _post_setup(ip_address, setup_payload)
        except Exception as exc:
            db.session.delete(system)
            db.session.commit()
            raise SystemError(
                f"Impossible de configurer l'agent ({exc}). "
                "La machine n'a pas été ajoutée.",
                503,
            ) from exc
    else:
        if data.get("agent_token"):
            system.agent_token = data["agent_token"]
        db.session.add(system)
        db.session.commit()

    return system


def update_system(system_id: int, data: dict) -> System:
    """Met à jour un système. Ne touche aux credentials que s'ils sont fournis."""
    system = get_system(system_id)

    if "hostname" in data:
        if not data["hostname"]:
            raise SystemError("'hostname' ne peut pas être vide", 400)
        system.hostname = data["hostname"]
    if "ip_address" in data:
        if not data["ip_address"]:
            raise SystemError("'ip_address' ne peut pas être vide", 400)
        system.ip_address = data["ip_address"]
    if "os_version" in data:
        if not data["os_version"]:
            raise SystemError("'os_version' ne peut pas être vide", 400)
        system.os_version = data["os_version"]
    if "os_type" in data:
        system.os_type = _parse_enum(OsType, data["os_type"], "os_type")
    if "connection_mode" in data:
        system.connection_mode = _parse_enum(
            ConnectionMode, data["connection_mode"], "connection_mode"
        )
    if "status" in data:
        system.status = _parse_enum(SystemStatus, data["status"], "status")
    if "use_sudo" in data:
        system.use_sudo = bool(data["use_sudo"])
    if "agent_token" in data:
        system.agent_token = data["agent_token"]

    if CREDENTIALS_FIELD in data and data[CREDENTIALS_FIELD]:
        system.ssh_credentials_enc = encrypt(data[CREDENTIALS_FIELD])

    db.session.commit()
    return system


def delete_system(system_id: int) -> None:
    """Supprime un système (cascade audits/results/snapshots ; logs conservés)."""
    system = get_system(system_id)
    db.session.delete(system)
    db.session.commit()


def set_ssh_credentials(system_id: int, ssh_user: str, ssh_password: str) -> System:
    """Chiffre et stocke un couple (user, password) SSH sur un système."""
    from app.utils.ssh_credentials import encrypt_credentials
    if not ssh_user or not ssh_password:
        raise SystemError("ssh_user et ssh_password sont requis", 400)
    system = get_system(system_id)
    system.ssh_credentials_enc = encrypt_credentials(ssh_user, ssh_password)
    db.session.commit()
    return system