"""auto-enregistrement de l'agent aupres du backend HardenOS.

Au premier démarrage, l'agent envoie ses coordonnées (hostname, IP, OS)
au backend qui choisit le bon jeu de règles CIS et retourne un token.
Les credentials (system_id, agent_token) sont sauvegardés dans agent.conf.
"""
import configparser
import logging
import platform
import socket

import requests
import urllib3

import config
import tls

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("hardenos_agent")


def _detect_os() -> str:
    """Retourne le type d'OS sous forme normalisée (correspond aux clés du backend)."""
    system = platform.system().lower()
    if system == "windows":
        return "windows_server_2022"
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if "debian" in content:
            return "debian_13"
        if "almalinux" in content or "alma" in content:
            return "almalinux_10"
    except OSError:
        pass
    return "linux"


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _save_credentials(system_id: int, agent_token: str) -> None:
    """Écrit system_id et agent_token dans agent.conf."""
    cfg = configparser.ConfigParser()
    cfg.read(config.CONFIG_PATH, encoding="utf-8")
    if not cfg.has_section("agent"):
        cfg.add_section("agent")
    cfg.set("agent", "system_id", str(system_id))
    cfg.set("agent", "agent_token", agent_token)
    with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
        cfg.write(f)
    log.info("Credentials sauvegardés dans agent.conf (system_id=%s).", system_id)


def ensure_registered() -> None:
    """Vérifie si l'agent est déjà enregistré ; sinon, lance l'enregistrement."""
    system_id = config.get("system_id")
    agent_token = config.get("agent_token")

    if system_id and agent_token:
        log.info("Agent déjà enregistré (system_id=%s).", system_id)
        return

    log.info("Premier démarrage — enregistrement automatique auprès du backend...")
    registration_token = config.get("registration_token")
    if not registration_token:
        log.error(
            "Clé 'registration_token' manquante dans agent.conf. "
            "Impossible de s'enregistrer automatiquement."
        )
        return

    backend_url = config.get("backend_url").rstrip("/")
    verify_ssl = config.get_verify()
    os_type = _detect_os()

    payload = {
        "hostname": socket.gethostname(),
        "ip_address": _get_local_ip(),
        "os_type": os_type,
    }
    log.info("Envoi des coordonnées : %s", payload)

    try:
        resp = requests.post(
            f"{backend_url}/api/agent/register",
            json=payload,
            headers={"X-Registration-Token": registration_token},
            verify=verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        _save_credentials(data["system_id"], data["agent_token"])
        log.info(
            "Enregistrement réussi — hostname=%s system_id=%s",
            data["hostname"], data["system_id"],
        )
    except Exception as exc:
        log.error("Échec de l'enregistrement : %s", exc)


def ensure_certificate() -> None:
    """S'assure que l'agent a son certificat TLS local (port 8585) et la clé
    publique de signature des scripts de remédiation (voir remediate.py).

    Indépendant du mode d'appairage (auto-enregistrement ci-dessus, ou ajout
    manuel depuis l'UI qui pousse system_id/agent_token via /setup) : appelé
    à chaque démarrage, ne fait rien si les deux sont déjà présents ou si
    l'agent n'a pas encore de token.
    """
    need_cert = not tls.has_certificate()
    need_pubkey = not tls.has_signing_pubkey()
    if not need_cert and not need_pubkey:
        return

    system_id = config.get("system_id").strip()
    agent_token = config.get("agent_token").strip()
    if not system_id or not agent_token:
        return  # agent pas encore appairé du tout

    backend_url = config.get("backend_url").rstrip("/")
    verify_ssl = config.get_verify()

    body = {}
    if need_cert:
        body["csr"] = tls.build_csr(common_name=_get_local_ip())

    try:
        resp = requests.post(
            f"{backend_url}/api/agent/certificate",
            params={"system_id": system_id},
            json=body,
            headers={"X-Agent-Token": agent_token},
            verify=verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        cert_pem = data.get("cert")
        if cert_pem:
            tls.save_certificate(cert_pem)
            log.info("Certificat TLS de l'agent reçu et enregistré.")
        elif need_cert:
            log.warning("Réponse sans certificat depuis /api/agent/certificate.")

        pubkey_pem = data.get("script_signing_pubkey")
        if pubkey_pem:
            tls.save_signing_pubkey(pubkey_pem)
            log.info("Clé publique de signature des scripts reçue et enregistrée.")
        elif need_pubkey:
            log.warning(
                "Clé de signature pas encore disponible côté backend — "
                "les scripts de remédiation seront rejetés en attendant."
            )
    except Exception as exc:
        log.warning(
            "Impossible de contacter /api/agent/certificate (%s) — certificat "
            "et/ou clé de signature pas encore obtenus.", exc,
        )
