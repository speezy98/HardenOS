"""Lecture de la configuration de l'agent HardenOS (agent.conf)."""
import configparser
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "agent.conf")

_defaults = {
    "backend_url": "http://localhost:5001",
    # Rempli manuellement avant le premier démarrage
    "registration_token": "",
    # Rempli automatiquement par register.py après le premier enregistrement
    "system_id": "",
    "agent_token": "",
    # Type d'OS — détermine le YAML que le backend va envoyer
    "os_type": "windows_server_2022",
    # Port d'écoute du serveur HTTP de l'agent
    "listen_port": "8585",
    "verify_ssl": "false",
    "log_file": "",
}


def load() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(defaults=_defaults)
    cfg.read(CONFIG_PATH, encoding="utf-8")
    if not cfg.has_section("agent"):
        cfg.add_section("agent")
    return cfg


def get(key: str) -> str:
    return load().get("agent", key)


def get_int(key: str) -> int:
    return int(get(key))


def get_bool(key: str) -> bool:
    return get(key).lower() in ("1", "true", "yes")


def get_verify() -> str | bool:
    """Valeur à passer à requests(verify=...) pour joindre le backend.

    - chemin de fichier explicite (ex. C:\\hardenos\\ca.crt) → vérifie la
      chaîne de confiance via ce fichier CA
    - "true"/"1"/"yes" → vérification via le magasin de certificats système
    - "false"/"0"/"no" → vérification désactivée (dev / air-gapped uniquement)
    - vide (par défaut) → utilise automatiquement la CA reçue du backend au
      moment du /setup (voir tls.save_ca_cert), si disponible ; sinon False
    """
    raw = get("verify_ssl").strip()
    if raw:
        lowered = raw.lower()
        if lowered in ("1", "true", "yes"):
            return True
        if lowered in ("0", "false", "no"):
            return False
        return raw

    import tls
    if tls.has_ca_cert():
        return tls.CA_PATH
    return False


def is_configured() -> bool:
    """True si system_id et agent_token sont déjà renseignés dans agent.conf."""
    return bool(get("system_id").strip() and get("agent_token").strip())


def save_registration(system_id: int, agent_token: str) -> None:
    """Écrit system_id et agent_token dans agent.conf.

    Crée la section [agent] si absente. Conserve toutes les autres valeurs.
    """
    cfg = load()
    cfg.set("agent", "system_id", str(system_id))
    cfg.set("agent", "agent_token", agent_token)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        cfg.write(f)
