"""Chargeur des référentiels CIS (fichiers YAML de backend/cis_rules/).

- Charge et met en cache les fichiers YAML (lecture disque une seule fois).
- Sélectionne le bon référentiel pour un système donné selon os_type/os_version,
  avec une correspondance souple (casse insensible, libellé de version tolérant).
"""
import os

import yaml

from app.models.system import System

# backend/app/services/rules_loader.py -> backend/cis_rules/
_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "cis_rules"
)

# Cache en mémoire : nom de fichier -> document YAML parsé.
_cache: dict[str, dict] = {}


class RulesError(Exception):
    """Erreur de chargement / sélection d'un référentiel CIS."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _load_file(filename: str) -> dict:
    """Charge un fichier de règles (mis en cache après le premier accès)."""
    if filename in _cache:
        return _cache[filename]
    path = os.path.join(_RULES_DIR, filename)
    if not os.path.isfile(path):
        raise RulesError(f"Référentiel CIS introuvable : {filename}", 500)
    with open(path, encoding="utf-8") as f:
        document = yaml.safe_load(f)
    _cache[filename] = document
    return document


# Correspondance EXPLICITE famille CIS -> fichier de règles. Un même référentiel
# couvre toute une famille (ex. debian13.yaml sert Debian ET Ubuntu). C'est la
# source de vérité pour la résolution : cohérente avec _FAMILY_CATALOG.
_FAMILY_TO_FILENAME = {
    "debian": "debian13.yaml",
    "rhel": "almalinux10.yaml",
    "windows": "windows_server2022.yaml",
}


def _resolve_filename_by_family(os_family: str) -> str | None:
    """Fichier de règles pour une famille CIS, ou None si famille inconnue/absente."""
    return _FAMILY_TO_FILENAME.get((os_family or "").strip().lower())


def _resolve_filename(os_type: str, os_version: str) -> str:
    """REPLI (systèmes sans os_family) : résolution souple par os_version.

    Conservé pour ne pas casser les machines créées avant le champ os_family
    (ex. debian-vm, os_version 'Debian 13'). Ne pas utiliser pour les nouvelles
    machines : elles portent un os_family explicite.
    """
    os_type = (os_type or "").strip().lower()
    version = (os_version or "").strip().lower()

    if os_type == "linux":
        if "debian" in version:
            return "debian13.yaml"
        if "alma" in version:  # AlmaLinux, "AlmaLinux 10", "alma 10"...
            return "almalinux10.yaml"
    elif os_type == "windows":
        # "Windows Server 2022", "Server 2022", "windows 2022"...
        if "2022" in version:
            return "windows_server2022.yaml"

    raise RulesError(
        f"Aucun référentiel CIS ne correspond à os_type='{os_type}', "
        f"os_version='{os_version}'.",
        400,
    )


def get_ruleset_for_system(system: System) -> tuple[dict, list[dict]]:
    """Retourne (benchmark, controls) du référentiel correspondant au système.

    Résolution EXPLICITE par famille (os_family) en priorité ; repli sur la
    résolution par os_version pour les systèmes antérieurs à ce champ.
    """
    # 1) Résolution explicite par famille (nouveaux systèmes).
    filename = _resolve_filename_by_family(getattr(system, "os_family", None))
    # 2) Repli : anciens systèmes sans os_family -> matching sur os_version.
    if filename is None:
        os_type = (
            system.os_type.value if hasattr(system.os_type, "value") else system.os_type
        )
        filename = _resolve_filename(os_type, system.os_version)

    document = _load_file(filename)
    return document.get("benchmark", {}), document.get("controls", [])


# --- Familles auditables (pour le formulaire d'ajout de machine) --------------
#
# Un même référentiel CIS couvre plusieurs OS/versions d'une même famille
# (ex. debian13.yaml sert de base pour Debian ET Ubuntu). Cette table de
# correspondance décrit, PAR FAMILLE, les OS/versions qu'on propose à l'ajout
# et le référentiel réellement appliqué.
#
# La clé de chaque famille est l'`os_family` déclaré dans le bloc `benchmark`
# du YAML (`debian`, `rhel`, `windows`). Une famille n'apparaît QUE si son
# fichier YAML est présent dans cis_rules/ : supprimer un YAML fait disparaître
# la famille correspondante (dérivation dynamique, cf. list_available_families).
_FAMILY_CATALOG = {
    "debian": {
        "family": "Debian",
        "ruleset_file": "debian13.yaml",
        "os_type": "linux",
        "connection_mode": "agentless",  # audité via SSH
        "requires_ssh": True,
        "operating_systems": [
            {"name": "Debian", "versions": ["12", "13"]},
            {"name": "Ubuntu", "versions": ["22.04", "24.04"]},
        ],
    },
    "rhel": {
        "family": "Red Hat",
        "ruleset_file": "almalinux10.yaml",
        "os_type": "linux",
        "connection_mode": "agentless",  # audité via SSH
        "requires_ssh": True,
        "operating_systems": [
            {"name": "RHEL", "versions": ["9", "10"]},
            {"name": "AlmaLinux", "versions": ["9", "10"]},
            {"name": "Rocky Linux", "versions": ["9", "10"]},
        ],
    },
    "windows": {
        "family": "Windows",
        "ruleset_file": "windows_server2022.yaml",
        "os_type": "windows",
        "connection_mode": "agent",  # machine à agent : PAS de credentials SSH
        "requires_ssh": False,
        "operating_systems": [
            {"name": "Windows Server", "versions": ["2022"]},
        ],
    },
}


def list_available_families() -> list[dict]:
    """Familles/OS auditables, dérivées des YAML réellement présents.

    Pour chaque fichier YAML de cis_rules/, on lit son `os_family` (bloc
    benchmark) et on renvoie l'entrée correspondante de `_FAMILY_CATALOG`,
    enrichie de la source du benchmark. Une famille inconnue du catalogue est
    ignorée (le YAML existe mais on n'a pas défini sa correspondance d'OS).

    Résultat trié par nom de famille, pour un affichage stable côté frontend.
    """
    families: list[dict] = []
    if not os.path.isdir(_RULES_DIR):
        return families

    for filename in sorted(os.listdir(_RULES_DIR)):
        if not filename.endswith((".yaml", ".yml")):
            continue
        try:
            benchmark = _load_file(filename).get("benchmark", {}) or {}
        except RulesError:
            continue  # fichier illisible : ignoré, ne casse pas la liste
        family_key = benchmark.get("os_family")
        catalog = _FAMILY_CATALOG.get(family_key)
        if catalog is None:
            continue  # YAML présent mais famille non cataloguée -> on n'invente pas
        families.append(
            {
                "family": catalog["family"],
                # Clé de famille persistée sur le système (choisit le référentiel).
                "os_family": family_key,
                "os_type": catalog["os_type"],
                "connection_mode": catalog["connection_mode"],
                "requires_ssh": catalog["requires_ssh"],
                "ruleset": os.path.splitext(filename)[0],  # ex. "debian13"
                "ruleset_source": benchmark.get("source"),
                "operating_systems": catalog["operating_systems"],
            }
        )

    families.sort(key=lambda f: f["family"])
    return families


def clear_cache() -> None:
    """Vide le cache (utile en test)."""
    _cache.clear()
