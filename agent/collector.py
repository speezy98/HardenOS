"""Collecteur CIS chargé de récupérer les règles depuis le backend
d'exécuter les commandes PowerShell associées et de déterminer 
le résultat de chaque contrôle.
"""
import logging
import re
import subprocess
from dataclasses import dataclass

import requests
import urllib3
import yaml

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("hardenos_agent")

PS_TIMEOUT = 30  # secondes par commande PowerShell


@dataclass
class ControlResult:
    control_id: str
    title: str
    domain: str
    cis_level: str
    weight: int
    impact: str
    status: str           # pass | fail | warn | na | error
    actual_value: str | None
    expected_value: str | None
    error: str | None = None


def fetch_controls() -> list[dict]:
    """Télécharge les règles CIS depuis le backend ."""
    backend_url = config.get("backend_url").rstrip("/")
    os_type = config.get("os_type")
    agent_token = config.get("agent_token")
    verify_ssl = config.get_verify()

    url = f"{backend_url}/api/rules/{os_type}"
    log.info("Téléchargement des règles CIS : GET %s", url)

    resp = requests.get(
        url,
        headers={"X-Agent-Token": agent_token},
        verify=verify_ssl,
        timeout=30,
    )
    resp.raise_for_status()
    data = yaml.safe_load(resp.text)
    controls = data.get("controls", [])
    log.info("%d règles CIS reçues depuis le backend.", len(controls))
    return controls


def run_powershell(command: str) -> tuple[str, str | None]:
    """Lance une commande PowerShell et retourne (stdout, erreur_ou_None)."""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", command,
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=PS_TIMEOUT,
        )
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr.strip():
            return output, result.stderr.strip()
        return output, None
    except subprocess.TimeoutExpired:
        return "", f"Timeout après {PS_TIMEOUT}s"
    except FileNotFoundError:
        return "", "PowerShell introuvable sur ce système"
    except Exception as exc:
        return "", str(exc)



# évaluation


def _extract_secedit_value(raw: str) -> str:
    """Extrait la valeur utile d'une ligne secedit
    Si ce n'est pas une ligne KEY = VALUE retourne la chaine 
    """
    if " = " in raw:
        return raw.split(" = ", 1)[1].strip()
    return raw.strip()


def _first_int(value: str):
    """Premier entier trouvé dans une chaîne, ou None. Robuste aux sorties
    « sales » (ex. secedit qui colle deux valeurs : '42 ...=4,30' -> 42), qui
    faisaient échouer int() et basculaient le contrôle en 'warn'."""
    m = re.search(r"-?\d+", value or "")
    return int(m.group()) if m else None


def _evaluate_from_condition(actual_str: str, condition: str) -> str:
    """Évalue un contrôle décrit par le texte `condition` (cas expected=null).

    Ne renvoie JAMAIS 'warn' : un contrôle qu'on ne peut pas confirmer comme
    conforme est considéré NON CONFORME ('fail'), et non « à vérifier
    manuellement ». Un contrôle numérique dont la valeur est lisible et dans la
    plage attendue reste 'pass'."""
    if not condition:
        return "fail"

    cond = condition.lower()

    # "ne doit être attribué à personne"  absence totale = conforme
    if "personne" in cond or "no one" in cond:
        return "pass" if not actual_str else "fail"

    # "doit inclure guests"  SID Guests *S-1-5-32-546
    if "inclure guests" in cond or "include guests" in cond:
        return "pass" if "*s-1-5-32-546" in actual_str.lower() else "fail"

    # "(valeur N = Libellé)" : indication numérique explicite du rédacteur de
    # la règle, ex. "MAPSReporting doit être activé (valeur 2 = Advanced)".
    m = re.search(r"valeur\s+(\d+)\s*=", cond)
    if m:
        val = _first_int(actual_str)
        return "pass" if val is not None and val == int(m.group(1)) else "fail"

    # "doit valoir N ou M" : plusieurs valeurs explicitement acceptées,
    # ex. "ConsentPromptBehaviorAdmin doit valoir 1 ou 2".
    m = re.search(r"doit valoir\s+(\d+)\s+ou\s+(\d+)", cond)
    if m:
        return "pass" if actual_str.strip() in (m.group(1), m.group(2)) else "fail"

    # Stratégie d'audit (sortie `auditpol /get /subcategory:"..."`, format
    # standard : la ligne de la sous-catégorie contient "Success and Failure",
    # "Success", "Failure" ou "No Auditing").
    if "success and failure" in cond:
        return "pass" if "success and failure" in actual_str.lower() else "fail"
    if "inclure success" in cond:
        return "pass" if "success" in actual_str.lower() else "fail"
    if "inclure failure" in cond:
        return "pass" if "failure" in actual_str.lower() else "fail"

    # "supérieur ou égal à N"
    m = re.search(r"sup[ée]rieur ou [ée]gal [àa]\s*(\d+)", cond)
    if m:
        val = _first_int(actual_str)
        return "pass" if val is not None and val >= int(m.group(1)) else "fail"

    # "entre N et M"
    m = re.search(r"entre\s+(\d+)\s+et\s+(\d+)", cond)
    if m:
        val = _first_int(actual_str)
        lo, hi = int(m.group(1)), int(m.group(2))
        return "pass" if val is not None and lo <= val <= hi else "fail"

    # "limité à administrators" → SID Admins *S-1-5-32-544
    if "limit" in cond and "administrator" in cond:
        return "pass" if "*s-1-5-32-544" in actual_str.lower() else "fail"

    # Rien de reconnu / valeur non vérifiable -> NON CONFORME (plus de 'warn').
    return "fail"



# Évaluation principale


def evaluate(actual: str, control: dict) -> str:
    """Compare la valeur obtenue avec celle attendue 
    en gérant les différents cas pris en charge : règles secedit,
      conditions dynamiques, valeurs par défaut du registre, booléens Windows 
      et comparaisons numériques ou textuelles.
    """
    # Extraire la valeur utile si c'est une ligne secedit
    actual_str = _extract_secedit_value(actual)

    expected = control["audit"].get("expected")

    # expected=null → tenter l'évaluation depuis le champ condition
    if expected is None:
        condition = control.get("audit", {}).get("condition", "")
        return _evaluate_from_condition(actual_str, condition)

    # Même extraction que sur actual_str : certains contrôles écrivent
    # `expected: CLÉ = VALEUR` (ligne secedit complète) plutôt que la valeur
    # nue — sans ça, actual_str ("1") ne matche jamais expected_str
    # ("PasswordComplexity = 1") alors que le réglage est correct.
    expected_str = _extract_secedit_value(str(expected).strip())

    # Commande sans sortie = registre/service absent.
    # Mots-clés "off" (disabled/false/block) : absent = éteint = conforme (ex.
    # service jamais installé -> StartType vide, ce qui satisfait "doit être
    # désactivé ou absent"). Mots-clés "on" (enabled/true/allow) : absent
    # alors que requis = non conforme. Sinon (valeur numérique), même logique
    # qu'avant : expected=0 -> pass, sinon fail.
    if not actual_str:
        expected_lower = expected_str.lower()
        if expected_lower in ("disabled", "false", "block"):
            return "pass"
        if expected_lower in ("enabled", "true", "allow"):
            return "fail"
        try:
            return "pass" if int(expected_str) == 0 else "fail"
        except (ValueError, TypeError):
            # Valeur absente + attendu non numérique : non configuré -> non conforme
            # (plus de 'warn' / « à vérifier manuellement »).
            return "fail"

    # Booléens et mots-clés Windows (insensible à la casse)
    if expected_str.lower() in ("true", "false", "disabled", "enabled", "block", "allow"):
        return "pass" if actual_str.lower() == expected_str.lower() else "fail"

    # Comparaison numérique exacte
    try:
        return "pass" if int(actual_str) == int(expected_str) else "fail"
    except (ValueError, TypeError):
        pass

    # Comparaison textuelle exacte
    return "pass" if actual_str == expected_str else "fail"



# Collecte


def _run_one(ctrl: dict) -> ControlResult:
    """Exécute et évalue UN contrôle — logique commune à collect_all() et
    run_control() (rejeu après remédiation), pour ne jamais diverger."""
    command = ctrl.get("audit", {}).get("command", "")
    expected = ctrl.get("audit", {}).get("expected")

    if not command:
        return ControlResult(
            control_id=ctrl["control_id"],
            title=ctrl["title"],
            domain=ctrl["domain"],
            cis_level=ctrl["cis_level"],
            weight=ctrl.get("weight", 1),
            impact=ctrl.get("impact", "moderate"),
            status="na",
            actual_value=None,
            expected_value=str(expected) if expected is not None else None,
            error="Commande absente",
        )

    actual, error = run_powershell(command)
    # Commande en erreur sans sortie : non vérifiable -> non conforme
    # (plus de 'warn' / « à vérifier manuellement »).
    status = "fail" if (error and not actual) else evaluate(actual, ctrl)

    # Affichage : une sortie vide ne doit jamais s'afficher comme "null" (illisible
    # pour l'utilisateur, qui ne peut pas distinguer "rien n'est configuré" d'un
    # bug) — même logique que côté Linux (SSHCollector : "(sortie vide)", etc.).
    if actual:
        actual_display = actual
    elif expected == 0:
        actual_display = "0"
    else:
        actual_display = "(sortie vide)"

    return ControlResult(
        control_id=ctrl["control_id"],
        title=ctrl["title"],
        domain=ctrl["domain"],
        cis_level=ctrl["cis_level"],
        weight=ctrl.get("weight", 1),
        impact=ctrl.get("impact", "moderate"),
        status=status,
        actual_value=actual_display,
        expected_value=str(expected) if expected is not None else None,
        error=error,
    )


def collect_all() -> list[ControlResult]:
    """Telécharge les regles depuis le backend, exécute chaque contrôle
    et retourne la liste des résultats.
    """
    controls = fetch_controls()
    return [_run_one(ctrl) for ctrl in controls]


def run_control(control: dict) -> ControlResult:
    """Rejoue UN contrôle dont la définition est fournie directement par
    l'appelant (le backend l'a déjà en mémoire, pas besoin de retélécharger
    les 100 règles pour n'en filtrer qu'une seule)."""
    return _run_one(control)
