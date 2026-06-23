"""Contrôleur agent — Blueprint /api/agent et /api/rules.

Gère les endpoints des agents (enregistrement, envoi d’audits
déclenchement de scan) ainsi que la distribution des règles CIS.


"""
import os
import re
import secrets
from datetime import datetime, timezone

import requests as http_client
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity

from app.services.agent_ingest import AgentIngestError, authenticate_agent, ingest
from app.utils.auth import role_required
from app.utils.dates import utc_isoformat

agents_bp = Blueprint("agents", __name__)



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_token() -> str | None:
    return request.headers.get("X-Agent-Token", "").strip() or None


def _agent_auth_headers(system) -> dict:
    """En-têtes d'authentification pour appeler l'agent (backend -> agent).

    L'agent vérifie ce token avant d'exécuter /run ou /remediate-script.
    Lève ValueError si le système n'a pas de token (agent jamais appairé).
    """
    if not system.agent_token:
        raise ValueError(
            "Aucun token d'agent pour ce système : l'agent n'est pas appairé."
        )
    return {"X-Agent-Token": system.agent_token}


def _agent_base_url(system) -> tuple[str, str | bool]:
    from app.utils.pki import agent_base_url
    return agent_base_url(system.ip_address)


def _create_windows_snapshot(system, audit_id: int, headers: dict, base_url: str, verify) -> tuple[bool, str | None]:
    """Sauvegarde secedit + registre (HKLM\\SOFTWARE, HKLM\\SYSTEM) via l'agent,
    puis enregistre un Snapshot rattaché à `audit_id`.

    Retourne (ok, message_erreur_ou_None).
    """
    from app.models.snapshot import Snapshot
    from app.utils.db import db

    snapshot_name = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    try:
        resp = http_client.post(
            f"{base_url}/backup",
            json={"snapshot_name": snapshot_name},
            headers=headers,
            verify=verify,
            timeout=200,  # reg export HKLM\SOFTWARE peut être lent (timeout agent : 180s)
        )
        resp.raise_for_status()
        backup_result = resp.json()
    except Exception as exc:
        return False, f"Impossible de joindre l'agent pour la sauvegarde : {exc}"

    if backup_result.get("status") != "ok":
        return False, backup_result.get("error") or "Échec de la sauvegarde (raison inconnue)."

    paths = backup_result.get("paths") or {}
    notes = "; ".join(f"{key}={value}" for key, value in paths.items())

    db.session.add(Snapshot(
        audit_id=audit_id,
        system_id=system.id,
        name=snapshot_name,
        notes=notes,
    ))
    db.session.commit()
    return True, None


def _snapshot_before_windows_remediation(system, headers: dict, base_url: str, verify) -> tuple[bool, str | None]:
    """Sauvegarde AVANT une remédiation Windows (cf. _create_windows_snapshot),
    rattachée au dernier audit du système.

    Bloquant par conception (Brique 2, validé avec l'utilisateur) : si la
    sauvegarde échoue, l'appelant NE DOIT PAS exécuter la remédiation — sans
    sauvegarde réussie, il n'y a pas de filet de sécurité pour un rollback.

    Retourne (ok, message_erreur_ou_None).
    """
    from app.models.audit import Audit
    from app.utils.db import db

    last_audit = (
        db.session.query(Audit)
        .filter_by(system_id=system.id)
        .order_by(Audit.id.desc())
        .first()
    )
    if last_audit is None:
        return False, "Aucun audit disponible pour rattacher la sauvegarde."

    return _create_windows_snapshot(system, last_audit.id, headers, base_url, verify)


# Préfixe de Snapshot.notes pour une sauvegarde Linux (archive /etc via SSH).
# Distingue les snapshots Linux des snapshots Windows (secpol=...; hklm_...).
_LINUX_BACKUP_NOTE = "linux_backup="


def _snapshot_before_linux_remediation(system, collector, use_sudo: bool) -> tuple[bool, str | None]:
    """Sauvegarde GLOBALE Linux (archive /etc via SSH) AVANT une remédiation,
    rattachée au dernier audit, puis enregistre un Snapshot. Miroir Linux de
    _snapshot_before_windows_remediation ; réutilise la connexion SSH déjà
    ouverte (`collector`).

    Bloquant : si la sauvegarde échoue, l'appelant NE DOIT PAS remédier.
    Retourne (ok, message_erreur_ou_None).
    """
    from datetime import datetime, timezone

    from app.models.audit import Audit
    from app.models.snapshot import Snapshot
    from app.utils.db import db

    last_audit = (
        db.session.query(Audit)
        .filter_by(system_id=system.id)
        .order_by(Audit.id.desc())
        .first()
    )
    if last_audit is None:
        return False, "Aucun audit disponible pour rattacher la sauvegarde."

    snapshot_name = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    try:
        result = collector.create_backup(snapshot_name, use_sudo)
    except Exception as exc:
        return False, f"Impossible de créer la sauvegarde : {exc}"

    if result.get("status") != "ok":
        return False, result.get("error") or "Échec de la sauvegarde (raison inconnue)."

    db.session.add(Snapshot(
        audit_id=last_audit.id,
        system_id=system.id,
        name=snapshot_name,
        notes=f"{_LINUX_BACKUP_NOTE}{result['path']}",
    ))
    db.session.commit()
    return True, None


def _parse_backup_paths(notes: str | None) -> dict:
    """Reconstruit le dict de chemins de sauvegarde depuis Snapshot.notes
    ("secpol=X; hklm_system=Y; hklm_software_policies=Z; ..."). Générique :
    ne connaît pas la liste exacte des clés (définie côté agent/backup.py)."""
    paths = {}
    for part in (notes or "").split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            paths[key.strip()] = value.strip()
    return paths


@agents_bp.get("/api/agent/snapshots/<int:system_id>")
@role_required("auditor")
def list_snapshots(system_id: int):
    """Liste les sauvegardes (Snapshot) d'un système, les plus récentes d'abord."""
    from app.models.snapshot import Snapshot
    from app.utils.db import db

    snapshots = (
        db.session.query(Snapshot)
        .filter_by(system_id=system_id)
        .order_by(Snapshot.id.desc())
        .all()
    )
    return jsonify([
        {
            "id": s.id,
            "name": s.name,
            "created_at": utc_isoformat(s.created_at),
            "audit_id": s.audit_id,
        }
        for s in snapshots
    ]), 200


@agents_bp.post("/api/agent/rollback/<int:snapshot_id>")
@role_required("auditor")
def rollback_snapshot(snapshot_id: int):
    """Restaure une sauvegarde Windows (secedit + registre) — rollback GLOBAL,
    pas ciblé par contrôle (limite assumée, cf. brief de la brique 2).
    """
    from app.models.snapshot import Snapshot
    from app.models.system import OsType, System
    from app.utils.db import db

    snapshot = db.session.get(Snapshot, snapshot_id)
    if not snapshot:
        return jsonify({"error": f"Sauvegarde id={snapshot_id} introuvable."}), 404

    system = db.session.get(System, snapshot.system_id)
    if not system:
        return jsonify({"error": "Système introuvable."}), 404
    if not system.ip_address:
        return jsonify({"error": "Adresse IP du système inconnue."}), 400

    if system.os_type == OsType.windows:
        # Rollback GLOBAL Windows : restauration via l'agent (secedit + registre).
        paths = _parse_backup_paths(snapshot.notes)
        if not paths:
            return jsonify({"error": "Impossible d'interpréter les chemins de sauvegarde de cette sauvegarde."}), 500
        try:
            headers = _agent_auth_headers(system)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        base_url, verify = _agent_base_url(system)
        try:
            resp = http_client.post(
                f"{base_url}/rollback",
                json={"paths": paths},
                headers=headers,
                verify=verify,
                # restore_backup() exécute plusieurs commandes séquentielles
                # (secedit + reg import), jusqu'à ~540s au pire cas.
                timeout=600,
            )
            resp.raise_for_status()
            result = resp.json()
        except Exception as exc:
            return jsonify({"error": f"Impossible de joindre l'agent pour la restauration : {exc}"}), 502

    elif system.os_type == OsType.linux:
        # Rollback GLOBAL Linux : ré-extraction de l'archive /etc via SSH.
        from app.services.collectors import SSHCollector, SSHConnectionError
        from app.utils.ssh_credentials import decrypt_credentials

        note = snapshot.notes or ""
        if not note.startswith(_LINUX_BACKUP_NOTE):
            return jsonify({"error": "Cette sauvegarde n'est pas une sauvegarde Linux exploitable."}), 500
        backup_path = note[len(_LINUX_BACKUP_NOTE):].strip()

        if not system.ssh_credentials_enc:
            return jsonify({"error": "Aucun identifiant SSH enregistré pour ce système."}), 409
        creds = decrypt_credentials(system.ssh_credentials_enc)
        collector = SSHCollector(
            hostname=system.ip_address, username=creds["user"],
            password=creds["password"], port=22,
        )
        try:
            collector.connect()
        except SSHConnectionError as exc:
            return jsonify({"error": f"Connexion SSH impossible : {exc}"}), 502
        try:
            result = collector.restore_backup(backup_path, bool(system.use_sudo))
        finally:
            collector.close()
        if result.get("status") != "ok":
            return jsonify({"error": result.get("error") or "Échec de la restauration."}), 502

    else:
        return jsonify({"error": "OS non supporté pour le rollback."}), 400

    # La restauration change l'état RÉEL de la machine (secedit, registre,
    # services...) sans jamais toucher aux AuditResult déjà en base : sans
    # nouvel audit, le score affiché resterait calculé sur des données
    # devenues obsolètes (constaté en conditions réelles le 11/07 — score
    # recalculé cohérent avec la base, mais plus avec la machine après un
    # rollback global). Best-effort, non bloquant : un échec ici ne doit pas
    # faire perdre le résultat de la restauration elle-même, déjà acquise.
    new_audit_id = None
    if result.get("status") == "ok":
        from app.services.audit_service import start_audit

        try:
            executed_by = int(get_jwt_identity())
            new_audit = start_audit(system.id, executed_by)
            new_audit_id = new_audit.id
        except Exception as exc:
            current_app.logger.warning(
                "Audit automatique post-rollback impossible pour le système %s : %s", system.id, exc
            )

    result["new_audit_id"] = new_audit_id
    return jsonify(result), 200


@agents_bp.post("/api/agent/rollback-control/<int:remediation_log_id>")
@role_required("auditor")
def rollback_control(remediation_log_id: int):
    """Annule UNE remédiation précise via son script d'annulation ciblé
    (capturé côté agent au moment de la remédiation — registre uniquement
    pour l'instant, cf. agent/undo.py). Contrairement à /rollback (snapshot),
    ne touche qu'au réglage de ce contrôle, pas à l'ensemble de la politique
    de sécurité / du registre.
    """
    import yaml as _yaml
    from app.models.audit import Audit
    from app.models.remediation_log import RemediationLog, RemediationMode, ScriptType
    from app.models.system import OsType, System
    from app.utils.db import db
    from app.utils.pki import PkiError, sign_script

    executed_by = int(get_jwt_identity())

    log_row = db.session.get(RemediationLog, remediation_log_id)
    if not log_row:
        return jsonify({"error": f"Remédiation id={remediation_log_id} introuvable."}), 404
    if not log_row.undo_script:
        return jsonify({"error": "Aucune annulation disponible pour cette remédiation."}), 400
    if not log_row.audit_id:
        return jsonify({"error": "Audit associé introuvable (peut-être supprimé)."}), 404

    audit = db.session.get(Audit, log_row.audit_id)
    if not audit:
        return jsonify({"error": "Audit associé introuvable."}), 404

    system = db.session.get(System, audit.system_id)
    if not system:
        return jsonify({"error": "Système introuvable."}), 404
    if not system.ip_address:
        return jsonify({"error": "Adresse IP du système inconnue."}), 400

    control_id = log_row.control_id

    # Linux : annulation via SSH (exécution du script de restauration capturé
    # avant la remédiation), chemin distinct de l'agent Windows ci-dessous.
    if system.os_type == OsType.linux:
        return _rollback_control_linux(system, log_row, control_id, executed_by)
    if system.os_type != OsType.windows:
        return jsonify({"error": "OS non supporté pour le rollback individuel."}), 400

    # Même enveloppe try/catch + marqueurs que la remédiation initiale
    # (cf. remediate_control) pour une exécution/journalisation cohérente.
    script = "\n".join([
        f"# Annulation — {control_id}",
        "$ErrorActionPreference = 'Stop'",
        "try {",
        f"    {log_row.undo_script}",
        f"    Write-Host '[OK] {control_id}'",
        "} catch {",
        f"    Write-Host '[ERR] {control_id} : ' + $_.Exception.Message",
        "    exit 1",
        "}",
    ])

    try:
        signature = sign_script(script)
    except PkiError as exc:
        return jsonify({"error": f"Signature indisponible : {exc}"}), 500

    try:
        headers = _agent_auth_headers(system)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    base_url, verify = _agent_base_url(system)

    try:
        resp = http_client.post(
            f"{base_url}/remediate-script",
            json={"script": script, "signature": signature},
            headers=headers,
            verify=verify,
            timeout=40,
        )
        resp.raise_for_status()
        remediation_result = resp.json()
    except Exception as exc:
        return jsonify({"error": f"Impossible de joindre l'agent : {exc}"}), 502

    # Recharge le contrôle depuis le YAML pour pouvoir rejouer son audit
    # (même logique que remediate_control, dupliquée ici volontairement :
    # pas de dépendance croisée entre les deux endpoints).
    os_key = system.os_type.value
    yaml_map = {"windows": "windows_server2022.yaml", "linux": "debian13.yaml"}
    yaml_file = yaml_map.get(os_key, "windows_server2022.yaml")
    rules_path = os.path.abspath(os.path.join(_RULES_DIR, yaml_file))
    ctrl = None
    if os.path.isfile(rules_path):
        with open(rules_path, encoding="utf-8") as f:
            rules_data = _yaml.safe_load(f)
        ctrl = next(
            (c for c in rules_data.get("controls", []) if c["control_id"] == control_id),
            None,
        )

    replay_status, replay_actual = None, None
    if remediation_result.get("status") == "ok" and ctrl is not None:
        try:
            replay_resp = http_client.post(
                f"{base_url}/run-control",
                json={"control": ctrl},
                headers=headers,
                verify=verify,
                timeout=40,
            )
            replay_resp.raise_for_status()
            replay_data = replay_resp.json()
            replay_status = replay_data.get("status")
            replay_actual = replay_data.get("actual_value")
        except Exception as exc:
            current_app.logger.warning(
                "Rejeu du contrôle %s (annulation) impossible : %s", control_id, exc
            )

    new_log_status, new_log_id = _finalize_remediation(
        system.id, control_id, executed_by, ScriptType.powershell,
        remediation_result, replay_status, replay_actual,
        mode=RemediationMode.rollback,
    )

    return jsonify({
        "remediation": remediation_result,
        "control_status": replay_status,
        "log_status": new_log_status,
        "remediation_log_id": new_log_id,
    }), 200


# ---------------------------------------------------------------------------
# Auto-enregistrement
# ---------------------------------------------------------------------------

@agents_bp.post("/api/agent/register")
def register_agent():
    """Enregistre automatiquement un nouvel agent au premier démarrage.

    Header  : X-Registration-Token: <AGENT_REGISTRATION_TOKEN>
    Body    : { hostname, ip_address, os_type }
    Réponse : { system_id, agent_token, hostname }
    """
    from app.models.system import System, OsType, SystemStatus
    from app.utils.db import db

    expected = os.environ.get("AGENT_REGISTRATION_TOKEN", "")
    received = request.headers.get("X-Registration-Token", "").strip()

    if not expected or received != expected:
        return jsonify({"error": "Token d'enregistrement invalide."}), 401

    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "").strip()
    ip_address = data.get("ip_address", "").strip()
    os_type_str = data.get("os_type", "").strip().lower()

    if not hostname:
        return jsonify({"error": "Champ 'hostname' manquant."}), 400

    # os_type string → enum (le modèle n'a que windows / linux)
    os_type_enum = OsType.windows if "windows" in os_type_str else OsType.linux

    system = db.session.query(System).filter_by(hostname=hostname).first()
    if system:
        system.ip_address = ip_address
        system.os_type = os_type_enum
    else:
        system = System(
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type_enum,
            status=SystemStatus.online,
        )
        db.session.add(system)

    if not system.agent_token:
        system.agent_token = secrets.token_urlsafe(32)

    db.session.commit()
    return jsonify({
        "system_id": system.id,
        "agent_token": system.agent_token,
        "hostname": system.hostname,
    }), 200


# ---------------------------------------------------------------------------
# Certificat TLS de l'agent
# ---------------------------------------------------------------------------

@agents_bp.post("/api/agent/certificate")
def issue_agent_certificate():
    """Fournit à un agent déjà appairé son certificat TLS et/ou la clé
    publique de signature des scripts de remédiation.

    Indépendant du mode d'appairage (auto-enregistrement ou ajout manuel
    depuis l'UI) : l'agent appelle cet endpoint dès qu'il détecte l'absence
    de l'un ou l'autre, avec le token qu'il a déjà (peu importe comment).

    Query   : ?system_id=<id>
    Header  : X-Agent-Token: <token>
    Body    : { csr? }  — fourni seulement si l'agent n'a pas encore de cert
    Réponse : { cert?, script_signing_pubkey? }
    """
    from app.utils.pki import PkiError, get_signing_public_key_pem, sign_csr

    token = _agent_token()
    if not token:
        return jsonify({"error": "Header X-Agent-Token manquant."}), 401

    system_id = request.args.get("system_id", type=int)
    if not system_id:
        return jsonify({"error": "Paramètre system_id manquant."}), 400

    try:
        system = authenticate_agent(system_id, token)
    except AgentIngestError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    data = request.get_json(silent=True) or {}
    csr_pem = data.get("csr", "").strip()

    response: dict = {}

    if csr_pem:
        sans = [system.ip_address] if system.ip_address else [system.hostname]
        try:
            response["cert"] = sign_csr(csr_pem.encode(), sans=sans).decode()
        except PkiError as exc:
            return jsonify({"error": str(exc)}), 500

    try:
        response["script_signing_pubkey"] = get_signing_public_key_pem()
    except PkiError:
        pass  # clé de signature pas encore générée côté backend — non bloquant

    return jsonify(response), 200


# ---------------------------------------------------------------------------
# Règles CIS
# ---------------------------------------------------------------------------

# Dossier backend/cis_rules/ — mettre les fichiers YAML ici sur le serveur
_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "cis_rules")

_YAML_MAP = {
    "windows_server_2022": "windows_server2022.yaml",
    "windows": "windows_server2022.yaml",
    "debian_13": "debian13.yaml",
    "debian": "debian13.yaml",
    "almalinux_10": "almalinux10.yaml",
    "almalinux": "almalinux10.yaml",
}


@agents_bp.get("/api/rules/<os_type>")
def get_rules(os_type: str):
    """Retourne le YAML de règles CIS pour l'OS demandé.

    L'agent s'authentifie avec X-Agent-Token (déjà enregistré).
    L'OS est détecté automatiquement par l'agent et envoyé dans l'URL.
    """
    if not _agent_token():
        return jsonify({"error": "Header X-Agent-Token manquant."}), 401

    filename = _YAML_MAP.get(os_type.lower())
    if not filename:
        return jsonify({"error": f"OS type inconnu : {os_type}"}), 404

    filepath = os.path.abspath(os.path.join(_RULES_DIR, filename))
    if not os.path.isfile(filepath):
        return jsonify({"error": f"Fichier de règles introuvable pour {os_type}."}), 404

    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    return current_app.response_class(content, mimetype="text/yaml")


# ---------------------------------------------------------------------------
# Réception des résultats d'audit
# ---------------------------------------------------------------------------

@agents_bp.post("/api/agent/audit")
def receive_audit():
    """Reçoit et stocke un rapport d'audit complet envoyé par l'agent."""
    token = _agent_token()
    if not token:
        return jsonify({"error": "Header X-Agent-Token manquant."}), 401

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Corps JSON invalide ou manquant."}), 400

    try:
        audit = ingest(payload, token)
    except AgentIngestError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    # Pas de sauvegarde ici : uniquement avant une remédiation
    # (_snapshot_before_windows_remediation), pour éviter d'avoir deux
    # sauvegardes par cycle audit+remédiation (retiré à la demande de
    # l'utilisateur — un audit seul n'a pas besoin de générer un snapshot).

    return jsonify({
        "audit_id": audit.id,
        "system_id": audit.system_id,
        "score_global": audit.score_global,
        "risk_level": audit.risk_level.value if audit.risk_level else None,
        "scores_by_domain": audit.scores_by_domain,
        "status": audit.status.value,
    }), 201


# ---------------------------------------------------------------------------
# Ping / health-check token
# ---------------------------------------------------------------------------

@agents_bp.get("/api/agent/ping")
def ping():
    """Vérifie que le token agent est valide (sans écriture en base)."""
    token = _agent_token()
    if not token:
        return jsonify({"error": "Header X-Agent-Token manquant."}), 401

    system_id = request.args.get("system_id", type=int)
    if not system_id:
        return jsonify({"error": "Paramètre system_id manquant."}), 400

    try:
        system = authenticate_agent(system_id, token)
    except AgentIngestError as exc:
        return jsonify({"error": exc.message}), exc.status_code

    return jsonify({"ok": True, "system_id": system.id, "hostname": system.hostname}), 200


# ---------------------------------------------------------------------------
# Remédiation d'un contrôle depuis l'UI
# ---------------------------------------------------------------------------

# Détecte les commandes registre d'un script de remédiation WINDOWS. Le
# référentiel écrit les valeurs sous la forme : Set-ItemProperty 'HKLM:\...' -Name ...
# (aussi New-ItemProperty). On capture le chemin de la clé (1er argument quoté).
_WIN_REGISTRY_CMD_RE = re.compile(
    r"(?:Set-ItemProperty|New-ItemProperty)\s+'([^']+)'", re.IGNORECASE
)


def _prepend_registry_key_creation(script_cmd: str) -> str:
    """Windows uniquement : préfixe le script d'une création de clé pour chaque
    chemin de registre visé par un Set-/New-ItemProperty.

    Set-ItemProperty ÉCHOUE si la clé (le chemin) n'existe pas encore — cas
    fréquent sur une installation vierge où les clés de stratégie ne sont créées
    qu'une fois la GPO appliquée (ex. HKLM:\\SOFTWARE\\Policies\\...\\Explorer).
    `New-Item -Force` crée la clé et ses parents de façon idempotente (ne touche
    pas une clé déjà présente). N'altère RIEN si le script ne contient aucune
    commande registre (ne concerne donc jamais les scripts bash Linux)."""
    paths = []
    for match in _WIN_REGISTRY_CMD_RE.finditer(script_cmd):
        path = match.group(1)
        if path not in paths:
            paths.append(path)
    if not paths:
        return script_cmd
    prefix = "".join(
        f"if (-not (Test-Path '{p}')) {{ New-Item -Path '{p}' -Force | Out-Null }}\n"
        for p in paths
    )
    return prefix + script_cmd


@agents_bp.post("/api/agent/remediate/<int:system_id>/<control_id>")
@role_required("auditor")
def remediate_control(system_id: int, control_id: str):
    """Exécute la remédiation d'un seul contrôle (Windows via l'agent, Linux via SSH)."""
    import yaml as _yaml
    from app.models.system import OsType, System
    from app.utils.db import db

    executed_by = int(get_jwt_identity())

    system = db.session.get(System, system_id)
    if not system:
        return jsonify({"error": f"Système id={system_id} introuvable."}), 404
    if not system.ip_address:
        return jsonify({"error": "Adresse IP du système inconnue."}), 400

    # Charger le YAML
    os_key = system.os_type.value
    yaml_map = {"windows": "windows_server2022.yaml", "linux": "debian13.yaml"}
    yaml_file = yaml_map.get(os_key, "windows_server2022.yaml")
    rules_path = os.path.abspath(os.path.join(_RULES_DIR, yaml_file))

    if not os.path.isfile(rules_path):
        return jsonify({"error": f"Fichier de règles introuvable : {yaml_file}"}), 500

    with open(rules_path, encoding="utf-8") as f:
        rules_data = _yaml.safe_load(f)

    ctrl = next(
        (c for c in rules_data.get("controls", []) if c["control_id"] == control_id),
        None,
    )
    if not ctrl:
        return jsonify({"status": "skipped", "reason": f"Contrôle {control_id} introuvable dans le YAML."}), 200

    rem = ctrl.get("remediation") or {}
    script_cmd = rem.get("script", "").strip()
    if not script_cmd:
        return jsonify({"status": "skipped", "reason": "Aucune remédiation définie pour ce contrôle."}), 200
    if script_cmd.startswith("#"):
        # Pas une commande : un commentaire décrivant l'action MANUELLE à mener
        # (ex. "# Ajouter Guests à : Deny access..."). On l'affiche à
        # l'utilisateur, accompagné de la condition (souvent plus explicite
        # sur ce qui est vérifié), au lieu de tout jeter silencieusement.
        return jsonify({
            "status": "skipped",
            "reason": "Action manuelle requise (pas de remédiation automatisable pour ce contrôle).",
            "condition": (ctrl.get("audit") or {}).get("condition", "").strip(),
            "recommendation": script_cmd.lstrip("#").strip(),
        }), 200

    if system.os_type == OsType.linux:
        result = _remediate_linux_and_replay(system, control_id, ctrl, script_cmd, executed_by)
        return jsonify(result), 200

    # Windows : crée les clés de registre manquantes avant tout Set-ItemProperty.
    script_cmd = _prepend_registry_key_creation(script_cmd)

    script = "\n".join([
        f"# Remédiation unitaire — {control_id}",
        f"# {ctrl['title']}",
        "$ErrorActionPreference = 'Stop'",
        "try {",
        f"    {script_cmd}",
        f"    Write-Host '[OK] {control_id}'",
        "} catch {",
        f"    Write-Host '[ERR] {control_id} : ' + $_.Exception.Message",
        "    exit 1",
        "}",
    ])

    from app.utils.pki import PkiError, sign_script

    try:
        signature = sign_script(script)
    except PkiError as exc:
        return jsonify({"error": f"Signature indisponible : {exc}"}), 500

    try:
        headers = _agent_auth_headers(system)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    base_url, verify = _agent_base_url(system)

    backup_ok, backup_error = _snapshot_before_windows_remediation(system, headers, base_url, verify)
    if not backup_ok:
        return jsonify({
            "error": f"Sauvegarde impossible avant remédiation : {backup_error}. Remédiation annulée par sécurité.",
        }), 502

    try:
        resp = http_client.post(
            f"{base_url}/remediate-script",
            json={"script": script, "signature": signature},
            headers=headers,
            verify=verify,
            timeout=40,
        )
        resp.raise_for_status()
        remediation_result = resp.json()
    except Exception as exc:
        return jsonify({"error": f"Impossible de joindre l'agent : {exc}"}), 502

    replay_status, replay_actual = None, None
    if remediation_result.get("status") == "ok":
        try:
            replay_resp = http_client.post(
                f"{base_url}/run-control",
                json={"control": ctrl},
                headers=headers,
                verify=verify,
                timeout=40,
            )
            replay_resp.raise_for_status()
            replay_data = replay_resp.json()
            replay_status = replay_data.get("status")
            replay_actual = replay_data.get("actual_value")
        except Exception as exc:
            # La remédiation a réussi mais on n'a pas pu vérifier le résultat
            # (agent injoignable entre-temps, etc.) : journalisé en 'error' par
            # _finalize_remediation (replay_status reste None), pas de crash.
            current_app.logger.warning("Rejeu du contrôle %s impossible : %s", control_id, exc)

    from app.models.remediation_log import ScriptType

    undo_script = remediation_result.get("undo_script")
    log_status, log_id = _finalize_remediation(
        system_id, control_id, executed_by, ScriptType.powershell,
        remediation_result, replay_status, replay_actual,
        undo_script=undo_script,
    )

    return jsonify({
        "remediation": remediation_result,
        "control_status": replay_status,
        "log_status": log_status,
        "remediation_log_id": log_id,
        "undo_available": bool(undo_script),
    }), 200


def _finalize_remediation(
    system_id: int,
    control_id: str,
    executed_by: int,
    script_type,
    remediation_result: dict,
    replay_status: str | None,
    replay_actual_value: str | None = None,
    undo_script: str | None = None,
    mode=None,
) -> tuple[str, int | None]:
    """Écrit le RemediationLog et met à jour l'AuditResult du contrôle.

    `replay_status` est le statut obtenu en rejouant l'audit du contrôle
    ('pass'|'fail'|'warn'|'na'), ou None si le rejeu n'a pas pu être effectué
    (remédiation déjà en échec, ou rejeu injoignable) — dans ce cas on
    journalise 'error' sans toucher à l'AuditResult existant.

    `undo_script` : script d'annulation ciblé capturé côté agent (registre
    uniquement pour l'instant), stocké tel quel pour un rollback individuel
    ultérieur — None si hors périmètre. `mode` : RemediationMode.apply (défaut)
    ou .rollback quand cet appel journalise l'EXÉCUTION d'une annulation.

    Retourne (statut du journal ('success'|'error'), id de la ligne créée ou None).
    """
    from app.models.audit import Audit
    from app.models.audit_result import AuditResult, ResultStatus
    from app.models.remediation_log import RemediationLog, RemediationMode, RemediationStatus
    from app.utils.db import db

    if mode is None:
        mode = RemediationMode.apply

    if mode == RemediationMode.rollback:
        # Une annulation réussie fait RÉGRESSER la conformité par définition
        # (elle remet volontairement le réglage d'origine, potentiellement
        # non conforme) — le critère de succès est donc l'exécution du script
        # d'annulation, pas le statut de conformité du rejeu (qui, lui, sert
        # seulement à remettre l'AuditResult à jour, cf. plus bas).
        log_status = RemediationStatus.success if remediation_result.get("status") == "ok" else RemediationStatus.error
    else:
        log_status = RemediationStatus.success if replay_status == "pass" else RemediationStatus.error

    output_parts = []
    if remediation_result.get("output"):
        output_parts.append(f"[remédiation] {remediation_result['output']}")
    if remediation_result.get("error"):
        output_parts.append(f"[remédiation:erreur] {remediation_result['error']}")
    if replay_status is not None:
        output_parts.append(f"[rejeu] statut={replay_status} valeur={replay_actual_value}")

    last_audit = (
        db.session.query(Audit)
        .filter_by(system_id=system_id)
        .order_by(Audit.id.desc())
        .first()
    )

    log_id = None
    if last_audit is not None:
        if replay_status is not None:
            result_row = (
                db.session.query(AuditResult)
                .filter_by(audit_id=last_audit.id, control_id=control_id)
                .first()
            )
            if result_row is not None:
                result_row.status = ResultStatus(replay_status)
                result_row.actual_value = replay_actual_value

        log_row = RemediationLog(
            audit_id=last_audit.id,
            executed_by=executed_by,
            control_id=control_id,
            mode=mode,
            script_type=script_type,
            output="\n".join(output_parts) or None,
            status=log_status,
            undo_script=undo_script,
        )
        db.session.add(log_row)
        db.session.commit()
        log_id = log_row.id

        if replay_status is not None:
            # Le score affiché doit refléter les contrôles corrigés sans
            # attendre un nouvel audit complet (demande utilisateur).
            from app.services.audit_engine import recompute_score
            recompute_score(last_audit.id)

    return log_status.value, log_id


def _remediate_linux_and_replay(system, control_id: str, ctrl: dict, command: str, executed_by: int) -> dict:
    """Exécute la remédiation bash sur un système Linux via SSH, rejoue
    l'audit du contrôle SUR LA MÊME CONNEXION si la remédiation a réussi
    (pas de reconnexion), puis journalise (RemediationLog + AuditResult).

    Retourne { remediation: {...}, control_status, log_status } — même forme
    que le chemin Windows (voir remediate_control).
    """
    from app.models.remediation_log import ScriptType
    from app.services.collectors import SSHCollector, SSHConnectionError
    from app.utils.ssh_credentials import decrypt_credentials

    def _finalize_and_wrap(remediation_result, replay_status=None, replay_actual=None):
        log_status, _log_id = _finalize_remediation(
            system.id, control_id, executed_by, ScriptType.bash,
            remediation_result, replay_status, replay_actual,
        )
        return {
            "remediation": remediation_result,
            "control_status": replay_status,
            "log_status": log_status,
        }

    if not system.ssh_credentials_enc:
        return _finalize_and_wrap({
            "status": "error",
            "output": "",
            "error": "Aucun identifiant SSH enregistré pour ce système.",
        })

    creds = decrypt_credentials(system.ssh_credentials_enc)
    if not creds.get("user"):
        return _finalize_and_wrap({
            "status": "error",
            "output": "",
            "error": "Les identifiants SSH enregistrés n'ont pas d'utilisateur.",
        })

    collector = SSHCollector(
        hostname=system.ip_address,
        username=creds["user"],
        password=creds["password"],
        port=22,
    )
    try:
        collector.connect()
    except SSHConnectionError as exc:
        return _finalize_and_wrap({"status": "error", "output": "", "error": str(exc)})

    use_sudo = bool(system.use_sudo)
    try:
        # Sauvegarde GLOBALE (archive /etc) AVANT toute modification — bloquant :
        # sans filet de sécurité, on ne remédie pas (comme Windows).
        backup_ok, backup_err = _snapshot_before_linux_remediation(system, collector, use_sudo)
        if not backup_ok:
            return _finalize_and_wrap({
                "status": "error", "output": "",
                "error": f"Sauvegarde impossible avant remédiation : {backup_err}. Remédiation annulée par sécurité.",
            })

        # Capture pour le rollback INDIVIDUEL : état des fichiers ciblés AVANT
        # la remédiation (None si le script ne touche aucun fichier -> seul le
        # rollback global couvrira ce contrôle).
        undo_script = collector.build_undo_script(command, use_sudo)

        remediation_result = collector.execute_remediation(command, use_sudo)

        replay_status, replay_actual = None, None
        if remediation_result.get("status") == "ok":
            outcome = collector.collect(system, ctrl)
            replay_status = outcome.status
            replay_actual = outcome.actual_value
    finally:
        collector.close()

    log_status, log_id = _finalize_remediation(
        system.id, control_id, executed_by, ScriptType.bash,
        remediation_result, replay_status, replay_actual,
        undo_script=undo_script,
    )
    return {
        "remediation": remediation_result,
        "control_status": replay_status,
        "log_status": log_status,
        "remediation_log_id": log_id,
        "undo_available": bool(undo_script),
    }


def _rollback_control_linux(system, log_row, control_id: str, executed_by: int):
    """Annule UNE remédiation Linux via SSH : exécute le script de restauration
    (`log_row.undo_script`, capturé avant la remédiation), rejoue l'audit du
    contrôle, journalise en mode rollback. Miroir Linux du chemin Windows de
    rollback_control. Retourne une réponse Flask (jsonify, code)."""
    import yaml as _yaml

    from app.models.remediation_log import RemediationMode, ScriptType
    from app.services.collectors import SSHCollector, SSHConnectionError
    from app.utils.ssh_credentials import decrypt_credentials

    if not system.ssh_credentials_enc:
        return jsonify({"error": "Aucun identifiant SSH enregistré pour ce système."}), 409
    creds = decrypt_credentials(system.ssh_credentials_enc)

    # Recharge le contrôle depuis le YAML pour rejouer son audit après annulation.
    rules_path = os.path.abspath(os.path.join(_RULES_DIR, "debian13.yaml"))
    ctrl = None
    if os.path.isfile(rules_path):
        with open(rules_path, encoding="utf-8") as f:
            rules_data = _yaml.safe_load(f)
        ctrl = next(
            (c for c in rules_data.get("controls", []) if c["control_id"] == control_id),
            None,
        )

    collector = SSHCollector(
        hostname=system.ip_address, username=creds["user"],
        password=creds["password"], port=22,
    )
    try:
        collector.connect()
    except SSHConnectionError as exc:
        return jsonify({"error": f"Connexion SSH impossible : {exc}"}), 502

    use_sudo = bool(system.use_sudo)
    try:
        remediation_result = collector.execute_remediation(log_row.undo_script, use_sudo)

        replay_status, replay_actual = None, None
        if remediation_result.get("status") == "ok" and ctrl is not None:
            outcome = collector.collect(system, ctrl)
            replay_status = outcome.status
            replay_actual = outcome.actual_value
    finally:
        collector.close()

    new_log_status, new_log_id = _finalize_remediation(
        system.id, control_id, executed_by, ScriptType.bash,
        remediation_result, replay_status, replay_actual,
        mode=RemediationMode.rollback,
    )
    return jsonify({
        "remediation": remediation_result,
        "control_status": replay_status,
        "log_status": new_log_status,
        "remediation_log_id": new_log_id,
    }), 200


def _run_bulk_linux_remediation(
    system, included: list[str], controls_by_id: dict[str, dict], executed_by: int,
) -> list[dict]:
    """Remédiation groupée Linux : UNE SEULE connexion SSH pour toute la boucle
    (remédiation + rejeu de chaque contrôle), pas de script combiné — chaque
    commande bash s'exécute directement, contrairement à Windows qui doit tout
    empaqueter dans un unique .ps1 signé envoyé à l'agent.
    """
    from app.models.remediation_log import ScriptType
    from app.services.collectors import SSHCollector, SSHConnectionError
    from app.utils.ssh_credentials import decrypt_credentials

    def _log_error_for_all(error_message: str) -> list[dict]:
        results = []
        for control_id in included:
            remediation_result = {"status": "error", "output": "", "error": error_message}
            log_status, _log_id = _finalize_remediation(
                system.id, control_id, executed_by, ScriptType.bash, remediation_result, None,
            )
            results.append({"control_id": control_id, "control_status": None, "log_status": log_status})
        return results

    if not system.ssh_credentials_enc:
        return _log_error_for_all("Aucun identifiant SSH enregistré pour ce système.")

    creds = decrypt_credentials(system.ssh_credentials_enc)
    if not creds.get("user"):
        return _log_error_for_all("Les identifiants SSH enregistrés n'ont pas d'utilisateur.")

    collector = SSHCollector(
        hostname=system.ip_address,
        username=creds["user"],
        password=creds["password"],
        port=22,
    )
    try:
        collector.connect()
    except SSHConnectionError as exc:
        return _log_error_for_all(str(exc))

    use_sudo = bool(system.use_sudo)

    # UNE seule sauvegarde globale avant toute la boucle (comme Windows : un
    # snapshot pour toute la remédiation groupée). Bloquant : si elle échoue,
    # on ne remédie rien.
    backup_ok, backup_err = _snapshot_before_linux_remediation(system, collector, use_sudo)
    if not backup_ok:
        collector.close()
        return _log_error_for_all(
            f"Sauvegarde impossible avant remédiation : {backup_err}. Remédiation annulée par sécurité."
        )

    results = []
    try:
        for control_id in included:
            ctrl = controls_by_id[control_id]
            script_cmd = (ctrl.get("remediation") or {}).get("script", "").strip()

            remediation_result = collector.execute_remediation(script_cmd, use_sudo)

            replay_status, replay_actual = None, None
            if remediation_result.get("status") == "ok":
                outcome = collector.collect(system, ctrl)
                replay_status = outcome.status
                replay_actual = outcome.actual_value

            log_status, _log_id = _finalize_remediation(
                system.id, control_id, executed_by, ScriptType.bash,
                remediation_result, replay_status, replay_actual,
            )
            results.append({"control_id": control_id, "control_status": replay_status, "log_status": log_status})
    finally:
        collector.close()

    return results


# ---------------------------------------------------------------------------
# Génération et exécution du script de remédiation
# ---------------------------------------------------------------------------

def _build_remediation_script(system_id: int) -> tuple[str, list[str], dict[str, dict], list[dict]]:
    """Construit un script PowerShell de remédiation à partir du dernier audit.

    Retourne (script_ps1, liste_des_control_ids_inclus, control_id -> définition
    complète du contrôle, liste des actions manuelles [{control_id, title,
    recommendation}] pour les contrôles dont la remédiation n'est pas
    automatisable). Le dict control_id->contrôle permet aux appelants de
    rejouer un contrôle sans que l'agent ait à retélécharger tout le ruleset.
    Lève ValueError si aucun audit ou aucune remédiation (automatique ou
    manuelle) disponible.
    """
    import yaml as _yaml
    from app.models.audit import Audit
    from app.models.audit_result import AuditResult, ResultStatus
    from app.models.system import System
    from app.utils.db import db

    system = db.session.get(System, system_id)
    if not system:
        raise ValueError(f"Système id={system_id} introuvable.")

    # Dernier audit du système
    last_audit = (
        db.session.query(Audit)
        .filter_by(system_id=system_id)
        .order_by(Audit.id.desc())
        .first()
    )
    if not last_audit:
        raise ValueError("Aucun audit disponible pour ce système.")

    # Contrôles en échec
    failures = (
        db.session.query(AuditResult)
        .filter_by(audit_id=last_audit.id, status=ResultStatus.fail)
        .all()
    )
    if not failures:
        raise ValueError("Aucun contrôle en échec — rien à remédier.")

    failing_ids = {r.control_id for r in failures}

    # Charger le YAML de règles selon l'OS du système
    os_key = system.os_type.value  # "windows" ou "linux"
    yaml_map = {
        "windows": "windows_server2022.yaml",
        "linux":   "debian13.yaml",
    }
    yaml_file = yaml_map.get(os_key, "windows_server2022.yaml")
    rules_path = os.path.abspath(os.path.join(_RULES_DIR, yaml_file))

    if not os.path.isfile(rules_path):
        raise ValueError(f"Fichier de règles introuvable : {yaml_file}")

    with open(rules_path, encoding="utf-8") as f:
        rules_data = _yaml.safe_load(f)

    # Assembler le script
    lines = [
        "# ============================================================",
        f"# Script de remédiation HardenOS",
        f"# Système  : {system.hostname}  (id={system.id})",
        f"# Audit    : #{last_audit.id}  —  {last_audit.finished_at}",
        f"# Échecs   : {len(failures)} contrôle(s)",
        "# ATTENTION : relisez ce script avant toute exécution.",
        "# ============================================================",
        "",
        "$ErrorActionPreference = 'Stop'",
        "$results = @()",
        "",
    ]

    included = []
    controls_by_id = {}
    manual_actions = []
    for ctrl in rules_data.get("controls", []):
        if ctrl["control_id"] not in failing_ids:
            continue
        rem = ctrl.get("remediation") or {}
        script_cmd = rem.get("script", "").strip()
        if not script_cmd:
            continue
        if script_cmd.startswith("#"):
            # Pseudo-script = action manuelle décrite en commentaire : on la
            # trace (avec la condition, souvent plus explicite) au lieu de la
            # jeter silencieusement (voir manual_actions).
            manual_actions.append({
                "control_id": ctrl["control_id"],
                "title": ctrl["title"],
                "condition": (ctrl.get("audit") or {}).get("condition", "").strip(),
                "recommendation": script_cmd.lstrip("#").strip(),
            })
            continue

        # Crée les clés de registre manquantes avant Set-ItemProperty (no-op si
        # le script n'en contient pas, donc sans effet sur les contrôles Linux).
        ps_cmd = _prepend_registry_key_creation(script_cmd)
        lines += [
            f"# [{ctrl['control_id']}] {ctrl['title']}",
            "try {",
            f"    {ps_cmd}",
            f"    $results += '[OK]  {ctrl['control_id']}'",
            "} catch {",
            f"    $results += '[ERR] {ctrl['control_id']} : ' + $_.Exception.Message",
            "}",
            "",
        ]
        included.append(ctrl["control_id"])
        controls_by_id[ctrl["control_id"]] = ctrl

    if not included and not manual_actions:
        raise ValueError(
            "Aucune remédiation (automatique ou manuelle) disponible pour les contrôles en échec."
        )

    lines += [
        "# ---- Résumé ----",
        "Write-Host ''",
        "Write-Host '=== Résultats de la remédiation ==='",
        "$results | ForEach-Object { Write-Host $_ }",
    ]

    return "\n".join(lines), included, controls_by_id, manual_actions


@agents_bp.get("/api/agent/remediation-script/<int:system_id>")
def get_remediation_script(system_id: int):
    """Retourne le script PowerShell de remédiation pour le dernier audit.

    Utilisé par le frontend pour afficher/télécharger le script avant exécution.
    """
    from app.utils.pki import PkiError, sign_script

    try:
        script, included, _controls_by_id, manual_actions = _build_remediation_script(system_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404

    try:
        signature = sign_script(script)
    except PkiError:
        signature = None  # affichage/téléchargement seul : non bloquant ici

    return jsonify({
        "system_id": system_id,
        "control_count": len(included),
        "control_ids": included,
        "script": script,
        "signature": signature,
        "manual_actions": manual_actions,
    }), 200


@agents_bp.post("/api/agent/remediate/<int:system_id>")
@role_required("auditor")
def run_remediation(system_id: int):
    """Exécute la remédiation groupée (Windows via l'agent, Linux via SSH),
    puis rejoue chaque contrôle inclus pour vérifier qu'il est réellement corrigé.
    """
    from app.models.system import OsType, System
    from app.utils.db import db

    executed_by = int(get_jwt_identity())

    system = db.session.get(System, system_id)
    if not system or not system.ip_address:
        return jsonify({"error": "Système introuvable ou IP inconnue."}), 404

    try:
        script, included, controls_by_id, manual_actions = _build_remediation_script(system_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404

    if not included:
        # Uniquement des actions manuelles pour les contrôles en échec : pas la
        # peine de solliciter l'agent/SSH pour un script vide.
        return jsonify({
            "message": "Aucune remédiation automatisable — actions manuelles requises.",
            "control_ids": [],
            "results": [],
            "manual_actions": manual_actions,
        }), 200

    if system.os_type == OsType.linux:
        # Pas de script combiné pour Linux (le script construit par
        # _build_remediation_script est en syntaxe PowerShell, inutilisable
        # ici) : chaque commande bash s'exécute directement via SSH, comme
        # pour l'unitaire (_remediate_linux_and_replay), mais en boucle sur
        # une seule connexion.
        results = _run_bulk_linux_remediation(system, included, controls_by_id, executed_by)
        success_count = sum(1 for r in results if r["log_status"] == "success")
        return jsonify({
            "message": f"Remédiation exécutée ({len(included)} contrôle(s), {success_count} vérifié(s) conforme(s)).",
            "control_ids": included,
            "results": results,
            "manual_actions": manual_actions,
        }), 200

    from app.utils.pki import PkiError, sign_script

    try:
        signature = sign_script(script)
    except PkiError as exc:
        return jsonify({"error": f"Signature indisponible : {exc}"}), 500

    try:
        headers = _agent_auth_headers(system)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    base_url, verify = _agent_base_url(system)

    backup_ok, backup_error = _snapshot_before_windows_remediation(system, headers, base_url, verify)
    if not backup_ok:
        return jsonify({
            "error": f"Sauvegarde impossible avant remédiation : {backup_error}. Remédiation annulée par sécurité.",
        }), 502

    try:
        resp = http_client.post(
            f"{base_url}/remediate-script",
            json={"script": script, "signature": signature},
            headers=headers,
            verify=verify,
            timeout=120,
        )
        resp.raise_for_status()
        agent_output = resp.json()
    except Exception as exc:
        return jsonify({"error": f"Impossible de joindre l'agent : {exc}"}), 502

    results = _replay_and_log_bulk_windows(
        system_id, base_url, headers, verify, included, controls_by_id,
        agent_output.get("output", ""), executed_by,
    )
    success_count = sum(1 for r in results if r["log_status"] == "success")

    return jsonify({
        "message": f"Remédiation exécutée ({len(included)} contrôle(s), {success_count} vérifié(s) conforme(s)).",
        "control_ids": included,
        "agent_output": agent_output,
        "results": results,
        "manual_actions": manual_actions,
    }), 200


# Marqueurs écrits par le script groupé (_build_remediation_script) :
# "[OK]  <control_id>" / "[ERR] <control_id> : <message>".
_SCRIPT_MARKER_RE = re.compile(r"^\[(OK|ERR)\]\s*(\S+)", re.MULTILINE)


def _replay_and_log_bulk_windows(
    system_id: int, base_url: str, headers: dict, verify, included: list[str],
    controls_by_id: dict[str, dict], script_output: str, executed_by: int,
) -> list[dict]:
    """Rejoue et journalise chaque contrôle d'une remédiation groupée Windows.

    Les contrôles marqués [ERR] par le script groupé sont journalisés
    directement (on sait déjà que leur remédiation a échoué, inutile de
    rejouer leur audit) ; les autres ([OK], ou marqueur non trouvé — on ne
    suppose jamais un succès sans vérification) sont rejoués un par un via
    /run-control, comme pour la remédiation unitaire (brique 1b).
    """
    from app.models.remediation_log import ScriptType

    markers = {control_id: tag for tag, control_id in _SCRIPT_MARKER_RE.findall(script_output or "")}

    results = []
    for control_id in included:
        if markers.get(control_id) == "ERR":
            remediation_result = {
                "status": "error", "output": "",
                "error": "Échec signalé par le script groupé (voir la sortie complète).",
            }
            log_status, _log_id = _finalize_remediation(
                system_id, control_id, executed_by, ScriptType.powershell,
                remediation_result, None,
            )
            results.append({"control_id": control_id, "control_status": None, "log_status": log_status})
            continue

        remediation_result = {"status": "ok", "output": "Inclus dans le script groupé (marqué [OK])."}
        replay_status, replay_actual = None, None
        try:
            replay_resp = http_client.post(
                f"{base_url}/run-control",
                json={"control": controls_by_id[control_id]},
                headers=headers,
                verify=verify,
                timeout=40,
            )
            replay_resp.raise_for_status()
            replay_data = replay_resp.json()
            replay_status = replay_data.get("status")
            replay_actual = replay_data.get("actual_value")
        except Exception as exc:
            current_app.logger.warning(
                "Rejeu du contrôle %s (remédiation groupée) impossible : %s", control_id, exc
            )

        log_status, _log_id = _finalize_remediation(
            system_id, control_id, executed_by, ScriptType.powershell,
            remediation_result, replay_status, replay_actual,
        )
        results.append({"control_id": control_id, "control_status": replay_status, "log_status": log_status})

    return results


# ---------------------------------------------------------------------------
# Déclenchement de scan depuis l'UI
# ---------------------------------------------------------------------------

@agents_bp.post("/api/agent/trigger/<int:system_id>")
def trigger_scan(system_id: int):
    """Appelle l'agent (port 8585) pour démarrer un scan.

    Appelé par le frontend quand l'admin clique sur « Lancer un audit ».
    """
    from app.models.system import System

    system = db.session.get(System, system_id) if False else \
             __import__("app.utils.db", fromlist=["db"]).db.session.get(System, system_id)
    if not system:
        return jsonify({"error": f"Système id={system_id} introuvable."}), 404

    if not system.ip_address:
        return jsonify({"error": "Adresse IP du système inconnue."}), 400

    try:
        headers = _agent_auth_headers(system)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    base_url, verify = _agent_base_url(system)
    try:
        resp = http_client.post(
            f"{base_url}/run",
            headers=headers,
            verify=verify,
            timeout=5,
        )
        resp.raise_for_status()
        return jsonify({"message": "Scan déclenché.", "agent_response": resp.json()}), 200
    except Exception as exc:
        return jsonify({"error": f"Impossible de joindre l'agent : {exc}"}), 502
