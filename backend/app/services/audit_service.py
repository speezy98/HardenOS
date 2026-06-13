"""Orchestration de haut niveau des audits : résolution des credentials,
choix du connecteur, exécution asynchrone (thread + contexte applicatif dédié).

Le moteur `audit_engine.run_audit` reste inchangé : il ne connaît que
`collector.collect(...)`. Ce service-ci s'occupe de fabriquer le bon collecteur
(bouchon, ou SSH connecté) et de gérer le cycle de vie de la connexion + le
threading.
"""
import threading
from datetime import datetime

import requests
from flask import current_app

from app.models.audit import Audit, AuditStatus, CisLevel
from app.models.system import OsType, System
from app.services.audit_engine import AuditError, run_audit
from app.services.collectors import SSHCollector, SSHConnectionError, StubCollector
from app.services.reachability import _AGENT_PORT, _SSH_PORT, tcp_reachable
from app.utils.crypto import CryptoError
from app.utils.db import db
from app.utils.ssh_credentials import decrypt_credentials, encrypt_credentials
from app.utils.ssh_errors import safe_ssh_error_message


def _resolve_ssh_credentials(system: System, ssh_user, ssh_password, save: bool) -> dict:
    """Détermine les credentials SSH à utiliser pour un système Linux.

    - Si fournis dans le body : on les utilise (et on les enregistre si save).
    - Sinon, si le système en a déjà : on les déchiffre.
    - Sinon : erreur 400 (credentials requis).
    """
    if ssh_user and ssh_password:
        if save:
            try:
                system.ssh_credentials_enc = encrypt_credentials(ssh_user, ssh_password)
                db.session.commit()
            except CryptoError as exc:
                raise AuditError(str(exc), 500) from exc
        return {"user": ssh_user, "password": ssh_password}

    if system.ssh_credentials_enc:
        try:
            creds = decrypt_credentials(system.ssh_credentials_enc)
        except CryptoError as exc:
            raise AuditError(str(exc), 500) from exc
        if not creds.get("user"):
            raise AuditError(
                "Les credentials enregistrés n'ont pas d'utilisateur SSH. "
                "Fournissez ssh_user et ssh_password (save_credentials pour les ré-enregistrer).",
                400,
            )
        return creds

    raise AuditError(
        "Credentials SSH requis : fournissez ssh_user et ssh_password "
        "(ce système n'a pas d'identifiants enregistrés).",
        400,
    )


def _run_with_collector(app, audit_id: int, system_id: int, collector):
    """Exécute l'audit (SSH) dans un contexte applicatif + session dédiés (thread).

    Ouvre/ferme la connexion SSH autour de l'exécution et remplit l'audit
    placeholder créé en amont (même id tout au long → suivi simple côté client).
    """
    with app.app_context():
        try:
            collector.connect()  # peut lever SSHConnectionError (message déjà sûr)
            audit = db.session.get(Audit, audit_id)
            run_audit(
                system_id=system_id,
                triggered_by=None,
                collector=collector,
                audit=audit,
            )
        except (SSHConnectionError, AuditError) as exc:
            # Messages déjà courts et non sensibles (SSHConnectionError : mappé ;
            # AuditError : messages métier sans credentials).
            _mark_error(audit_id, str(exc))
        except Exception as exc:  # filet de sécurité
            # Ne jamais logguer/exposer le détail (peut contenir des données
            # sensibles) : on ne garde que le type.
            _mark_error(audit_id, safe_ssh_error_message(exc))
        finally:
            try:
                collector.close()
            except Exception:
                pass


def _mark_error(audit_id: int, message: str) -> None:
    """Passe l'audit en erreur avec un message court et non sensible."""
    db.session.rollback()
    audit = db.session.get(Audit, audit_id)
    if audit is not None:
        audit.status = AuditStatus.error
        audit.finished_at = datetime.utcnow()
        audit.error_message = message
        db.session.commit()


def _agent_watchdog(app, audit_id: int, timeout_seconds: int) -> None:
    """Attend `timeout_seconds` puis passe l'audit en error s'il est encore running.

    Appelé dans un thread daemon : ne bloque pas la réponse HTTP.
    """
    import time
    time.sleep(timeout_seconds)
    with app.app_context():
        audit = db.session.get(Audit, audit_id)
        if audit and audit.status == AuditStatus.running:
            audit.status = AuditStatus.error
            audit.finished_at = datetime.utcnow()
            audit.error_message = (
                f"Délai dépassé ({timeout_seconds // 60} min) : aucun résultat "
                "reçu de l'agent. Le scan a peut-être été interrompu ou n'a pas "
                "pu s'exécuter correctement sur la machine Windows."
            )
            db.session.commit()


def _start_agent_watchdog(app, audit_id: int, timeout_seconds: int) -> None:
    """Lance le watchdog dans un thread daemon."""
    thread = threading.Thread(
        target=_agent_watchdog,
        args=(app, audit_id, timeout_seconds),
        daemon=True,
    )
    thread.start()


def start_audit(
    system_id: int,
    triggered_by: int | None,
    *,
    use_stub: bool = False,
    seed: int | None = None,
    ssh_user: str | None = None,
    ssh_password: str | None = None,
    save_credentials: bool = False,
) -> Audit:
    """Crée un audit 'running' et lance son exécution en arrière-plan.

    Retourne immédiatement l'audit placeholder (status=running) ; le thread le
    remplace par l'audit complet (done) ou le passe en error.

    En mode test/démo (`use_stub`), exécute de façon SYNCHRONE avec le bouchon
    et retourne directement l'audit terminé (pratique pour les tests).
    """
    system = db.session.get(System, system_id)
    if system is None:
        raise AuditError("Système introuvable", 404)

    # --- Mode bouchon : synchrone, sans réseau (démos/tests) ---
    if use_stub:
        return run_audit(
            system_id=system_id,
            triggered_by=triggered_by,
            collector=StubCollector(seed=seed),
        )

    # --- Mode réel Windows : agent HTTP ---
    if system.os_type == OsType.windows:
        if not system.ip_address:
            raise AuditError("Adresse IP du système Windows inconnue.", 400)

        # Vérification de joignabilité avant de créer le placeholder
        if not tcp_reachable(system.ip_address, _AGENT_PORT):
            raise AuditError(
                f"L'agent Windows n'est pas joignable sur {system.ip_address}:{_AGENT_PORT}. "
                "Vérifiez que l'agent HardenOS est démarré et que le port "
                f"{_AGENT_PORT} est autorisé par le pare-feu.",
                503,
            )

        # Créer un audit placeholder visible immédiatement par le client
        audit = Audit(
            system_id=system.id,
            triggered_by=triggered_by,
            status=AuditStatus.running,
            started_at=datetime.utcnow(),
            cis_level=CisLevel.L1,
        )
        db.session.add(audit)
        db.session.commit()

        # Déclencher l'agent en arrière-plan (best-effort).
        # L'agent vérifie X-Agent-Token avant d'accepter le scan.
        try:
            if system.agent_token:
                from app.utils.pki import agent_base_url

                base_url, verify = agent_base_url(system.ip_address)
                requests.post(
                    f"{base_url}/run",
                    headers={"X-Agent-Token": system.agent_token},
                    verify=verify,
                    timeout=10,
                )
        except Exception:
            pass  # L'agent renverra les résultats via POST /api/agent/audit

        # Watchdog : si l'audit est encore running après 2 min → error
        _start_agent_watchdog(
            app=current_app._get_current_object(),
            audit_id=audit.id,
            timeout_seconds=120,
        )

        return audit

    # --- Mode réel Linux : SSH ---
    if system.os_type != OsType.linux:
        raise AuditError("OS non supporté pour l'audit automatique.", 400)

    # Vérification de joignabilité SSH avant de créer le placeholder
    if not system.ip_address:
        raise AuditError("Adresse IP du système Linux inconnue.", 400)

    if not tcp_reachable(system.ip_address, _SSH_PORT):
        raise AuditError(
            f"La machine Linux n'est pas joignable sur {system.ip_address}:{_SSH_PORT}. "
            "Vérifiez que SSH est actif et que le port "
            f"{_SSH_PORT} est autorisé par le pare-feu.",
            503,
        )

    creds = _resolve_ssh_credentials(system, ssh_user, ssh_password, save_credentials)
    collector = SSHCollector(
        hostname=system.ip_address,
        username=creds["user"],
        password=creds["password"],
        port=_SSH_PORT,
    )

    # Audit placeholder 'running' visible immédiatement par le client.
    audit = Audit(
        system_id=system.id,
        triggered_by=triggered_by,
        status=AuditStatus.running,
        started_at=datetime.utcnow(),
        cis_level=CisLevel.L1,
    )
    db.session.add(audit)
    db.session.commit()

    # Thread d'exécution : contexte applicatif + session dédiés.
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_with_collector,
        args=(app, audit.id, system.id, collector),
        daemon=True,
    )
    thread.start()
    return audit
