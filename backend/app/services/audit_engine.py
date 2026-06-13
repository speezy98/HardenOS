"""Moteur d'audit et de scoring CIS.

Orchestration : charge le système et son référentiel, collecte chaque contrôle
via un connecteur (bouchon ou vrai scanner), calcule les scores par domaine et
le score global, en déduit le niveau de risque, et persiste le tout.
"""
from datetime import datetime

from app.models.audit import Audit, AuditStatus, CisLevel, RiskLevel
from app.models.audit_result import (
    AuditResult,
    CisLevelResult,
    Domain,
    ResultStatus,
)
from app.models.system import System
from app.services.collectors.base import BaseCollector
from app.services.rules_loader import RulesError, get_ruleset_for_system
from app.utils.db import db

# Les 6 domaines couverts par les référentiels.
DOMAINS = ["access", "network", "logging", "crypto", "updates", "services"]

# Mapping statut -> membre d'enum (ResultStatus.passed porte la valeur "pass",
# car "pass" est un mot-clé Python).
_STATUS_TO_ENUM = {
    "pass": ResultStatus.passed,
    "fail": ResultStatus.fail,
    "warn": ResultStatus.warn,
    "na": ResultStatus.na,
}

# Crédit accordé au numérateur selon le statut (warn = échec partiel à 50%).
_SCORE_CREDIT = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


class AuditError(Exception):
    """Erreur métier du moteur d'audit (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _domain_score(results: list[dict]) -> float | None:
    """Score d'un domaine = somme(crédit*poids des évaluables) / somme(poids) * 100.

    Les contrôles 'na' sont exclus (numérateur ET dénominateur). Un 'warn'
    apporte la moitié du poids. Retourne None si aucun contrôle évaluable.
    """
    total_weight = 0
    earned = 0.0
    for r in results:
        if r["status"] == "na":
            continue
        total_weight += r["weight"]
        earned += _SCORE_CREDIT[r["status"]] * r["weight"]
    if total_weight == 0:
        return None
    return earned / total_weight * 100


def _risk_level(score: float) -> RiskLevel:
    """Niveau de risque depuis le score global.

    >=90 low · >=70 moderate · >=50 high · sinon critical.
    """
    if score >= 90:
        return RiskLevel.low
    if score >= 70:
        return RiskLevel.moderate
    if score >= 50:
        return RiskLevel.high
    return RiskLevel.critical


def recompute_score(audit_id: int) -> None:
    """Recalcule score_global / scores_by_domain / risk_level d'un audit déjà
    persisté, à partir des AuditResult actuels (après une remédiation) —
    sans relancer de collecte. Même formule que run_audit(), pour rester
    cohérent avec le score d'un audit complet."""
    audit = db.session.get(Audit, audit_id)
    if audit is None:
        return

    results = db.session.query(AuditResult).filter_by(audit_id=audit_id).all()

    per_domain: dict[str, list[dict]] = {d: [] for d in DOMAINS}
    all_results: list[dict] = []
    for r in results:
        entry = {"status": r.status.value, "weight": r.weight}
        all_results.append(entry)
        domain = r.domain.value
        if domain in per_domain:
            per_domain[domain].append(entry)

    scores_by_domain = {}
    for domain in DOMAINS:
        score = _domain_score(per_domain[domain])
        scores_by_domain[domain] = round(score) if score is not None else None

    global_score = _domain_score(all_results)
    global_score = round(global_score, 2) if global_score is not None else 0.0

    audit.score_global = global_score
    audit.risk_level = _risk_level(global_score)
    audit.scores_by_domain = scores_by_domain
    db.session.commit()


def run_audit(
    system_id: int,
    triggered_by: int | None,
    collector: BaseCollector,
    seed: int | None = None,
    audit: Audit | None = None,
) -> Audit:
    """Exécute un audit complet sur un système et persiste le résultat.

    Si `audit` est fourni (ex. placeholder 'running' créé en amont pour un audit
    asynchrone), on le remplit ; sinon on en crée un. Le `seed` n'est pas utilisé
    directement ici (le collecteur en est porteur) ; il est accepté pour cohérence.
    """
    system = db.session.get(System, system_id)
    if system is None:
        raise AuditError("Système introuvable", 404)

    try:
        _benchmark, controls = get_ruleset_for_system(system)
    except RulesError as exc:
        raise AuditError(exc.message, exc.status_code) from exc

    if not controls:
        raise AuditError("Le référentiel sélectionné ne contient aucun contrôle", 400)

    # Réutilise l'audit fourni (placeholder async) ou en crée un nouveau.
    if audit is None:
        audit = Audit(
            system_id=system.id,
            triggered_by=triggered_by,
            status=AuditStatus.running,
            started_at=datetime.utcnow(),
            cis_level=CisLevel.L1,  # nos règles sont L1
        )
        db.session.add(audit)
    else:
        audit.status = AuditStatus.running
        if audit.started_at is None:
            audit.started_at = datetime.utcnow()
    db.session.flush()  # pour obtenir audit.id avant d'ajouter les résultats

    try:
        # Accumulateur par domaine pour le scoring (poids + statut).
        per_domain: dict[str, list[dict]] = {d: [] for d in DOMAINS}
        all_results: list[dict] = []

        for control in controls:
            outcome = collector.collect(system, control)
            status = outcome.status
            domain = control["domain"]
            weight = int(control.get("weight", 1))
            expected = control.get("audit", {}).get("expected")

            result = AuditResult(
                audit_id=audit.id,
                control_id=str(control["control_id"]),
                title=control["title"],
                domain=Domain(domain),
                cis_level=CisLevelResult(control.get("cis_level", "L1")),
                weight=weight,
                status=_STATUS_TO_ENUM[status],
                actual_value=outcome.actual_value,
                expected_value=str(expected) if expected is not None else None,
            )
            db.session.add(result)

            entry = {"status": status, "weight": weight}
            all_results.append(entry)
            if domain in per_domain:
                per_domain[domain].append(entry)

        # Scoring par domaine (0 si domaine présent mais sans contrôle évaluable).
        scores_by_domain = {}
        for domain in DOMAINS:
            score = _domain_score(per_domain[domain])
            scores_by_domain[domain] = round(score) if score is not None else None

        # Score global : même formule pondérée sur TOUS les contrôles évaluables
        # (cohérent et insensible au déséquilibre du nombre de contrôles par domaine).
        global_score = _domain_score(all_results)
        global_score = round(global_score, 2) if global_score is not None else 0.0

        audit.status = AuditStatus.done
        audit.finished_at = datetime.utcnow()
        audit.score_global = global_score
        audit.risk_level = _risk_level(global_score)
        audit.scores_by_domain = scores_by_domain

        system.last_audit_at = audit.finished_at

        db.session.commit()
        return audit

    except Exception as exc:
        # Marque l'audit en erreur puis propage proprement.
        db.session.rollback()
        failed = db.session.get(Audit, audit.id)
        if failed is not None:
            failed.status = AuditStatus.error
            failed.finished_at = datetime.utcnow()
            db.session.commit()
        raise AuditError(f"Échec de l'audit : {exc}", 500) from exc
