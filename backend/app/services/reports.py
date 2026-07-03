"""Assemblage d'un rapport d'audit.

Réunit, pour un audit donné, TOUTES les données nécessaires à un rapport
exploitable : identité machine, synthèse (score/risque/domaines), compteurs
calculés depuis les résultats, et le détail des contrôles enrichi de la
REMEDIATION issue du référentiel YAML du système (jointe par control_id).

La remediation n'est pas persistée dans audit_results : on la récupère au moment
de générer le rapport via le même référentiel que celui utilisé par l'audit
(rules_loader.get_ruleset_for_system), sans casser la résolution existante.

Le contrôleur reste mince : il appelle build_report() et mappe ReportError.
"""
from app.models.audit import Audit, AuditStatus
from app.models.system import System
from app.services.rules_loader import RulesError, get_ruleset_for_system
from app.utils.dates import utc_isoformat
from app.utils.db import db


class ReportError(Exception):
    """Erreur métier de génération de rapport (mappée vers un code HTTP)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _remediation_by_control(system: System) -> dict[str, dict | None]:
    """Map control_id -> remediation (dict) du référentiel YAML du système.

    Résout le référentiel comme l'audit (os_family -> fichier, avec repli sur
    os_version). Si le référentiel est introuvable, on renvoie une map vide :
    le rapport reste générable, chaque contrôle aura remediation=None.
    """
    try:
        _benchmark, controls = get_ruleset_for_system(system)
    except RulesError:
        return {}

    mapping: dict[str, dict | None] = {}
    for control in controls:
        # control_id peut être un nombre/chaîne dans le YAML : on normalise en str,
        # comme le fait le moteur d'audit lors de la persistance des résultats.
        cid = str(control.get("control_id"))
        mapping[cid] = control.get("remediation")
    return mapping


def _counts(results: list) -> dict:
    """Compteurs par statut, calculés depuis les résultats (jamais inventés)."""
    counts = {"pass": 0, "fail": 0, "warn": 0, "na": 0}
    for r in results:
        status = r.status.value
        if status in counts:
            counts[status] += 1
    counts["total"] = len(results)
    return counts


def build_report(audit_id: int) -> dict:
    """Assemble le rapport d'un audit terminé.

    Lève ReportError(404) si l'audit n'existe pas, (400) s'il n'est pas terminé.
    """
    audit = db.session.get(Audit, audit_id)
    if audit is None:
        raise ReportError("Audit introuvable", 404)
    if audit.status != AuditStatus.done:
        raise ReportError(
            f"L'audit n'est pas terminé (statut : {audit.status.value})", 400
        )

    system = db.session.get(System, audit.system_id)
    if system is None:
        raise ReportError("Système de l'audit introuvable", 404)

    remediations = _remediation_by_control(system)

    controls = []
    for r in audit.results:
        controls.append(
            {
                "control_id": r.control_id,
                "title": r.title,
                "domain": r.domain.value,
                "cis_level": r.cis_level.value,
                "weight": r.weight,
                "status": r.status.value,
                "actual_value": r.actual_value,
                "expected_value": r.expected_value,
                # None proprement si le contrôle n'a pas de remediation dans le YAML.
                "remediation": remediations.get(r.control_id),
            }
        )

    return {
        "system": {
            "id": system.id,
            "hostname": system.hostname,
            "ip_address": system.ip_address,
            "os_type": system.os_type.value,
            "os_version": system.os_version,
        },
        "audit": {
            "id": audit.id,
            "cis_level": audit.cis_level.value,
            "status": audit.status.value,
            "started_at": utc_isoformat(audit.started_at),
            "finished_at": utc_isoformat(audit.finished_at),
            "created_at": utc_isoformat(audit.created_at),
        },
        "summary": {
            "score_global": audit.score_global,
            "risk_level": audit.risk_level.value if audit.risk_level else None,
            "scores_by_domain": audit.scores_by_domain,
            "counts": _counts(audit.results),
        },
        "controls": controls,
    }
