"""Service chargé de traiter les résultats d'audit envoyés par les agents.
 Il enregistre l'audit et ses contrôles, calcule les scores et le niveau de risque, 
 puis met à jour les informations du système."""

from datetime import datetime, timezone

from app.models.audit import Audit, AuditStatus, RiskLevel, CisLevel
from app.models.audit_result import AuditResult, Domain, ResultStatus, CisLevelResult
from app.models.system import System
from app.utils.db import db


class AgentIngestError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)



# Authentification par token agent


def authenticate_agent(system_id: int, agent_token: str) -> System:
    """Vérifie que le token correspond au système déclaré """
    system = db.session.get(System, system_id)
    if system is None:
        raise AgentIngestError("Système introuvable.", 404)
    if not system.agent_token:
        raise AgentIngestError(
            "Aucun token agent configuré pour ce système.", 403
        )
    if system.agent_token != agent_token:
        raise AgentIngestError("Token agent invalide.", 403)
    return system



# scoring


_DOMAIN_MAP = {d.value: d for d in Domain}
_RESULT_STATUS_MAP = {s.value: s for s in ResultStatus}
_CIS_LEVEL_MAP = {l.value: l for l in CisLevelResult}

_RISK_THRESHOLDS = [
    (80.0, RiskLevel.low),
    (60.0, RiskLevel.moderate),
    (40.0, RiskLevel.high),
    (0.0,  RiskLevel.critical),
]


def _compute_scores(results_data: list[dict]) -> tuple[float, dict, RiskLevel]:
    """Calcule le score global et les scores par domaine     """
    domain_totals: dict[str, dict] = {}

    for r in results_data:
        status = r.get("status", "warn")
        if status in ("warn", "na", "error"):
            continue  # non évaluable, exclu du score

        domain = r.get("domain", "")
        weight = int(r.get("weight", 1))

        if domain not in domain_totals:
            domain_totals[domain] = {"passed": 0, "total": 0}

        domain_totals[domain]["total"] += weight
        if status == "pass":
            domain_totals[domain]["passed"] += weight

    # Scores par domaine
    scores_by_domain: dict[str, float] = {}
    global_passed = 0
    global_total = 0

    for domain, data in domain_totals.items():
        if data["total"] > 0:
            scores_by_domain[domain] = round(
                data["passed"] / data["total"] * 100, 1
            )
        global_passed += data["passed"]
        global_total += data["total"]

    score_global = (
        round(global_passed / global_total * 100, 1) if global_total > 0 else 0.0
    )

    # Niveau de risque
    risk_level = RiskLevel.critical
    for threshold, level in _RISK_THRESHOLDS:
        if score_global >= threshold:
            risk_level = level
            break

    return score_global, scores_by_domain, risk_level



# ingestion principale


def ingest(payload: dict, agent_token: str) -> Audit:
    """Ingère un rapport d'audit depuis l'agent et le persiste en base.

    Retourne l'objet Audit créé.
    """
    system_id = payload.get("system_id")
    if not system_id:
        raise AgentIngestError("Champ 'system_id' manquant.")

    system = authenticate_agent(int(system_id), agent_token)

    results_data: list[dict] = payload.get("results", [])
    if not results_data:
        raise AgentIngestError("Aucun résultat fourni.")

    # Dates de scan
    def _parse_dt(val) -> datetime | None:
        if not val:
            return None
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except ValueError:
            return None

    started_at = _parse_dt(payload.get("scan_started_at")) or datetime.now(timezone.utc)
    finished_at = _parse_dt(payload.get("scan_finished_at")) or datetime.now(timezone.utc)

    # Calcul des scores
    score_global, scores_by_domain, risk_level = _compute_scores(results_data)

    # Réutiliser le placeholder running créé par audit_service si présent
    audit = (
        db.session.query(Audit)
        .filter_by(system_id=system.id, status=AuditStatus.running)
        .order_by(Audit.id.desc())
        .first()
    )

    if audit:
        # Mettre à jour le placeholder existant
        audit.started_at    = started_at
        audit.finished_at   = finished_at
        audit.status        = AuditStatus.done
        audit.score_global  = score_global
        audit.risk_level    = risk_level
        audit.cis_level     = CisLevel.L1
        audit.scores_by_domain = scores_by_domain
    else:
        # Aucun placeholder : l'agent a été déclenché manuellement, créer un audit
        audit = Audit(
            system_id=system.id,
            triggered_by=None,
            started_at=started_at,
            finished_at=finished_at,
            status=AuditStatus.done,
            score_global=score_global,
            risk_level=risk_level,
            cis_level=CisLevel.L1,
            scores_by_domain=scores_by_domain,
        )
        db.session.add(audit)

    db.session.flush()  # génère audit.id si nouvel objet

    # Création des AuditResult
    for r in results_data:
        domain_val = r.get("domain", "")
        domain_enum = _DOMAIN_MAP.get(domain_val)
        if domain_enum is None:
            continue  # domaine inconnu, on ignore

        status_val = r.get("status", "warn")
        status_enum = _RESULT_STATUS_MAP.get(status_val, ResultStatus.warn)

        cis_level_val = r.get("cis_level", "L1")
        cis_level_enum = _CIS_LEVEL_MAP.get(cis_level_val, CisLevelResult.L1)

        result = AuditResult(
            audit_id=audit.id,
            control_id=str(r.get("control_id", "")),
            title=str(r.get("title", ""))[:512],
            domain=domain_enum,
            cis_level=cis_level_enum,
            weight=int(r.get("weight", 1)),
            status=status_enum,
            actual_value=str(r["actual_value"])[:2048] if r.get("actual_value") else None,
            expected_value=str(r["expected_value"])[:2048] if r.get("expected_value") else None,
        )
        db.session.add(result)

    # Mise à jour du système : last_audit_at
    system.last_audit_at = finished_at

    db.session.commit()
    return audit
