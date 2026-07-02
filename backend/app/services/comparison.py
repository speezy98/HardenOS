"""Comparaison d'audits (évolution de la conformité entre deux audits).

Ce service est **totalement agnostique à l'OS** : il n'opère que sur la structure
d'audit commune (score global, scores par domaine, résultats par contrôle) que le
moteur d'audit produit à l'identique quel que soit le collecteur (SSH Linux,
bouchon, WinRM à venir…). Aucune logique ne dépend de `system.os_type`.

Trois opérations :
- `list_comparable_systems()` : systèmes ayant AU MOINS DEUX audits terminés.
- `list_done_audits(system_id)` : audits terminés d'un système (choix des deux).
- `compare_audits(audit_a_id, audit_b_id)` : diff scores + domaines + contrôles.

Le contrôleur (controllers/comparison.py) reste mince : il appelle ce service et
mappe les ComparisonError vers des réponses HTTP.
"""
from app.models.audit import Audit, AuditStatus
from app.models.audit_result import AuditResult
from app.models.system import System
from app.utils.db import db

# Rang de sévérité : traite toutes les transitions de statut de façon uniforme.
# Un statut de rang plus BAS est "meilleur". na et pass sont neutres (rang 0) car
# 'na' (non évaluable) n'est ni une réussite ni un échec au sens du score.
# Aligné sur le utilitaire frontend (utils/auditDiff.js) pour un contrat commun.
_SEVERITY = {"pass": 0, "na": 0, "warn": 1, "fail": 2}


class ComparisonError(Exception):
    """Erreur métier de comparaison (mappée vers un code HTTP par le contrôleur)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# --- Helpers -----------------------------------------------------------------


def _get_done_audit(audit_id: int) -> Audit:
    """Charge un audit et vérifie qu'il est terminé (sinon 404 / 400)."""
    audit = db.session.get(Audit, audit_id)
    if audit is None:
        raise ComparisonError(f"Audit {audit_id} introuvable", 404)
    if audit.status != AuditStatus.done:
        raise ComparisonError(
            f"L'audit {audit_id} n'est pas terminé (statut : {audit.status.value})",
            400,
        )
    return audit


def _domain_delta(before: dict | None, after: dict | None) -> dict:
    """Delta des 6 scores par domaine entre deux audits.

    Chaque domaine : { before, after, delta }. Un domaine à None (aucun contrôle
    évaluable dans cet audit) donne delta=None (évolution non calculable).
    """
    before = before or {}
    after = after or {}
    domains = {}
    for name in sorted(set(before) | set(after)):
        b = before.get(name)
        a = after.get(name)
        delta = round(a - b, 2) if (a is not None and b is not None) else None
        domains[name] = {"before": b, "after": a, "delta": delta}
    return domains


def _entry(before: AuditResult, after: AuditResult) -> dict:
    """Ligne de diff pour un contrôle présent dans les deux audits."""
    return {
        "control_id": before.control_id,
        "title": before.title,
        "domain": before.domain.value,
        "cis_level": before.cis_level.value,
        "status_before": before.status.value,
        "status_after": after.status.value,
        "actual_before": before.actual_value,
        "actual_after": after.actual_value,
    }


# --- Opérations --------------------------------------------------------------


def list_comparable_systems() -> list[dict]:
    """Systèmes ayant AU MOINS DEUX audits terminés (comparables).

    Agnostique à l'OS : un système Windows avec 2 audits 'done' apparaît au même
    titre qu'un Linux. Une machine avec 0 ou 1 audit terminé n'apparaît pas.
    """
    done_count = (
        db.select(
            Audit.system_id.label("system_id"),
            db.func.count(Audit.id).label("done_count"),
        )
        .where(Audit.status == AuditStatus.done)
        .group_by(Audit.system_id)
        .having(db.func.count(Audit.id) >= 2)
        .subquery()
    )

    rows = db.session.execute(
        db.select(System, done_count.c.done_count)
        .join(done_count, System.id == done_count.c.system_id)
        .order_by(System.id)
    ).all()

    return [
        {**system.to_dict(), "done_audits_count": int(count)}
        for system, count in rows
    ]


def list_done_audits(system_id: int) -> list[dict]:
    """Audits terminés d'un système (id, date, score), du plus récent au plus ancien.

    Sert à l'utilisateur pour choisir les deux audits à comparer.
    """
    system = db.session.get(System, system_id)
    if system is None:
        raise ComparisonError("Système introuvable", 404)

    audits = db.session.scalars(
        db.select(Audit)
        .filter_by(system_id=system_id, status=AuditStatus.done)
        .order_by(Audit.created_at.desc(), Audit.id.desc())
    ).all()
    return [a.to_summary() for a in audits]


def compare_audits(audit_a_id: int, audit_b_id: int) -> dict:
    """Compare deux audits TERMINÉS d'une MÊME machine.

    Validation :
    - les deux audits existent et sont terminés (status=done) ;
    - ils appartiennent au même système (refus 400 sinon) ;
    - deux audits identiques sont refusés (comparaison sans objet).

    A = "avant", B = "après". Le diff par contrôle s'appuie sur `control_id`
    (indépendant de l'OS). Un contrôle absent d'un des deux audits est reporté
    à part (`added` / `removed`) plutôt qu'ignoré silencieusement.
    """
    if audit_a_id == audit_b_id:
        raise ComparisonError("Les deux audits à comparer doivent être différents", 400)

    audit_a = _get_done_audit(audit_a_id)
    audit_b = _get_done_audit(audit_b_id)

    if audit_a.system_id != audit_b.system_id:
        raise ComparisonError(
            "Les deux audits doivent appartenir à la même machine", 400
        )

    index_a = {r.control_id: r for r in audit_a.results}
    index_b = {r.control_id: r for r in audit_b.results}

    improvements: list[dict] = []
    regressions: list[dict] = []
    unchanged: list[dict] = []
    added: list[dict] = []    # présent en B seulement (nouveau contrôle)
    removed: list[dict] = []  # présent en A seulement (contrôle disparu)

    for control_id in sorted(set(index_a) | set(index_b)):
        before = index_a.get(control_id)
        after = index_b.get(control_id)

        if before is None:
            added.append(after.to_dict())
            continue
        if after is None:
            removed.append(before.to_dict())
            continue

        rank_before = _SEVERITY.get(before.status.value, 0)
        rank_after = _SEVERITY.get(after.status.value, 0)
        entry = _entry(before, after)
        if rank_after < rank_before:
            improvements.append(entry)
        elif rank_after > rank_before:
            regressions.append(entry)
        else:
            unchanged.append(entry)

    before_score = audit_a.score_global
    after_score = audit_b.score_global
    delta = (
        round(after_score - before_score, 2)
        if (before_score is not None and after_score is not None)
        else None
    )

    return {
        "system_id": audit_a.system_id,
        "audit_before": audit_a.to_summary(),
        "audit_after": audit_b.to_summary(),
        "score_diff": {
            "before": before_score,
            "after": after_score,
            "delta": delta,
        },
        "domains": _domain_delta(
            audit_a.scores_by_domain, audit_b.scores_by_domain
        ),
        "improvements": improvements,
        "regressions": regressions,
        "unchanged": unchanged,
        "added": added,
        "removed": removed,
        "summary": {
            "improved": len(improvements),
            "regressed": len(regressions),
            "unchanged": len(unchanged),
            "added": len(added),
            "removed": len(removed),
        },
    }
