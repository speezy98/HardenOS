"""Connecteur BOUCHON — résultats de collecte simulés, sans aucun réseau.

Génère pour chaque contrôle un statut tiré aléatoirement avec une distribution
contrôlée (~75% pass). Une graine (seed) optionnelle rend l'audit reproductible :
deux exécutions avec la même seed produisent exactement les mêmes résultats.

La valeur observée (actual_value) est fabriquée de façon RÉELLEMENT cohérente
avec le statut : identique à l'attendu en pass, plausiblement divergente (et
jamais l'attendu décoré d'un suffixe) en fail/warn, vide en na.
"""
import random

from app.services.collectors.base import BaseCollector, CollectionResult

# Couples de valeurs opposées (insensible à la casse) pour fabriquer un fail
# plausible : l'attendu "no" devient "yes", "0" devient "1", etc.
_OPPOSITES = {
    "no": "yes",
    "yes": "no",
    "0": "1",
    "1": "0",
    "false": "true",
    "true": "false",
    "enabled": "disabled",
    "disabled": "enabled",
    "enforcing": "permissive",
    "permissive": "enforcing",
    "active": "inactive",
    "inactive": "active",
    "present": "absent",
    "absent": "present",
}

# Distribution cible des statuts. na rare ; le reste du non-pass majoritairement fail.
#   pass ~75% · fail ~17% · warn ~6% · na ~2%
_STATUS_WEIGHTS = {
    "pass": 0.75,
    "fail": 0.17,
    "warn": 0.06,
    "na": 0.02,
}


class StubCollector(BaseCollector):
    """Collecteur simulé déterministe (via seed)."""

    def __init__(self, seed: int | None = None):
        # Générateur dédié : n'altère pas l'état global de random, et permet la
        # reproductibilité par seed indépendamment du reste du processus.
        self._rng = random.Random(seed)
        self._statuses = list(_STATUS_WEIGHTS.keys())
        self._weights = list(_STATUS_WEIGHTS.values())

    def collect(self, system, control: dict) -> CollectionResult:
        status = self._rng.choices(self._statuses, weights=self._weights, k=1)[0]
        expected = control.get("audit", {}).get("expected")

        if status == "na":
            # Non applicable : aucune valeur observée.
            return CollectionResult(status="na", actual_value=None)

        if status == "pass":
            # Conforme : observé strictement identique à l'attendu (aucun suffixe).
            actual = expected if expected is not None else "conforme"
            return CollectionResult(status="pass", actual_value=str(actual))

        if status == "warn":
            # Avertissement : configuration partielle/ambiguë, distincte de l'attendu.
            actual = self._rng.choice(
                ["valeur partielle", "partiellement configuré", "configuration incomplète"]
            )
            return CollectionResult(status="warn", actual_value=actual)

        # fail : valeur réellement divergente de l'attendu, plausible et lisible.
        return CollectionResult(status="fail", actual_value=self._fail_value(expected))

    def _fail_value(self, expected) -> str:
        """Fabrique une valeur observée qui VIOLE clairement l'attendu."""
        if expected is None:
            # Attendu exprimé en condition texte : on renvoie un constat de violation.
            return self._rng.choice(
                ["non conforme", "non configuré", "valeur absente"]
            )

        expected = str(expected)
        tokens = expected.split()

        # Cas "clé valeur" (ex. "permitrootlogin no") : on inverse le dernier token.
        if len(tokens) >= 2:
            last = tokens[-1]
            opp = self._opposite_token(last)
            if opp is not None:
                return " ".join(tokens[:-1] + [opp])

        # Token unique opposable (no/yes, 0/1, False/True, Enforcing/Permissive...).
        opp = self._opposite_token(expected)
        if opp is not None:
            return opp

        # Valeur purement numérique : une autre valeur numérique nette.
        if expected.strip().lstrip("-").isdigit():
            return self._different_number(expected.strip())

        # Aucune transformation évidente : valeur clairement distincte.
        return f"non conforme : {expected}"

    def _opposite_token(self, token: str) -> str | None:
        """Retourne l'opposé d'un token connu en préservant la casse, sinon None."""
        opp = _OPPOSITES.get(token.lower())
        if opp is None:
            return None
        # Préserve la casse de l'attendu (False -> True, ENABLED -> DISABLED...).
        if token.isupper():
            return opp.upper()
        if token[:1].isupper():
            return opp.capitalize()
        return opp

    def _different_number(self, value: str) -> str:
        """Renvoie un nombre différent de `value` (plausible, déterministe)."""
        try:
            n = int(value)
        except ValueError:
            return "non conforme : " + value
        # 0 -> 1, sinon une valeur franchement différente.
        return "1" if n == 0 else str(self._rng.choice([0, n + 1, n * 2 + 1]))
