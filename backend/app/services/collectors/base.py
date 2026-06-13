"""Interface abstraite des connecteurs de collecte."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CollectionResult:
    """Résultat de la collecte d'un contrôle sur un système.

    - status      : 'pass' | 'fail' | 'warn' | 'na' (statut déterminé par le collecteur)
    - actual_value: valeur observée sur la cible (None si na)
    """

    status: str
    actual_value: str | None = None


class BaseCollector(ABC):
    """Contrat commun à tous les connecteurs (bouchon ou vrais scanners).

    Le moteur d'audit appelle `collect(system, control)` sans connaître
    l'implémentation concrète.
    """

    @abstractmethod
    def collect(self, system, control: dict) -> CollectionResult:
        """Collecte le résultat d'un contrôle pour un système donné."""
        raise NotImplementedError
