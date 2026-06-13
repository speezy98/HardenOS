"""Connecteurs de collecte des contrôles CIS.

`BaseCollector` est l'interface ; `StubCollector` est une implémentation bouchon
(aucune connexion réseau). Les vrais scanners SSH/WinRM implémenteront la même
interface et remplaceront le bouchon sans toucher au moteur d'audit.
"""
from app.services.collectors.base import BaseCollector, CollectionResult
from app.services.collectors.ssh_collector import SSHCollector, SSHConnectionError
from app.services.collectors.stub import StubCollector

__all__ = [
    "BaseCollector",
    "CollectionResult",
    "StubCollector",
    "SSHCollector",
    "SSHConnectionError",
]
