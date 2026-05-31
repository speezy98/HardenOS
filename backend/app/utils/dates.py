"""Sérialisation des dates envoyées au frontend.

Nos colonnes DateTime sont naïves (pas de fuseau en base) mais toujours
alimentées en UTC (`func.now()` côté Postgres, `datetime.utcnow()` côté
Python). Sans indication explicite, `dt.isoformat()` produit une chaîne sans
fuseau que le navigateur interprète comme une heure LOCALE au lieu de la
convertir depuis l'UTC — d'où un décalage égal au fuseau local de
l'utilisateur dans l'affichage.
"""
from datetime import datetime


def utc_isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat() + "Z"
