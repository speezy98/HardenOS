"""Exécution du script de remédiation CIS

 backend génère un script PwShell complet, le signe (Ed25519) et l'envoie.
   L'agent vérifie la signature avec sa clé publique locale (voir tls.py)
avant d'écrire quoi que ce soit sur disque, puis exécute via PowerShell
avec -ExecutionPolicy Bypass (pas de restriction d'exécution). Un script
non signé, ou dont la signature ne correspond pas, est rejeté sans être
écrit ni exécuté.
"""
import base64
import logging
import subprocess
import tempfile
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import tls
import undo

log = logging.getLogger("hardenos_agent")

PS_TIMEOUT = 120


def _load_signing_pubkey():
    if not tls.has_signing_pubkey():
        return None
    with open(tls.SIGNING_PUBKEY_PATH, "rb") as f:
        return load_pem_public_key(f.read())


def _verify_signature(script: str, signature: str | None) -> str | None:
    """Vérifie la signature Ed25519 du script. Retourne un message d'erreur
    (str) si invalide/absente, ou None si la vérification a réussi."""
    pubkey = _load_signing_pubkey()
    if pubkey is None:
        return "Clé publique de signature absente localement."
    if not signature:
        return "Signature manquante."
    try:
        pubkey.verify(base64.b64decode(signature), script.encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError):
        return "Signature invalide."
    return None


def execute_script(script: str, signature: str | None = None) -> dict:
    """Vérifie la signature du script puis l'exécute via PowerShell si valide.

    Retourne :
      { "status": "ok",    "output": "..." }
      { "status": "error", "output": "...", "error": "..." }
    """
    error = _verify_signature(script, signature)
    if error:
        log.error("Script de remédiation rejeté (non exécuté) : %s", error)
        return {"status": "error", "output": "", "error": error}
    log.info("Signature du script de remédiation vérifiée avec succès.")

    log.info("Exécution du script de remédiation (%d caractères).", len(script))

    # Capturé AVANT exécution : permet de proposer un rollback individuel
    # (registre uniquement pour l'instant, cf. undo.py) si la remédiation
    # réussit. None pour tout script hors de ce périmètre (bulk, autres
    # familles) — pas de rollback individuel proposé dans ce cas.
    before_state = undo.capture_before_state(script)

    # Écrire dans un fichier .ps1 temporaire
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        result = subprocess.run(
            [
                "powershell",
                "-NonInteractive",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", tmp_path,
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=PS_TIMEOUT,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and stderr:
            log.error("Script de remédiation échoué (code %d) : %s", result.returncode, stderr)
            return {"status": "error", "output": stdout, "error": stderr}

        log.info("Script de remédiation terminé avec succès.")
        return {"status": "ok", "output": stdout, "undo_script": undo.build_undo_script(before_state)}

    except subprocess.TimeoutExpired:
        log.error("Timeout : le script de remédiation a dépassé %ds.", PS_TIMEOUT)
        return {"status": "error", "output": "", "error": f"Timeout après {PS_TIMEOUT}s"}
    except Exception as exc:
        log.error("Erreur inattendue : %s", exc)
        return {"status": "error", "output": "", "error": str(exc)}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
