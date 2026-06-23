"""Envoi des résultats d'audit au backend HardenOS via HTTPS."""
import json
import socket
from datetime import datetime, timezone

import requests
import urllib3

import config
from collector import ControlResult

# Silence les warnings SSL en cas de certificat auto-signé (dev/air-gapped)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _build_payload(results: list[ControlResult],
                   scan_started_at: datetime,
                   scan_finished_at: datetime) -> dict:
    """Construit le JSON à envoyer au backend."""
    return {
        "system_id": config.get_int("system_id"),
        "hostname": socket.gethostname(),
        "ip_address": _get_local_ip(),
        "os_type": "windows",
        "scan_started_at": scan_started_at.isoformat(),
        "scan_finished_at": scan_finished_at.isoformat(),
        "results": [
            {
                "control_id": r.control_id,
                "title": r.title,
                "domain": r.domain,
                "cis_level": r.cis_level,
                "weight": r.weight,
                "impact": r.impact,
                "status": r.status,
                "actual_value": r.actual_value,
                "expected_value": r.expected_value,
                "error": r.error,
            }
            for r in results
        ],
    }


def _get_local_ip() -> str:
    """Retourne l'adresse IP locale (best-effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def send(results: list[ControlResult],
         scan_started_at: datetime,
         scan_finished_at: datetime) -> dict:
    """Envoie les résultats au backend.

    Retourne la réponse JSON du backend ou lève une exception.
    """
    backend_url = config.get("backend_url").rstrip("/")
    agent_token = config.get("agent_token")
    verify_ssl = config.get_verify()

    url = f"{backend_url}/api/agent/audit"
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Token": agent_token,
    }
    payload = _build_payload(results, scan_started_at, scan_finished_at)

    response = requests.post(
        url,
        headers=headers,
        data=json.dumps(payload),
        verify=verify_ssl,
        timeout=60,
    )
    response.raise_for_status()
    return response.json()
