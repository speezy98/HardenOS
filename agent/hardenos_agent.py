
"""HardenOS Windows Agent — Serveur HTTP sur le port 8585.

L'agent :
  1. S'enregistre automatiquement auprès du backend au premier démarrage
  2. Écoute sur 0.0.0.0:8585 les requêtes du backend
  3. GET  /status  → renvoie l'état de l'agent
  4. POST /run     → déclenche un scan CIS dans un thread séparé

Modes de lancement :
  python hardenos_agent.py run      # exécution directe (dev / test)
  python hardenos_agent.py install  # installe le service Windows
  python hardenos_agent.py start    # démarre le service
  python hardenos_agent.py stop     # arrête le service
  python hardenos_agent.py remove   # désinstalle le service
"""
import hmac
import json
import logging
import os
import socket
import ssl
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

 
# Logging
 
LOG_FILE = os.path.join(os.path.dirname(__file__), "hardenos_agent.log")
_log_handlers = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
if sys.stdout is not None:
    # sys.stdout est None quand l'exe figé (PyInstaller) est lancé sans
    # console attachée (ex. démarré par le Service Control Manager) —
    # ajouter un StreamHandler dans ce cas fait planter le premier log.info()
    # avant que le service ait pu signaler SERVICE_RUNNING (→ erreur 1053).
    _log_handlers.append(logging.StreamHandler(sys.stdout))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_log_handlers,
)
log = logging.getLogger("hardenos_agent")

 
# Modules internes
 
import config
import collector
import sender
import register
import remediate
import tls
import backup


# État global du scan

_scan_lock = threading.Lock()
_scan_running = False


# État global du serveur HTTP(S) — permet le rechargement à chaud HTTP -> HTTPS

_server_lock = threading.Lock()
_current_server: HTTPServer | None = None


def _run_scan() -> None:
    """Lance un cycle complet d'audit et envoie les résultats au backend."""
    global _scan_running
    log.info("=== Démarrage du scan CIS ===")
    started = datetime.now(timezone.utc)

    try:
        results = collector.collect_all()
    except Exception as exc:
        log.error("Erreur lors de la collecte : %s", exc)
        _scan_running = False
        return

    finished = datetime.now(timezone.utc)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    warn   = sum(1 for r in results if r.status == "warn")
    log.info(
        "Collecte terminée en %.1fs — pass=%d fail=%d warn=%d",
        (finished - started).total_seconds(), passed, failed, warn,
    )

    try:
        resp = sender.send(results, started, finished)
        log.info(
            "Résultats envoyés — audit_id=%s score=%.1f%%",
            resp.get("audit_id", "?"), resp.get("score_global", 0),
        )
    except Exception as exc:
        log.error("Erreur lors de l'envoi : %s", exc)
    finally:
        _scan_running = False


 
# Serveur HTTP
 

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug("HTTP %s", fmt % args)

    def _json(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        """Vérifie le header X-Agent-Token envoyé par le backend.

        Le secret partagé est l'agent_token de agent.conf (le même que
        l'agent utilise pour s'authentifier auprès du backend). La
        comparaison est en temps constant pour éviter les attaques
        temporelles. Renvoie False (et répond 401/403) si invalide.
        """
        expected = config.get("agent_token").strip()
        if not expected:
            log.warning("Requête refusée : aucun agent_token configuré sur l'agent.")
            self._json(403, {"error": "Agent non configuré (agent_token absent)."})
            return False
        provided = (self.headers.get("X-Agent-Token") or "").strip()
        if not provided or not hmac.compare_digest(provided, expected):
            log.warning(
                "Requête %s refusée : token invalide (source %s).",
                self.path, self.client_address[0],
            )
            self._json(401, {"error": "Token d'agent invalide ou manquant."})
            return False
        return True

    def do_GET(self):  # noqa: N802
        if self.path == "/status":
            self._json(200, {
                "status": "running",
                "hostname": socket.gethostname(),
                "scan_running": _scan_running,
            })
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):  # noqa: N802
        global _scan_running

        # /run, /remediate-script, /run-control, /backup et /rollback
        # exécutent du code : token obligatoire. /setup est le premier
        # appairage (l'agent n'a pas encore de token) et reste protégé par
        # is_configured().
        if self.path in ("/run", "/remediate-script", "/run-control", "/backup", "/rollback") \
                and not self._authorized():
            return

        if self.path == "/run":
            with _scan_lock:
                if _scan_running:
                    self._json(409, {"message": "Scan déjà en cours."})
                    return
                _scan_running = True
            threading.Thread(target=_run_scan, daemon=True).start()
            self._json(200, {"message": "Scan démarré"})

        elif self.path == "/remediate-script":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            script = body.get("script", "").strip()
            signature = body.get("signature", "").strip()
            if not script:
                self._json(400, {"error": "Champ 'script' manquant."})
                return
            result = remediate.execute_script(script, signature)
            code = 200 if result["status"] == "ok" else 500
            self._json(code, result)

        elif self.path == "/backup":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            snapshot_name = body.get("snapshot_name", "").strip()
            if not snapshot_name:
                self._json(400, {"error": "Champ 'snapshot_name' manquant."})
                return
            result = backup.create_backup(snapshot_name)
            code = 200 if result["status"] == "ok" else 500
            self._json(code, result)

        elif self.path == "/rollback":
            log.info("Requête /rollback reçue (Content-Length=%s).", self.headers.get("Content-Length"))
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            log.info("Corps /rollback lu et décodé avec succès.")
            paths = body.get("paths")
            if not paths:
                self._json(400, {"error": "Champ 'paths' manquant."})
                return
            result = backup.restore_backup(paths)
            log.info("restore_backup() est revenue : %s", result)
            code = 200 if result["status"] == "ok" else 500
            self._json(code, result)

        elif self.path == "/run-control":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            control = body.get("control")
            if not control or not control.get("control_id"):
                self._json(400, {"error": "Champ 'control' manquant ou invalide."})
                return
            try:
                result = collector.run_control(control)
            except Exception as exc:
                log.error("Erreur lors du rejeu du contrôle %s : %s", control.get("control_id"), exc)
                self._json(502, {"error": f"Échec du rejeu : {exc}"})
                return
            self._json(200, {
                "control_id": result.control_id,
                "status": result.status,
                "actual_value": result.actual_value,
                "error": result.error,
            })

        elif self.path == "/setup":
            if config.is_configured():
                self._json(409, {"error": "Agent déjà configuré. Supprimez system_id et agent_token de agent.conf pour réinitialiser."})
                return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            system_id = body.get("system_id")
            agent_token = body.get("agent_token", "").strip()
            ca_cert_pem = body.get("ca_cert", "").strip()
            if not system_id or not agent_token:
                self._json(400, {"error": "Champs 'system_id' et 'agent_token' requis."})
                return
            try:
                config.save_registration(int(system_id), agent_token)
                if ca_cert_pem:
                    tls.save_ca_cert(ca_cert_pem)
                    log.info("Certificat de la CA reçu et enregistré.")
                log.info("Configuration reçue du backend — system_id=%s", system_id)
                self._json(200, {"message": "Agent configuré avec succès."})
                # Le serveur HTTP tourne déjà (démarré avant que l'agent ait un
                # token) : on récupère le certificat puis on recharge le
                # serveur en HTTPS à chaud, en tâche de fond (voir
                # _bootstrap_certificate_and_reload / reload_tls_server).
                threading.Thread(target=_bootstrap_certificate_and_reload, daemon=True).start()
            except Exception as exc:
                log.error("Erreur écriture agent.conf : %s", exc)
                self._json(500, {"error": "Impossible d'écrire dans agent.conf."})

        else:
            self._json(404, {"error": "Not found"})


def _detect_lan_ip() -> str:
    """Retourne l'IP LAN de la machine (best-effort, sans trafic réel).

    Sert d'adresse d'écoute afin d'éviter 0.0.0.0 (toutes les interfaces,
    trop exposé) : l'agent ne se lie qu'à son unique interface réseau.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _build_server() -> HTTPServer:
    """Construit le serveur HTTP(S) (sans bloquer) — HTTPS si un certificat
    local est disponible, HTTP sinon."""
    host = _detect_lan_ip()
    port = config.get_int("listen_port")
    server = HTTPServer((host, port), _Handler)

    if tls.has_certificate():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls.CERT_PATH, keyfile=tls.KEY_PATH)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        log.info("Serveur HTTPS démarré sur %s:%d.", host, port)
    else:
        log.warning(
            "Aucun certificat local (agent/certs/agent.crt) — serveur démarré "
            "en HTTP non chiffré. Basculera automatiquement en HTTPS dès "
            "qu'un certificat sera obtenu, sans redémarrage."
        )
        log.info("Serveur HTTP démarré sur %s:%d.", host, port)

    return server


def _start_http_server() -> None:
    """Boucle de service du serveur agent (bloquant).

    Un appel à reload_tls_server() depuis un autre thread interrompt le tour
    courant (server.shutdown()) pour relancer immédiatement avec le
    certificat désormais disponible : c'est le mécanisme qui permet de
    passer d'HTTP à HTTPS à chaud, sans redémarrer le processus.
    """
    global _current_server
    register.ensure_certificate()

    while True:
        with _server_lock:
            server = _build_server()
            _current_server = server
        server.serve_forever()
        server.server_close()


def reload_tls_server() -> None:
    """Relance le serveur agent en HTTPS à chaud dès qu'un certificat est prêt.

    Doit être appelé depuis un thread différent de celui qui exécute
    serve_forever() (sinon deadlock — cf. doc Python de HTTPServer.shutdown()).
    """
    with _server_lock:
        server = _current_server
    if server is not None:
        log.info("Certificat disponible — rechargement du serveur agent en HTTPS...")
        server.shutdown()


def _bootstrap_certificate_and_reload() -> None:
    """Récupère le certificat TLS de l'agent puis recharge le serveur à chaud.

    Appelé en tâche de fond juste après un /setup réussi (l'agent vient
    d'obtenir son token mais son serveur HTTP tourne déjà sans certificat).
    """
    register.ensure_certificate()
    if tls.has_certificate():
        reload_tls_server()


 
# Windows Service (pywin32 — optionnel)
 

def _try_win32():
    try:
        import win32serviceutil, win32service, win32event, servicemanager
        return win32serviceutil, win32service, win32event, servicemanager
    except ImportError:
        return None


_win32 = _try_win32()

if _win32:
    win32serviceutil, win32service, win32event, servicemanager = _win32

    class HardenOSService(win32serviceutil.ServiceFramework):
        _svc_name_ = "HardenOSAgent"
        _svc_display_name_ = "HardenOS Security Agent"
        _svc_description_ = (
            "Agent de conformité CIS HardenOS — "
            "serveur HTTP port 8585, scan déclenché par le backend."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            log.info("Arrêt du service demandé.")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            log.info("Service HardenOS Agent démarré.")
            threading.Thread(target=_start_http_server, daemon=True).start()
            # Sans ce signal explicite, le Gestionnaire des services attend une
            # confirmation qui n'arrive jamais et finit par abandonner le
            # démarrage ("Le service n'a pas répondu assez vite..."), même si
            # le serveur HTTP démarre correctement en interne.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            log.info("Service HardenOS Agent arrêté.")


# Point d'entrée


def main():
    if len(sys.argv) == 1 and _win32:
        # Lancé sans argument = démarré par le Service Control Manager.
        # HandleCommandLine() n'est qu'un parseur d'arguments (install/start/
        # stop/debug) : avec 0 argument il affiche l'usage et sys.exit(1),
        # il ne faut donc jamais l'appeler ici. L'hébergement réel du
        # service passe par StartServiceCtrlDispatcher().
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(HardenOSService)
        servicemanager.StartServiceCtrlDispatcher()
        return

    if len(sys.argv) >= 2:
        cmd = sys.argv[1].lower()

        if cmd in ("install", "remove", "start", "stop", "restart", "update", "debug") \
                and _win32:
            win32serviceutil.HandleCommandLine(HardenOSService)
            return

        if cmd == "run":
            log.info("Mode exécution directe (hors service).")
            _start_http_server()  # bloquant
            return

    print(
        "Usage :\n"
        "  python hardenos_agent.py run      # démarre le serveur HTTP (dev/test)\n"
        "  python hardenos_agent.py install  # installe le service Windows\n"
        "  python hardenos_agent.py start    # démarre le service\n"
        "  python hardenos_agent.py stop     # arrête le service\n"
        "  python hardenos_agent.py remove   # désinstalle le service\n"
    )


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        import traceback
        _crash_path = os.path.join(os.path.dirname(__file__), "crash.log")
        with open(_crash_path, "a", encoding="utf-8") as _f:
            _f.write(f"\n--- {datetime.now(timezone.utc).isoformat()} ---\n")
            traceback.print_exc(file=_f)
        raise
