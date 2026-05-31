"""Point d'entrée WSGI / CLI.

Usage :
    flask --app wsgi db migrate -m "init"
    flask --app wsgi db upgrade
    python wsgi.py            # serveur de développement
"""
import os

from app import create_app

app = create_app()


if __name__ == "__main__":
    # Port 5001 : le port 5000 est occupé par AirPlay sur macOS.
    # HTTPS si BACKEND_TLS_CERT/BACKEND_TLS_KEY sont configurés et existent
    # (cf. `flask issue-backend-cert`), sinon HTTP comme avant.
    cert_path = os.environ.get("BACKEND_TLS_CERT")
    key_path = os.environ.get("BACKEND_TLS_KEY")
    ssl_context = None
    if cert_path and key_path and os.path.isfile(cert_path) and os.path.isfile(key_path):
        ssl_context = (cert_path, key_path)
    app.run(host="0.0.0.0", port=5001, ssl_context=ssl_context)
