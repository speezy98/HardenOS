"""Commandes CLI Flask pour HardenOS."""
import os

import click
from flask import Flask

from app.services.auth import AuthError, create_admin


def register_cli(app: Flask) -> None:
    """Enregistre les commandes CLI personnalisées sur l'application."""

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True, help="Email de l'administrateur.")
    @click.password_option(
        "--password",
        prompt="Mot de passe",
        confirmation_prompt=True,
        help="Mot de passe de l'administrateur.",
    )
    def create_admin_command(email: str, password: str) -> None:
        """Crée le premier utilisateur administrateur (rôle admin, status active)."""
        try:
            user = create_admin(email, password)
        except AuthError as exc:
            raise click.ClickException(exc.message)
        click.echo(f"Administrateur créé : {user.email} (id={user.id})")

    @app.cli.command("issue-backend-cert")
    @click.option(
        "--san", "sans", multiple=True, required=True,
        help="IP ou nom DNS par lequel les agents joignent ce backend (répétable, au moins un requis).",
    )
    @click.option("--common-name", default=None, help="CN du certificat (défaut : le premier --san).")
    def issue_backend_cert_command(sans: tuple[str, ...], common_name: str | None) -> None:
        """Émet (une fois) le certificat serveur HTTPS du backend, signé par AGENT_CA_KEY."""
        from app.utils.pki import PkiError, issue_server_cert

        cert_path = os.environ.get("BACKEND_TLS_CERT")
        key_path = os.environ.get("BACKEND_TLS_KEY")
        if not cert_path or not key_path:
            raise click.ClickException(
                "BACKEND_TLS_CERT / BACKEND_TLS_KEY doivent être définis dans .env avant d'émettre le certificat."
            )

        san_list = list(sans)
        cn = common_name or san_list[0]

        try:
            cert_pem, key_pem = issue_server_cert(cn, san_list)
        except PkiError as exc:
            raise click.ClickException(str(exc))

        os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

        click.echo(f"Certificat backend émis : {cert_path} (CN={cn}, SAN={san_list})")

    @app.cli.command("issue-signing-key")
    def issue_signing_key_command() -> None:
        """Émet (une fois) la clé Ed25519 dédiée à la signature des scripts de remédiation."""
        from app.utils.pki import generate_signing_key

        key_path = os.environ.get("SCRIPT_SIGNING_KEY_PATH")
        if not key_path:
            raise click.ClickException("SCRIPT_SIGNING_KEY_PATH doit être défini dans .env avant d'émettre la clé.")

        private_pem = generate_signing_key()
        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(private_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

        click.echo(f"Clé de signature des scripts émise : {key_path}")
        click.echo(
            "La clé publique correspondante est distribuée automatiquement "
            "aux agents via /api/agent/certificate — rien d'autre à faire."
        )
