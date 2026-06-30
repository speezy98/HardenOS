"""PKI interne HardenOS — émission de certificats TLS et signature de scripts.

Deux usages distincts de cryptographie asymétrique, avec des clés séparées :
  1. La CA (AGENT_CA_CERT / AGENT_CA_KEY, cf. .env.example) signe des
     certificats TLS : le certificat serveur du backend lui-même (une fois,
     via `flask issue-backend-cert`) et les certificats des agents Windows
     (CSR fourni par l'agent, SAN forcé à l'IP réelle du système enregistré).
     TLS ici = chiffrement du transport uniquement, pas d'authentification
     applicative (qui reste portée par les tokens existants) : pas de mTLS.
  2. Une clé Ed25519 dédiée (SCRIPT_SIGNING_KEY_PATH, générée une fois via
     `flask issue-signing-key`) signe les scripts de remédiation envoyés aux
     agents, vérifiés côté agent avant toute exécution. Volontairement
     séparée de la CA TLS : une compromission de l'une n'affecte pas l'autre.
"""
import base64
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class PkiError(Exception):
    """Erreur de configuration ou d'opération PKI (CA absente, CSR invalide, ...)."""


def load_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Charge le certificat et la clé privée de la CA depuis AGENT_CA_CERT/AGENT_CA_KEY."""
    cert_path = os.environ.get("AGENT_CA_CERT")
    key_path = os.environ.get("AGENT_CA_KEY")
    if not cert_path or not key_path:
        raise PkiError("AGENT_CA_CERT / AGENT_CA_KEY non configurés dans l'environnement.")
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        raise PkiError(f"Fichiers CA introuvables : {cert_path} / {key_path}")

    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    return ca_cert, ca_key


def _build_san(sans: list[str]) -> x509.SubjectAlternativeName:
    """Construit une SAN à partir d'IP et/ou de noms DNS (détection automatique du type)."""
    entries = []
    for value in sans:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            entries.append(x509.DNSName(value))
    return x509.SubjectAlternativeName(entries)


def _leaf_extensions(sans: list[str], public_key, ca_cert: x509.Certificate) -> list[tuple[x509.ExtensionType, bool]]:
    """Extensions communes à tous les certificats feuille émis par cette CA.

    SubjectKeyIdentifier / AuthorityKeyIdentifier sont nécessaires pour que la
    construction de chaîne stricte d'OpenSSL/Python (ssl.SSLContext) accepte
    le certificat — `openssl verify` est plus permissif et ne les exige pas,
    ce qui peut masquer leur absence en test manuel.
    """
    return [
        (_build_san(sans), False),
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            True,
        ),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), False),
    ]


def issue_server_cert(common_name: str, sans: list[str], days: int = 825) -> tuple[bytes, bytes]:
    """Génère une paire clé privée + certificat, signée directement par la CA.

    Utilisé pour le certificat serveur du backend lui-même (identité unique,
    générée une fois via `flask issue-backend-cert`). Retourne (cert_pem, key_pem).
    """
    ca_cert, ca_key = load_ca()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    for ext, critical in _leaf_extensions(sans, key.public_key(), ca_cert):
        builder = builder.add_extension(ext, critical=critical)
    cert = builder.sign(ca_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def agent_base_url(ip_address: str) -> tuple[str, str | bool]:
    """URL de base + valeur `verify` pour joindre un agent (backend -> agent, port 8585).

    Bascule automatiquement en HTTPS (vérifié via AGENT_CA_CERT) si la CA est
    configurée et présente sur disque ; sinon reste en HTTP (comportement
    précédent, pour ne pas casser les déploiements sans certificats).
    """
    ca_path = os.environ.get("AGENT_CA_CERT")
    if ca_path and os.path.isfile(ca_path):
        return f"https://{ip_address}:8585", ca_path
    return f"http://{ip_address}:8585", True


def sign_csr(csr_pem: bytes, sans: list[str], days: int = 825) -> bytes:
    """Signe un CSR reçu d'un agent avec la CA locale.

    Les SAN sont imposés par le backend (IP réelle du système enregistré en
    base), jamais ceux demandés dans le CSR, pour empêcher un agent de
    s'auto-attribuer une autre identité. Retourne le certificat signé (PEM).
    """
    ca_cert, ca_key = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise PkiError("CSR invalide (signature incorrecte).")

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    for ext, critical in _leaf_extensions(sans, csr.public_key(), ca_cert):
        builder = builder.add_extension(ext, critical=critical)
    cert = builder.sign(ca_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Signature des scripts de remédiation (Ed25519, clé dédiée)
# ---------------------------------------------------------------------------

def generate_signing_key() -> bytes:
    """Génère une nouvelle paire Ed25519 dédiée à la signature de scripts.

    Retourne la clé privée au format PEM (PKCS8, non chiffrée). Ne réutilise
    jamais la CA TLS pour cet usage : les deux clés ont des rôles différents.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_signing_key() -> ed25519.Ed25519PrivateKey:
    key_path = os.environ.get("SCRIPT_SIGNING_KEY_PATH")
    if not key_path or not os.path.isfile(key_path):
        raise PkiError("SCRIPT_SIGNING_KEY_PATH non configuré ou fichier introuvable.")
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def get_signing_public_key_pem() -> str:
    """Clé publique de signature des scripts, à distribuer aux agents."""
    key = _load_signing_key()
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def sign_script(script: str) -> str:
    """Signe un script de remédiation (Ed25519) ; retourne la signature en base64."""
    key = _load_signing_key()
    signature = key.sign(script.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")
