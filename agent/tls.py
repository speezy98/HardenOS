"""Certificat TLS local de l'agent (clé privée générée sur la machine, CSR,
certificat signé par la CA HardenOS via /api/agent/register).

La clé privée ne quitte jamais la machine : seul le CSR (public) est envoyé
au backend, qui répond avec un certificat signé pour l'IP de cette machine.
"""
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
KEY_PATH = os.path.join(_CERT_DIR, "agent.key")
CERT_PATH = os.path.join(_CERT_DIR, "agent.crt")
CA_PATH = os.path.join(_CERT_DIR, "ca.crt")
SIGNING_PUBKEY_PATH = os.path.join(_CERT_DIR, "script_signing_pub.pem")


def has_certificate() -> bool:
    return os.path.isfile(KEY_PATH) and os.path.isfile(CERT_PATH)


def has_ca_cert() -> bool:
    return os.path.isfile(CA_PATH)


def save_ca_cert(pem: str) -> None:
    """Enregistre le certificat public de la CA, reçu du backend via /setup.

    C'est un fichier public (pas la clé privée de la CA) : aucune contrainte
    de confidentialité, seulement d'intégrité — mais le canal /setup est déjà
    le point de confiance initial de l'agent (il y reçoit aussi son
    agent_token), donc on ne dégrade pas le modèle de confiance existant.
    """
    os.makedirs(_CERT_DIR, exist_ok=True)
    with open(CA_PATH, "w", encoding="utf-8") as f:
        f.write(pem)


def _ensure_key() -> rsa.RSAPrivateKey:
    """Charge la clé privée locale, ou en génère une nouvelle (jamais transmise)."""
    os.makedirs(_CERT_DIR, exist_ok=True)
    if os.path.isfile(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass  # chmod POSIX indisponible sous Windows ; le dossier certs/ reste local à la machine
    return key


def build_csr(common_name: str) -> str:
    """Génère (ou réutilise) la clé locale et construit un CSR PEM pour ce nom."""
    key = _ensure_key()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def save_certificate(cert_pem: str) -> None:
    os.makedirs(_CERT_DIR, exist_ok=True)
    with open(CERT_PATH, "w", encoding="utf-8") as f:
        f.write(cert_pem)


def has_signing_pubkey() -> bool:
    return os.path.isfile(SIGNING_PUBKEY_PATH)


def save_signing_pubkey(pem: str) -> None:
    """Enregistre la clé publique Ed25519 utilisée pour vérifier la
    signature des scripts de remédiation avant exécution (voir remediate.py)."""
    os.makedirs(_CERT_DIR, exist_ok=True)
    with open(SIGNING_PUBKEY_PATH, "w", encoding="utf-8") as f:
        f.write(pem)
