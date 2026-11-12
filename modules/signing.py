"""Ed25519 key generation, signing and verification for audit-log entries."""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key,
)

PRIVATE_KEY_FILE = "chainproof_private.pem"
PUBLIC_KEY_FILE = "chainproof_public.pem"


def generate_keypair(case_dir, key_dir=None):
    """Generate a fresh Ed25519 keypair and persist it under key_dir.

    Returns (private_key, public_key, key_dir_path).
    """
    target = Path(key_dir) if key_dir else Path(case_dir) / "keys"
    target.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    priv_pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    (target / PRIVATE_KEY_FILE).write_bytes(priv_pem)
    (target / PUBLIC_KEY_FILE).write_bytes(pub_pem)
    return private, public, target


def load_private_key(case_dir, key_dir=None):
    target = Path(key_dir) if key_dir else Path(case_dir) / "keys"
    path = target / PRIVATE_KEY_FILE
    return load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(case_dir, key_dir=None):
    target = Path(key_dir) if key_dir else Path(case_dir) / "keys"
    path = target / PUBLIC_KEY_FILE
    return load_pem_public_key(path.read_bytes())


def sign_data(private_key, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
