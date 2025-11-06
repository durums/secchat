# crypto_helpers.py
"""Kryptographische Hilfsfunktionen:
- X25519 Keypair
- HKDF -> AES-256 key
- AES-GCM encrypt/decrypt
- known_hosts (TOFU) helper
"""
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import secrets


KNOWN_HOSTS_PATH = Path.home() / '.ws_messenger_known_hosts'


# --- Key helpers ---
def generate_x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


from cryptography.hazmat.primitives import serialization

def pubkey_to_b64(pubkey):
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("utf8")



def b64_to_pubkey(b64data: str) -> x25519.X25519PublicKey:
    raw = base64.b64decode(b64data)
    return x25519.X25519PublicKey.from_public_bytes(raw)


def derive_aes_key(our_priv: x25519.X25519PrivateKey, their_pub: x25519.X25519PublicKey, info: bytes = b"ws-chat") -> bytes:
    shared = our_priv.exchange(their_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared)


# --- AES-GCM ---
def encrypt_message(aes_key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct


def decrypt_message(aes_key: bytes, data: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    if len(data) < 12:
        raise ValueError('Payload too short for nonce')
    nonce = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(nonce, ct, associated_data=None)


# --- known_hosts (TOFU) ---
def load_known_hosts() -> dict:
    hosts = {}
    try:
        with open(KNOWN_HOSTS_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(' ')
                if len(parts) >= 2:
                    hosts[parts[0]] = parts[1]
    except FileNotFoundError:
        pass
    return hosts


def save_known_host(host: str, pub_b64: str):
    KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(KNOWN_HOSTS_PATH, 'a') as f:
        f.write(f"{host} {pub_b64}\n")


def check_known_host(host: str, pub_b64: str) -> bool:
    hosts = load_known_hosts()
    if host in hosts:
        return hosts[host] == pub_b64
    return False