"""AES-256-GCM encryption and HMAC-SHA256 integrity (encrypt-then-MAC).

All cryptography comes from the `cryptography` library and Python's standard
`hmac` module. Nothing is implemented by hand.

A secure message ("envelope") looks like this:
    device_id, timestamp, nonce, token   <- header (readable, but MAC-protected)
    ciphertext                           <- AES-GCM encrypted JSON payload
    mac                                  <- HMAC-SHA256 over header + ciphertext
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32      # 256-bit keys
NONCE_SIZE = 12    # recommended GCM nonce size
TAG_SIZE = 16      # GCM authentication tag

HEADER_FIELDS = ("device_id", "timestamp", "nonce", "token")


class IntegrityError(Exception):
    """Raised when a message fails HMAC verification or cannot be decrypted."""


def generate_key() -> bytes:
    """Return a fresh random 256-bit key from the OS secure random source."""
    return os.urandom(KEY_SIZE)


# --------------------------------------------------------------------------
# AES-256-GCM
# --------------------------------------------------------------------------
def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce || ciphertext || tag."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypt data produced by `encrypt`. Raises IntegrityError on failure."""
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise IntegrityError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except InvalidTag:
        raise IntegrityError("decryption failed (wrong key or modified data)")


# --------------------------------------------------------------------------
# HMAC-SHA256
# --------------------------------------------------------------------------
def compute_hmac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, data: bytes, tag: str) -> bool:
    """Constant-time comparison of the expected and received tag."""
    return hmac.compare_digest(compute_hmac(key, data), str(tag))


# --------------------------------------------------------------------------
# Envelopes (encrypt-then-MAC)
# --------------------------------------------------------------------------
def is_envelope(packet: Any) -> bool:
    return isinstance(packet, dict) and "ciphertext" in packet and "mac" in packet


def _header_bytes(envelope: Dict[str, Any]) -> bytes:
    header = {name: envelope[name] for name in HEADER_FIELDS}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _mac_input(envelope: Dict[str, Any]) -> bytes:
    return _header_bytes(envelope) + b"." + envelope["ciphertext"].encode()


def seal_message(enc_key: bytes, mac_key: bytes, device_id: str,
                 payload: Dict[str, Any], token: Optional[str],
                 timestamp: Optional[float] = None,
                 nonce: Optional[str] = None) -> Dict[str, Any]:
    """Encrypt `payload` and protect header + ciphertext with an HMAC."""
    envelope = {
        "device_id": device_id,
        "timestamp": time.time() if timestamp is None else timestamp,
        "nonce": nonce or os.urandom(12).hex(),
        "token": token or "",
    }
    aad = _header_bytes(envelope)  # binds the header to the ciphertext
    blob = encrypt(enc_key, json.dumps(payload).encode(), aad)
    envelope["ciphertext"] = base64.b64encode(blob).decode()
    envelope["mac"] = compute_hmac(mac_key, _mac_input(envelope))
    return envelope


def verify_envelope(mac_key: bytes, envelope: Dict[str, Any]) -> bool:
    """True only if the HMAC matches. Never raises on malformed input."""
    try:
        return verify_hmac(mac_key, _mac_input(envelope), envelope["mac"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def decrypt_envelope(enc_key: bytes, envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt the payload of an envelope (call verify_envelope first)."""
    try:
        blob = base64.b64decode(envelope["ciphertext"], validate=True)
        plaintext = decrypt(enc_key, blob, _header_bytes(envelope))
        payload = json.loads(plaintext.decode())
    except IntegrityError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise IntegrityError("malformed envelope")
    if not isinstance(payload, dict):
        raise IntegrityError("payload is not a JSON object")
    return payload


def open_message(enc_key: bytes, mac_key: bytes,
                 envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the HMAC, then decrypt. Raises IntegrityError if either fails."""
    if not verify_envelope(mac_key, envelope):
        raise IntegrityError("HMAC verification failed")
    return decrypt_envelope(enc_key, envelope)
