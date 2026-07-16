"""Quantum-resistant crypto interface with a classical hybrid fallback.

True post-quantum KEMs (Kyber et al.) require liboqs, which is an
optional extra. This module provides the framework's crypto surface
using the ``cryptography`` package: X25519 key agreement + HKDF +
AES-256-GCM. The interface is shaped so a liboqs-backed implementation
can drop in behind the same methods.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUPPORTED_ALGORITHMS = ("lattice", "hybrid-x25519")


class QuantumResistantCrypto:
    """Key agreement + authenticated encryption for node communication.

    ``algorithm`` selects the intended scheme; both currently map to the
    classical hybrid implementation, with the name recorded so peers can
    negotiate an upgrade when a PQC backend is available.
    """

    def __init__(self, algorithm: str = "lattice"):
        self.algorithm = algorithm if algorithm in SUPPORTED_ALGORITHMS else "lattice"
        self._private_key = X25519PrivateKey.generate()
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def derive_shared_key(self, peer_public_key: bytes) -> bytes:
        """Derive a 32-byte shared key from a peer's raw public key."""
        peer = X25519PublicKey.from_public_bytes(peer_public_key)
        secret = self._private_key.exchange(peer)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sentinel-v-node-channel",
        ).derive(secret)

    def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt with AES-256-GCM; returns (nonce, ciphertext)."""
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt AES-256-GCM output; raises on tampering."""
        return AESGCM(key).decrypt(nonce, ciphertext, None)
