"""liboqs-backed post-quantum KEM (optional ``quantum`` extra).

Requires the ``oqs`` bindings. For the dependency-light hybrid used by
the core system, see ``sentinel_v.crypto.QuantumResistantCrypto``.
"""

from typing import Any, Tuple

import oqs


class QuantumCrypto:
    """Key encapsulation using a real PQC algorithm (default Kyber512)."""

    def __init__(self, kem_alg: str = "Kyber512"):
        self.kem = oqs.KeyEncapsulation(kem_alg)

    def generate_keypair(self) -> Tuple[Any, Any]:
        """Return (public_key, secret_key)."""
        public_key = self.kem.generate_keypair()
        return public_key, self.kem.export_secret_key()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        """Return (ciphertext, shared_secret) for a peer's public key."""
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: Any) -> Any:
        """Recover the shared secret from a ciphertext."""
        return self.kem.decap_secret(ciphertext)


if __name__ == "__main__":
    crypto = QuantumCrypto()
    pub_key, sec_key = crypto.generate_keypair()
    cipher, shared_enc = crypto.encapsulate(pub_key)
    shared_dec = crypto.decapsulate(cipher)
    print(shared_enc == shared_dec)  # True
