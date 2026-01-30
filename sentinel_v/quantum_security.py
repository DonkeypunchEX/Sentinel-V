import oqs

class QuantumCrypto:
    def __init__(self, kem_alg="Kyber512"):
        self.kem = oqs.KeyEncapsulation(kem_alg)
    
    def generate_keypair(self):
        public_key = self.kem.generate_keypair()
        return public_key, self.kem.export_secret_key()
    
    def encapsulate(self, public_key):
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext):
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret

# Example
if __name__ == "__main__":
    crypto = QuantumCrypto()
    pub_key, sec_key = crypto.generate_keypair()
    cipher, shared_enc = crypto.encapsulate(pub_key)
    shared_dec = crypto.decapsulate(cipher)
    print(shared_enc == shared_dec)  # True
