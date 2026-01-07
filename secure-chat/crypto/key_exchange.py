from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Gerar um par de chaves RSA (pública + privada)


def generate_rsa_keypair(bits: int = 2048):
    """
    Gera um par de chaves RSA (privada + pública).
    Retorna (private_key_pem, public_key_pem)
    """
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem


# Criptografar a chave AES com a chave pública do destinatário

def encrypt_session_key(session_key: bytes, peer_public_key_pem: bytes) -> bytes:
    """
    Recebe:
        - session_key: bytes (ex: 16 ou 32 bytes)
        - peer_public_key_pem: chave pública RSA em PEM
    Retorna:
        - session_key cifrada com RSA-OAEP
    """
    public_key = RSA.import_key(peer_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(session_key)
    return encrypted


# Descriptografar a chave AES usando a chave privada local

def decrypt_session_key(encrypted_session_key: bytes, private_key_pem: bytes) -> bytes:
    """
    Recebe:
        - encrypted_session_key: chave da sessão cifrada com RSA
        - private_key_pem: chave privada RSA em PEM
    Retorna:
        - session_key original (bytes)
    """
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    return session_key


# gerar chave AES aleatória

def generate_aes_session_key(size: int = 32) -> bytes:
    """
    Gera uma chave AES aleatória.
    Tamanho padrão: 32 bytes = AES-256.
    Pode usar 16 para AES-128
    """
    return get_random_bytes(size)
