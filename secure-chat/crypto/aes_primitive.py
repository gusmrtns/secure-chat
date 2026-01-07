from Crypto.Cipher import AES


BLOCK_SIZE = 16  # Tamanho fixo de bloco do AES em bytes (128 bits)


def new_aes_ecb(key: bytes):
    """Cria e retorna um objeto AES em modo ECB para a chave informada.
    A chave deve ter um tamanho válido para AES: 16, 24 ou 32 bytes.
    """
    return AES.new(key, AES.MODE_ECB)


def encrypt_block(aes_ecb, block: bytes) -> bytes:
    """Criptografa exatamente um bloco de 16 bytes e retorna o ciphertext (16 bytes).
    Lança erro se o tamanho do bloco for diferente de BLOCK_SIZE.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Block must be {BLOCK_SIZE} bytes")
    return aes_ecb.encrypt(block)


def decrypt_block(aes_ecb, block: bytes) -> bytes:
    """Descriptografa exatamente um bloco de 16 bytes e retorna o plaintext (16 bytes).
    Lança erro se o tamanho do bloco for diferente de BLOCK_SIZE.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Block must be {BLOCK_SIZE} bytes")
    return aes_ecb.decrypt(block)
