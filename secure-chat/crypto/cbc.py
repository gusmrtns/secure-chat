from . import aes_primitive
from . import padding


BLOCK_SIZE = 16  # Tamanho de bloco do AES em bytes (128 bits)


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Criptografa o plaintext usando AES-CBC
    Retorna o ciphertext em bytes
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")

    # Cria um cifrador AES em modo ECB, usado como primitive para montar o CBC
    aes = aes_primitive.new_aes_ecb(key)

    # Aplica padding PKCS#7 para que o plaintext seja múltiplo de 16 bytes
    padded = padding.pkcs7_pad(plaintext)

    ciphertext = b""
    # Para o primeiro bloco, o "previous" é o IV; depois passa a ser o último ciphertext
    previous = iv

    # Processa o texto em blocos de 16 bytes
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]

        # Faz XOR do bloco atual com o bloco anterior (ou IV no primeiro bloco)
        xored = bytes(a ^ b for a, b in zip(block, previous))

        # Criptografa o resultado do XOR com AES-ECB
        encrypted = aes_primitive.encrypt_block(aes, xored)

        # Acrescenta o bloco cifrado ao ciphertext final
        ciphertext += encrypted
        # Atualiza o "previous" com o último bloco cifrado gerado
        previous = encrypted

    return ciphertext


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # Descriptografa o ciphertext usando AES-CBC .

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be multiple of 16 bytes")

    # usa AES-ECB como primitive para o modo CBC
    aes = aes_primitive.new_aes_ecb(key)
    plaintext = b""
    previous = iv

    # Processa o ciphertext em blocos de 16 bytes
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]

        # Primeiro decifra o bloco
        decrypted = aes_primitive.decrypt_block(aes, block)
        # Depois faz XOR com o bloco anterior (ou IV para o primeiro)
        xored = bytes(a ^ b for a, b in zip(decrypted, previous))

        # Concatena o resultado ao plaintext bruto (ainda com padding)
        plaintext += xored
        # Atualiza o "previous" com o bloco de ciphertext atual
        previous = block

    # Remove o padding PKCS#7 e devolve o plaintext original
    return padding.pkcs7_unpad(plaintext)
