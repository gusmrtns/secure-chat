from Crypto.Random import get_random_bytes
from . import aes_primitive


BLOCK_SIZE = 16  # Tamanho de bloco do AES em bytes (128 bits)


def _inc_counter_block(counter_block: bytes) -> bytes:
    """Incrementa os últimos 8 bytes de um bloco de contador de 16 bytes
    Mantém os 8 primeiros bytes como prefixo (nonce) fixo.
    """
    if len(counter_block) != BLOCK_SIZE:
        raise ValueError("counter_block must be 16 bytes")
    prefix = counter_block[:8]
    counter_bytes = counter_block[8:]
    counter = int.from_bytes(counter_bytes, 'big')
    counter = (counter + 1) & ((1 << 64) - 1)
    return prefix + counter.to_bytes(8, 'big')


def ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Criptografa o plaintext usando AES em modo CTR
    - key: chave AES (16, 24 ou 32 bytes)
    - nonce: bloco inicial de 16 bytes (nonce/counter)
      tipicamente: 8 bytes de nonce fixo || 8 bytes de contador inicial
    - plaintext: dados em bytes
    Retorna: ciphertext em bytes, com o mesmo tamanho do plaintext.
    """
    if len(nonce) != BLOCK_SIZE:
        raise ValueError(
            "Nonce must be 16 bytes (e.g., 8-byte nonce || 8-byte counter)"
        )

    # Usa AES-ECB como primitive para gerar o keystream a partir do contador
    aes = aes_primitive.new_aes_ecb(key)
    counter_block = nonce
    ciphertext = bytearray()

    # Processa em blocos de BLOCK_SIZE bytes; o último bloco pode ser parcial
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]

        # Bloco de keystream = AES_encrypt(counter_block)
        keystream = aes_primitive.encrypt_block(aes, counter_block)

        # Faz XOR do bloco de plaintext com o keystream (apenas no tamanho do bloco atual)
        xored = bytes(b ^ k for b, k in zip(block, keystream[:len(block)]))
        ciphertext.extend(xored)

        # Incrementa o bloco de contador para a próxima iteração
        counter_block = _inc_counter_block(counter_block)

    return bytes(ciphertext)


# Em CTR, criptografia e descriptografia são a mesma operação (XOR com o mesmo keystream)
ctr_decrypt = ctr_encrypt


# gera um nonce de 16 bytes (8 bytes aleatórios + 8 bytes de contador iniciando em 0)
def generate_nonce() -> bytes:
    prefix = get_random_bytes(8)
    counter0 = (0).to_bytes(8, 'big')
    return prefix + counter0
