BLOCK_SIZE = 16


def pkcs7_pad(data: bytes) -> bytes:
    """Aplica padding PKCS#7 para que o tamanho seja múltiplo de BLOCK_SIZE."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    # Se já for múltiplo exato do bloco, adiciona um bloco inteiro de padding
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    # Cada byte de padding carrega o valor pad_len, repetido pad_len vezes
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes) -> bytes:
    """Remove o padding PKCS#7. Lança ValueError se o padding for inválido."""
    # Tamanho tem que ser positivo e múltiplo exato de BLOCK_SIZE
    if len(padded) == 0 or len(padded) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")
    pad_len = padded[-1]
    # Valor do último byte define o tamanho do padding; precisa estar no intervalo válido
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    # Verifica se todos os últimos pad_len bytes batem com o valor pad_len
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    # Retorna apenas os dados originais, sem o padding
    return padded[:-pad_len]
