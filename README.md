# Sistema de Comunicação Segura com RSA e AES

Este repositório contém a implementação de um **chat** ponto-a-ponto seguro utilizando sockets TCP, criptografia assimétrica (RSA-OAEP) para troca de chaves e criptografia simétrica (AES-256) nos modos CBC e CTR para proteger as mensagens de sessão.[1][2]

## Arquitetura do sistema

- Servidor TCP simples, atuando como roteador de mensagens (store-and-forward), sem acesso ao plaintext.[1]
- Clientes em linha de comando (CLI), responsáveis por:
  - Geração de chave RSA 2048 bits localmente.
  - Troca de chaves públicas via servidor.
  - Geração de chaves de sessão AES-256.
  - Derivação de chave final compartilhada a partir de contribuições de ambos os clientes.
  - Criptografia e descriptografia das mensagens com AES em modo CBC ou CTR.[1]

## Criptografia e troca de chaves

- RSA-OAEP (2048 bits) para cifrar as chaves de sessão simétricas trocadas entre os clientes.[1]
- Cada cliente gera uma chave AES-256 aleatória local, cifra com a chave pública do par e envia.[1]
- Após receber e decifrar a chave do par, a chave de sessão final é derivada via XOR entre as duas chaves AES locais, garantindo que nenhum cliente controle sozinho a chave final e que o servidor não conheça nenhum segredo.[1]
- Biblioteca utilizada: **PyCryptodome** para primitivas de bloco AES e RSA; a lógica dos modos CBC e CTR é implementada manualmente conforme exigido na proposta do professor.[2][1]

## Modos AES implementados

- **AES-CBC**

  - Utiliza IV aleatório de 16 bytes por sessão/mensagem.
  - Requer padding (PKCS7).
  - Cada bloco depende do bloco anterior, evitando padrões diretos do plaintext.[2][1]

- **AES-CTR**
  - Funciona como “stream cipher” usando nonce + contador.
  - Não requer padding.
  - Focado em desempenho e paralelismo, com nonce único por mensagem.[2][1]

## Estrutura do projeto

- `server/`
  - `server.py`: servidor TCP responsável por receber e encaminhar mensagens e chaves públicas entre clientes.[1]
- `client/`
  - `client.py`: cliente de chat seguro em CLI (envio/recebimento de mensagens, troca de chaves, criptografia AES).[1]
- `crypto/`
  - `cbc.py`: implementação manual do modo CBC usando AES básico.
  - `ctr.py`: implementação manual do modo CTR.
  - `keyexchange.py`: geração de chaves RSA, uso de OAEP e derivação da chave final via XOR.[1]
  - `aes_primitive.py`: responsável por criar o cifrador e oferecer funções para criptografar e descriptografar exatamente um bloco de 16 bytes, servindo de base para as implementações manuais dos modos CBC e CTR.
  - `padding.py`: aplica padding necessário no processo de criptografia.

## Como executar

1. Instalar dependências:

```bash
pip install pycryptodome
```

2. Iniciar o servidor (exemplo):

```bash
cd server
python server.py
```

3. Iniciar clientes (exemplo: Alice e Bob, modo CBC):

```bash
# terminal 1 (Alice)
python -m client.client --user alice --peer bob --mode cbc

# terminal 2 (Bob)
python -m client.client --user bob --peer alice --mode cbc
```

Parâmetros principais do cliente:[1]

- `--user`: identificador local do usuário.
- `--peer`: destinatário esperado.
- `--mode`: `cbc` ou `ctr`.
- `--debug` (opcional): ativa modo de depuração para mostrar chaves locais, IV/nonce e ciphertext no terminal local, útil para fins didáticos e auditoria.[1]
