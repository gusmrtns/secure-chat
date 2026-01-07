import socket
import threading
import json
import argparse
import base64
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from crypto import cbc
from crypto import ctr
from crypto import key_exchange


def send_json(sock, data: dict):
    # Envia um dicionário como JSON codificado em UTF-8 pelo socket
    sock.send(json.dumps(data).encode("utf-8"))


def recv_json(sock):
    # Recebe dados do socket e tenta decodificar como JSON
    try:
        data = sock.recv(4096)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))
    except:
        return None


def dbg(print_debug, label, value):
    if print_debug:
        print(f"[DEBUG][{label:<12}] {value}")


# Thread de recepção de mensagens

def receiver_thread(sock, mode, aes_key, username, debug_enabled):
    # Fica escutando mensagens do servidor em loop infinito
    while True:
        msg = recv_json(sock)
        if msg is None:
            print("[!] Desconectado do servidor.")
            sys.exit(0)

        # Ignora mensagens que não sejam do tipo "chat"
        if msg.get("type") != "chat":
            continue

        ciphertext_b64 = msg.get("ciphertext")
        iv_b64 = msg.get("iv")
        cipher_mode = msg.get("mode")
        sender = msg.get("from")

        # Garante que o modo de cifragem recebido é o mesmo em uso local
        if cipher_mode != mode:
            print("[AVISO] Mensagem ignorada: modo inválido recebido.")
            continue

        # Decodifica IV e ciphertext de base64 para bytes
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        dbg(debug_enabled, "IV", iv.hex())
        dbg(debug_enabled, "CIPHERTEXT", ciphertext_b64)

        # Decifra a mensagem conforme o modo de operação escolhido
        if mode == "cbc":
            plaintext = cbc.cbc_decrypt(aes_key, iv, ciphertext)
        else:
            plaintext = ctr.ctr_decrypt(aes_key, iv, ciphertext)

        dbg(debug_enabled, "PLAINTEXT", plaintext.decode("utf-8"))

        # Exibe a mensagem recebida formatada no console
        print(f"\n[{sender}] {plaintext.decode('utf-8')}")
        print("> ", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Cliente de Chat Seguro")
    parser.add_argument("--user", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--mode", required=True, choices=["cbc", "ctr"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=9000, type=int)
    parser.add_argument("--debug", action="store_true",
                        help="Ativa o modo DEBUG para exibir detalhes da execução")

    args = parser.parse_args()

    username = args.user
    peer = args.peer
    mode = args.mode
    debug_enabled = args.debug

    print(
        f"[+] Iniciando cliente como '{username}', destino = '{peer}', modo = {mode.upper()}")

    # Conexão ao servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print("[+] Conectado ao servidor.")

    # Envio de mensagem inicial

    send_json(sock, {"type": "init", "username": username})

    # Geração do par de chaves RSA

    private_pem, public_pem = key_exchange.generate_rsa_keypair()
    print("[+] Par de chaves RSA gerado com sucesso.")

    # Envio da chave pública ao peer

    send_json(sock, {
        "type": "pubkey",
        "from": username,
        "to": peer,
        "pubkey": public_pem.decode("utf-8")
    })
    print("[+] Chave pública enviada. Aguardando chave do peer...")

    # Espera pela chave pública do peer

    peer_pubkey = None
    while True:
        msg = recv_json(sock)
        if msg and msg.get("type") == "pubkey" and msg.get("from") == peer:
            peer_pubkey = msg.get("pubkey").encode("utf-8")
            print("[+] Chave pública do peer recebida.")
            break

    # Geração de uma chave de sessão AES temporária

    aes_key_local = key_exchange.generate_aes_session_key(32)
    dbg(debug_enabled, "AES-LOCAL", aes_key_local.hex())

    print("[+] Chave de sessão AES local criada.")

    # Encriptação e envio da chave AES ao peer

    encrypted_key = key_exchange.encrypt_session_key(
        aes_key_local, peer_pubkey)
    dbg(debug_enabled, "RSA-SEND", base64.b64encode(encrypted_key).decode())

    send_json(sock, {
        "type": "session_key",
        "from": username,
        "to": peer,
        "key": base64.b64encode(encrypted_key).decode()
    })

    print("[+] Chave de sessão criptografada enviada ao peer.")

    # Recebimento da chave criptografada do peer
    print("[+] Aguardando chave de sessão vinda do peer...")

    while True:
        msg = recv_json(sock)
        if msg and msg.get("type") == "session_key" and msg.get("from") == peer:
            enc_key_b64 = msg.get("key")
            dbg(debug_enabled, "RSA-RECV", enc_key_b64)

            peer_enc_key = base64.b64decode(enc_key_b64)
            aes_key_peer = key_exchange.decrypt_session_key(
                peer_enc_key, private_pem)

            dbg(debug_enabled, "AES-PEER", aes_key_peer.hex())

            # Combina as duas chaves AES (local e peer) através de XOR
            aes_key_final = bytes(a ^ b for a, b in zip(
                aes_key_local, aes_key_peer))
            dbg(debug_enabled, "AES-FINAL", aes_key_final.hex())

            print("[+] Chave de sessão compartilhada derivada com sucesso.")
            break

    # Inicia thread para recepção de mensagens
    threading.Thread(
        target=receiver_thread,
        args=(sock, mode, aes_key_final, username, debug_enabled),
        daemon=True
    ).start()

    print("\n[CHAT ATIVO] Digite suas mensagens abaixo:")
    print("> ", end="", flush=True)

    # Loop principal para envio de mensagens
    while True:
        try:
            msg_text = input("> ")
        except EOFError:
            break

        if not msg_text:
            continue

        # Cria IV/nonce e cifra a mensagem conforme o modo
        if mode == "cbc":
            from Crypto.Random import get_random_bytes
            iv = get_random_bytes(16)
            ciph = cbc.cbc_encrypt(aes_key_final, iv, msg_text.encode())
        else:
            iv = ctr.generate_nonce()
            ciph = ctr.ctr_encrypt(aes_key_final, iv, msg_text.encode())

        dbg(debug_enabled, "PLAINTEXT", msg_text)
        dbg(debug_enabled, "IV", iv.hex())
        dbg(debug_enabled, "CIPHERTEXT", base64.b64encode(ciph).decode())

        send_json(sock, {
            "type": "chat",
            "from": username,
            "to": peer,
            "mode": mode,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciph).decode()
        })


if __name__ == "__main__":
    main()
