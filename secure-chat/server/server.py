# server.py
# Servidor TCP Relay com suporte a armazenamento de chaves públicas.
# Permite que clientes conectem em qualquer ordem e ainda consigam trocar chaves.

import socket
import threading
import json

HOST = "0.0.0.0"
PORT = 9000

# Armazena conexões: username -> socket
clients = {}

# Armazena chaves públicas: username -> public_key_pem
pubkeys = {}


def forward_message(dest, data):
    """Envia mensagem para o destinatário, se ele existir."""
    if dest in clients:
        try:
            clients[dest].send(data)
            return True
        except:
            print(f"[ERRO] Falha ao enviar mensagem para {dest}")
    return False


def handle_client(conn, addr):
    print(f"[+] Conexão estabelecida com {addr}")

    username = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                msg = json.loads(data.decode("utf-8"))
            except:
                print("[!] Mensagem inválida recebida, ignorando.")
                continue

            msg_type = msg.get("type")

            # Mensagem de INIT -> registra o cliente

            if msg_type == "init":
                username = msg.get("username")
                clients[username] = conn
                print(f"[+] Cliente registrado: {username}")

                # Se já existir chave pública anterior (caso reconexão)
                if username in pubkeys:
                    print(
                        f"[info] Chave pública de {username} já existe no servidor.")
                continue

            # Mensagem de PUBLIC KEY (armazenar e repassar)

            if msg_type == "pubkey":
                sender = msg.get("from")
                dest = msg.get("to")
                pubkey = msg.get("pubkey")

                pubkeys[sender] = pubkey  # armazena

                print(f"[pubkey] Recebida chave pública de {sender}")

                # Se o destinatário já estiver conectado E já tiver enviado sua chave
                if dest in clients and dest in pubkeys:
                    print(
                        f"[relay:pubkey] Enviando chave de {sender} para {dest}")
                    forward_message(dest, data)

                    # Agora enviar a chave pública do dest para o sender
                    print(
                        f"[relay:pubkey] Enviando chave de {dest} para {sender}")
                    send_json = {
                        "type": "pubkey",
                        "from": dest,
                        "to": sender,
                        "pubkey": pubkeys[dest]
                    }
                    clients[sender].send(json.dumps(send_json).encode("utf-8"))

                # Caso contrário, só armazenamos e esperamos o outro entrar
                else:
                    print(f"[info] {dest} ainda não disponível. Chave salva.")
                continue

            # SESSION KEY (repassar)

            if msg_type == "session_key":
                dest = msg.get("to")
                print(f"[relay:session_key] {msg.get('from')} -> {dest}")
                forward_message(dest, data)
                continue

            # CHAT MESSAGE (repassar)

            if msg_type == "chat":
                dest = msg.get("to")
                print(f"[relay:chat] {msg.get('from')} -> {dest}")
                forward_message(dest, data)
                continue

    except Exception as e:
        print("[EXCEÇÃO]", e)

    finally:
        # Limpeza na desconexão
        if username in clients:
            del clients[username]
        print(f"[-] Cliente desconectado: {addr}")
        conn.close()


def start_server():
    print(f"Servidor iniciando em {HOST}:{PORT} ...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print("[OK] Servidor aguardando conexões.\n")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_server()
