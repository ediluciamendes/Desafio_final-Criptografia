"""
client.py
Cliente de chat seguro em linha de comando.

Fluxo:
1. Conecta ao servidor e faz login/cadastro (senha nunca trafega "crua"
   sem TLS em produção real — aqui, para fins didáticos do capítulo,
   o servidor apenas recebe a senha para gerar o hash comparativo;
   o ponto central do exercício é a cifragem das MENSAGENS).
2. Gera um par de chaves RSA-2048 para a sessão.
3. Envia a chave pública ao servidor, que a distribui aos demais.
4. Para cada mensagem: gera uma chave AES aleatória, cifra a mensagem,
   cifra a chave AES com a chave pública RSA do destinatário e envia
   tudo ao servidor, que apenas roteia.
5. Ao receber, decifra a chave AES com sua chave privada e depois a
   mensagem com AES.

Comandos no chat:
  @usuario mensagem   -> envia para um destinatário específico
  mensagem            -> envia para o único peer conhecido (se houver 1)
  /peers               -> lista peers com chave pública já trocada
  /quit                -> encerra o cliente
"""

import socket
import sys
import threading

import crypto_utils
import net_utils

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555


class ChatClient:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username = None
        self.private_key = None
        self.public_key = None
        self.peers = {}  # username -> chave pública RSA (objeto)
        self.peers_lock = threading.Lock()

    # -- Autenticação -------------------------------------------------

    def authenticate(self):
        while True:
            action = input("Digite 'login' ou 'registrar': ").strip().lower()
            if action not in ("login", "registrar"):
                print("Opção inválida.")
                continue

            username = input("Usuário: ").strip()
            password = input("Senha: ").strip()

            net_utils.send_json(
                self.sock,
                {
                    "action": "register" if action == "registrar" else "login",
                    "username": username,
                    "password": password,
                },
            )
            resp = net_utils.recv_json(self.sock)
            print(f"[servidor] {resp['message']}")

            if resp["success"] and action == "login":
                self.username = username
                return
            # se cadastro deu certo, volta ao início para fazer login
            # se falhou (login ou registro), tenta novamente

    # -- Chaves RSA -----------------------------------------------------

    def setup_keys(self):
        self.private_key, self.public_key = crypto_utils.generate_rsa_keypair()
        pubkey_b64 = crypto_utils.serialize_public_key(self.public_key)
        net_utils.send_json(self.sock, {"type": "pubkey", "key": pubkey_b64})
        print("[*] Par de chaves RSA-2048 gerado e chave pública enviada ao servidor.")

    # -- Recebimento (thread) -------------------------------------------

    def listen_loop(self):
        while True:
            try:
                msg = net_utils.recv_json(self.sock)
            except (ConnectionError, OSError):
                print("\n[!] Conexão com o servidor encerrada.")
                sys.exit(0)

            mtype = msg.get("type")

            if mtype == "peer_pubkey":
                uname = msg["username"]
                pubkey = crypto_utils.deserialize_public_key(msg["key"])
                with self.peers_lock:
                    self.peers[uname] = pubkey
                print(f"\n[*] Chave pública de '{uname}' recebida. Canal seguro pronto.")

            elif mtype == "message":
                sender = msg.get("from")
                try:
                    plaintext = crypto_utils.decrypt_message(msg, self.private_key)
                    print(f"\n[{sender}] {plaintext}")
                except Exception as e:
                    print(f"\n[!] Falha ao decifrar mensagem de {sender}: {e}")

            elif mtype == "error":
                print(f"\n[servidor] {msg.get('message')}")

            print("> ", end="", flush=True)

    # -- Envio ------------------------------------------------------------

    def send_message(self, recipient: str, text: str):
        with self.peers_lock:
            pubkey = self.peers.get(recipient)
        if pubkey is None:
            print(f"[!] Ainda não tenho a chave pública de '{recipient}'.")
            return

        payload = crypto_utils.encrypt_message(text, pubkey)
        payload["type"] = "message"
        payload["to"] = recipient
        net_utils.send_json(self.sock, payload)

    def input_loop(self):
        print("Comandos: '@usuario mensagem' | 'mensagem' (se só houver 1 peer) | '/peers' | '/quit'")
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                continue
            if line == "/quit":
                break
            if line == "/peers":
                with self.peers_lock:
                    names = list(self.peers.keys())
                print(f"[*] Peers conhecidos: {names if names else 'nenhum ainda'}")
                continue

            if line.startswith("@"):
                try:
                    target, text = line[1:].split(" ", 1)
                except ValueError:
                    print("[!] Formato: @usuario mensagem")
                    continue
                self.send_message(target, text)
            else:
                with self.peers_lock:
                    names = list(self.peers.keys())
                if len(names) == 1:
                    self.send_message(names[0], line)
                elif len(names) == 0:
                    print("[!] Nenhum peer conectado ainda. Aguarde alguém entrar.")
                else:
                    print(f"[!] Vários peers conhecidos {names}. Use '@usuario mensagem'.")

        self.sock.close()
        print("[*] Encerrado.")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT

    client = ChatClient(host, port)
    client.authenticate()
    client.setup_keys()

    t = threading.Thread(target=client.listen_loop, daemon=True)
    t.start()

    client.input_loop()


if __name__ == "__main__":
    main()