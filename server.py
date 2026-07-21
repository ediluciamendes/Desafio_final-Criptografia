"""
server.py
Servidor de chat seguro.

Responsabilidades do servidor (ele NUNCA vê texto claro nem chaves
privadas):
1. Autenticar usuários (login/cadastro) comparando hashes de senha.
2. Receber a chave pública RSA de cada cliente conectado e distribuí-la
   aos demais clientes (troca de chaves).
3. Rotear mensagens cifradas (AES) e a chave AES cifrada (RSA) entre
   remetente e destinatário, sem nunca decifrar nada.
"""

import socket
import threading

import auth
import net_utils

HOST = "0.0.0.0"
PORT = 5555

# username -> {"conn": socket, "pubkey": str_b64}
clients: dict[str, dict] = {}
clients_lock = threading.Lock()


def broadcast_pubkey(new_username: str, new_pubkey_b64: str) -> None:
    """Envia a chave pública do novo usuário a todos os outros já
    conectados, e envia as chaves públicas dos outros ao novo usuário."""
    with clients_lock:
        others = [
            (uname, info) for uname, info in clients.items() if uname != new_username
        ]

    for uname, info in others:
        try:
            net_utils.send_json(
                info["conn"],
                {"type": "peer_pubkey", "username": new_username, "key": new_pubkey_b64},
            )
        except (ConnectionError, OSError):
            continue

        # também informa ao novo usuário sobre esse peer já existente
        with clients_lock:
            my_conn = clients[new_username]["conn"]
        try:
            net_utils.send_json(
                my_conn,
                {"type": "peer_pubkey", "username": uname, "key": info["pubkey"]},
            )
        except (ConnectionError, OSError):
            continue


def handle_auth(conn) -> str | None:
    """Executa o fluxo de cadastro/login. Retorna o username autenticado
    ou None se a conexão falhar/for encerrada."""
    while True:
        try:
            req = net_utils.recv_json(conn)
        except (ConnectionError, OSError):
            return None

        action = req.get("action")
        username = req.get("username", "")
        password = req.get("password", "")

        if action == "register":
            ok, msg = auth.register(username, password)
        elif action == "login":
            ok, msg = auth.login(username, password)
            if ok:
                with clients_lock:
                    if username in clients:
                        ok, msg = False, "Usuário já está conectado em outra sessão."
        else:
            ok, msg = False, "Ação inválida."

        net_utils.send_json(conn, {"type": "auth_result", "success": ok, "message": msg})

        if ok and action == "login":
            return username
        # se for apenas "register" bem-sucedido, o cliente ainda precisa logar
        # o loop continua esperando a próxima ação (ex.: login)


def handle_client(conn, addr) -> None:
    print(f"[+] Nova conexão de {addr}")
    username = None
    try:
        username = handle_auth(conn)
        if username is None:
            return

        # Recebe a chave pública RSA do cliente recém-autenticado
        pubkey_msg = net_utils.recv_json(conn)
        if pubkey_msg.get("type") != "pubkey":
            print(f"[!] Esperava chave pública de {username}, encerrando.")
            return
        pubkey_b64 = pubkey_msg["key"]

        with clients_lock:
            clients[username] = {"conn": conn, "pubkey": pubkey_b64}
        print(f"[+] {username} autenticado e chave pública registrada.")

        broadcast_pubkey(username, pubkey_b64)

        # Loop principal: roteamento de mensagens cifradas
        while True:
            msg = net_utils.recv_json(conn)
            if msg.get("type") == "message":
                recipient = msg.get("to")
                with clients_lock:
                    target = clients.get(recipient)
                if target is None:
                    net_utils.send_json(
                        conn,
                        {"type": "error", "message": f"Usuário '{recipient}' não está conectado."},
                    )
                    continue
                # Servidor apenas repassa o payload cifrado, sem decifrar nada
                forward = dict(msg)
                forward["from"] = username
                net_utils.send_json(target["conn"], forward)

    except (ConnectionError, OSError):
        pass
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
        conn.close()
        print(f"[-] Conexão encerrada: {addr} ({username})")


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    print(f"[*] Servidor de chat seguro escutando em {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Encerrando servidor.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()