"""
net_utils.py
Funções auxiliares para trocar mensagens JSON via socket TCP.

Como o TCP é um fluxo de bytes (sem "fronteiras" de mensagem), cada
mensagem é enviada precedida por 4 bytes indicando seu tamanho. Isso
evita que mensagens grandes (ex: chaves RSA) sejam cortadas ou que
duas mensagens colem uma na outra.
"""

import json
import struct


def send_json(sock, data: dict) -> None:
    payload = json.dumps(data).encode("utf-8")
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo peer.")
        buf += chunk
    return buf


def recv_json(sock) -> dict:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))