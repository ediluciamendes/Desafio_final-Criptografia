"""
database.py
Armazenamento simples de usuários em arquivo JSON.
Guarda apenas: username, salt (hex) e hash da senha (hex).
Nunca armazena a senha em texto claro.
"""

import json
import os
import threading

DB_PATH = os.path.join(os.path.dirname(__file__), "users.json")
_lock = threading.Lock()


def _load():
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def _save(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2)


def user_exists(username: str) -> bool:
    with _lock:
        return username in _load()


def add_user(username: str, salt_hex: str, hash_hex: str) -> None:
    with _lock:
        data = _load()
        data[username] = {"salt": salt_hex, "hash": hash_hex}
        _save(data)


def get_user(username: str):
    with _lock:
        return _load().get(username)