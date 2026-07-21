"""
auth.py
Autenticação de usuários usando hash de senha (PBKDF2-HMAC-SHA256 + salt).

Regra de segurança: a senha em texto claro NUNCA é armazenada nem logada.
Apenas o salt e o hash resultante ficam no banco de dados. No login,
recalculamos o hash da senha digitada com o mesmo salt e comparamos
os hashes (nunca "decodificamos" a senha original).
"""

import hashlib
import os
import hmac

import database

PBKDF2_ITERATIONS = 100_000
HASH_ALGO = "sha256"


def _derive_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        HASH_ALGO, password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


def register(username: str, password: str) -> tuple[bool, str]:
    """Cadastra um novo usuário. Retorna (sucesso, mensagem)."""
    if not username or not password:
        return False, "Usuário e senha não podem ser vazios."
    if database.user_exists(username):
        return False, "Usuário já existe."

    salt = os.urandom(16)
    pwd_hash = _derive_hash(password, salt)
    database.add_user(username, salt.hex(), pwd_hash.hex())
    return True, "Usuário cadastrado com sucesso."


def login(username: str, password: str) -> tuple[bool, str]:
    """Verifica credenciais. Retorna (sucesso, mensagem)."""
    user = database.get_user(username)
    if user is None:
        return False, "Usuário não encontrado."

    salt = bytes.fromhex(user["salt"])
    stored_hash = bytes.fromhex(user["hash"])
    candidate_hash = _derive_hash(password, salt)

    # Comparação em tempo constante para evitar timing attacks
    if hmac.compare_digest(candidate_hash, stored_hash):
        return True, "Login bem-sucedido."
    return False, "Senha incorreta."