"""
crypto_utils.py
Funções de criptografia híbrida (RSA-2048 + AES-256-CBC) usando a
biblioteca `cryptography` (auditada). Nenhum algoritmo criptográfico
é implementado do zero.

Fluxo de uma mensagem:
1. Gera-se uma chave AES-256 aleatória (e um IV aleatório).
2. A mensagem é criptografada com AES-256-CBC (com padding PKCS7).
3. A chave AES é criptografada com a chave pública RSA do destinatário
   (usando padding OAEP).
4. O destinatário decifra a chave AES com sua chave privada RSA e,
   em seguida, decifra a mensagem.
"""

import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# ---------------------------------------------------------------------------
# RSA: geração e serialização de chaves
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    """Gera um par de chaves RSA-2048."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> str:
    """Serializa a chave pública em PEM e retorna como string base64
    (para facilitar o transporte em JSON pela rede)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("ascii")


def deserialize_public_key(pubkey_b64: str):
    """Reconstrói uma chave pública a partir da string base64/PEM."""
    pem = base64.b64decode(pubkey_b64)
    return serialization.load_pem_public_key(pem)


# ---------------------------------------------------------------------------
# AES-256-CBC (criptografia simétrica da mensagem)
# ---------------------------------------------------------------------------

def aes_encrypt(message: bytes) -> tuple[bytes, bytes, bytes]:
    """Criptografa `message` com uma chave AES-256 aleatória.
    Retorna (chave_aes, iv, ciphertext)."""
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return aes_key, iv, ciphertext


def aes_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decifra o ciphertext usando a chave AES e o IV fornecidos."""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


# ---------------------------------------------------------------------------
# RSA: criptografar/decifrar a chave AES (OAEP)
# ---------------------------------------------------------------------------

def rsa_encrypt_key(aes_key: bytes, recipient_public_key) -> bytes:
    """Criptografa a chave AES com a chave pública RSA do destinatário."""
    return recipient_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """Decifra a chave AES usando a chave privada RSA do destinatário."""
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# Funções de alto nível: criptografia híbrida completa de uma mensagem
# ---------------------------------------------------------------------------

def encrypt_message(message: str, recipient_public_key) -> dict:
    """Criptografa uma mensagem de texto com o fluxo híbrido completo.
    Retorna um dicionário pronto para ser serializado em JSON e enviado
    pela rede (todos os campos binários em base64)."""
    aes_key, iv, ciphertext = aes_encrypt(message.encode("utf-8"))
    encrypted_key = rsa_encrypt_key(aes_key, recipient_public_key)

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(payload: dict, private_key) -> str:
    """Reverte encrypt_message: decifra a chave AES com RSA e depois
    decifra a mensagem com AES."""
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aes_key = rsa_decrypt_key(encrypted_key, private_key)
    plaintext = aes_decrypt(aes_key, iv, ciphertext)
    return plaintext.decode("utf-8")