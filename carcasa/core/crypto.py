"""Criptografia de Carcasa.

Diseno:
  * Argon2id deriva una clave de envoltura (KEK) a partir del PIN o del codigo
    de recuperacion. Parametros fijos y documentados: t=3, m=64 MiB, p=4.
  * La clave maestra de la boveda (VK, 32 bytes aleatorios) se guarda envuelta
    con AES-256-GCM, una vez con el PIN y otra con el codigo de recuperacion.
    Cambiar el PIN no exige recifrar los archivos.
  * Cada archivo se cifra con AES-256-GCM en trozos de 1 MiB con nonce aleatorio
    de 96 bits por trozo y un terminador autenticado (detecta truncamiento y
    reordenacion).
  * Un nonce base aleatorio en la cabecera separa dominios entre bovedas.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import struct
from dataclasses import dataclass
from typing import BinaryIO

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536  # KiB = 64 MiB
KDF_PARALLELISM = 4
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
WRAP_LEN = KEY_LEN + 16

PIN_MIN = 6
PIN_MAX = 64

RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # sin 0/O/1/I
RECOVERY_PAYLOAD = 20
RECOVERY_CHECK = 4
RECOVERY_LEN = RECOVERY_PAYLOAD + RECOVERY_CHECK  # 24 caracteres

STREAM_MAGIC = b"CRCB1"
DEFAULT_CHUNK = 1 << 20
MIN_CHUNK = 4096
MAX_CHUNK = 8 << 20
MAX_CIPHER_CHUNK = MAX_CHUNK + 16

RECOVERY_CONTEXT = b"carcasa-recovery-v1"


class CryptoError(Exception):
    pass


class AuthenticationError(CryptoError):
    """El dato no autentica: clave, nonce o contenido alterados."""


class FormatError(CryptoError):
    """Formato invalido o truncado."""


# --------------------------------------------------------------------------
# Claves
# --------------------------------------------------------------------------


def kdf_params(
    time_cost: int = KDF_TIME_COST,
    memory_cost: int = KDF_MEMORY_COST,
    parallelism: int = KDF_PARALLELISM,
) -> dict[str, int]:
    return {
        "time_cost": int(time_cost),
        "memory_cost": int(memory_cost),
        "parallelism": int(parallelism),
    }


def validate_kdf_params(params: dict) -> dict[str, int]:
    """Evita parametros absurdos si la cabecera fue manipulada."""
    try:
        clean = {
            "time_cost": int(params["time_cost"]),
            "memory_cost": int(params["memory_cost"]),
            "parallelism": int(params["parallelism"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise FormatError("parametros de KDF invalidos") from exc
    if not 1 <= clean["time_cost"] <= 10:
        raise FormatError("parametros de KDF invalidos")
    if not 8192 <= clean["memory_cost"] <= 1024 * 1024:
        raise FormatError("parametros de KDF invalidos")
    if not 1 <= clean["parallelism"] <= 8:
        raise FormatError("parametros de KDF invalidos")
    return clean


def derive_key(
    secret: str,
    salt: bytes,
    *,
    time_cost: int = KDF_TIME_COST,
    memory_cost: int = KDF_MEMORY_COST,
    parallelism: int = KDF_PARALLELISM,
) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise ValueError("secreto vacio")
    if len(salt) < SALT_LEN:
        raise ValueError("salt corto")
    return hash_secret_raw(
        secret=secret.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def new_vault_key() -> bytearray:
    return bytearray(os.urandom(KEY_LEN))


def validate_pin(pin: str) -> str:
    if not isinstance(pin, str):
        raise ValueError("PIN invalido")
    pin = pin.strip()
    if not PIN_MIN <= len(pin) <= PIN_MAX:
        raise ValueError(f"El PIN debe tener entre {PIN_MIN} y {PIN_MAX} caracteres.")
    if pin.isspace():
        raise ValueError("PIN invalido")
    return pin


# --------------------------------------------------------------------------
# AES-256-GCM de un solo uso (cabecera, indice, envolturas)
# --------------------------------------------------------------------------


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Devuelve nonce(12) || ciphertext+tag."""
    if len(key) != KEY_LEN:
        raise ValueError("clave invalida")
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError("clave invalida")
    if len(blob) < NONCE_LEN + 16:
        raise FormatError("bloque demasiado corto")
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("no autentica") from exc


# --------------------------------------------------------------------------
# Cifrado por trozos
# --------------------------------------------------------------------------


def _chunk_aad(base: bytes, index: int, final: bool) -> bytes:
    return base + b"|" + struct.pack(">II", index, 1 if final else 0)


def encrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    aad: bytes,
    *,
    chunk_size: int = DEFAULT_CHUNK,
) -> int:
    """Cifra un flujo. Devuelve bytes en claro consumidos."""
    if len(key) != KEY_LEN:
        raise ValueError("clave invalida")
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ValueError("tamano de trozo invalido")
    dst.write(STREAM_MAGIC)
    dst.write(struct.pack("<I", chunk_size))
    cipher = AESGCM(key)
    index = 0
    total = 0
    while True:
        block = src.read(chunk_size)
        final = len(block) < chunk_size
        nonce = os.urandom(NONCE_LEN)
        payload = cipher.encrypt(nonce, block, _chunk_aad(aad, index, final))
        dst.write(b"\x01" if final else b"\x00")
        dst.write(nonce)
        dst.write(struct.pack("<I", len(payload)))
        dst.write(payload)
        total += len(block)
        if final:
            return total
        index += 1


def decrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    aad: bytes,
    *,
    max_bytes: int | None = None,
) -> int:
    """Descifra un flujo y comprueba el terminador. Devuelve bytes escritos."""
    if len(key) != KEY_LEN:
        raise ValueError("clave invalida")
    magic = src.read(len(STREAM_MAGIC))
    if magic != STREAM_MAGIC:
        raise FormatError("cabecera de archivo invalida")
    raw_chunk = src.read(4)
    if len(raw_chunk) != 4:
        raise FormatError("archivo truncado")
    chunk_size = struct.unpack("<I", raw_chunk)[0]
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise FormatError("tamano de trozo invalido")
    cipher = AESGCM(key)
    index = 0
    total = 0
    while True:
        flag = src.read(1)
        if not flag:
            raise FormatError("archivo truncado")
        if flag not in (b"\x00", b"\x01"):
            raise FormatError("marca invalida")
        nonce = src.read(NONCE_LEN)
        raw_len = src.read(4)
        if len(nonce) != NONCE_LEN or len(raw_len) != 4:
            raise FormatError("archivo truncado")
        length = struct.unpack("<I", raw_len)[0]
        if not 16 <= length <= MAX_CIPHER_CHUNK:
            raise FormatError("bloque invalido")
        payload = src.read(length)
        if len(payload) != length:
            raise FormatError("archivo truncado")
        final = flag == b"\x01"
        try:
            block = cipher.decrypt(nonce, payload, _chunk_aad(aad, index, final))
        except InvalidTag as exc:
            raise AuthenticationError("no autentica") from exc
        total += len(block)
        if max_bytes is not None and total > max_bytes:
            raise FormatError("archivo demasiado grande")
        dst.write(block)
        if final:
            if src.read(1):
                raise FormatError("datos tras el terminador")
            return total
        index += 1


def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Utilidad para tests y datos pequenos (no usar con archivos grandes)."""
    import io

    out = io.BytesIO()
    encrypt_stream(key, io.BytesIO(plaintext), out, aad)
    return out.getvalue()


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    import io

    out = io.BytesIO()
    decrypt_stream(key, io.BytesIO(blob), out, aad)
    return out.getvalue()


# --------------------------------------------------------------------------
# Codigo de recuperacion (24 caracteres, con suma de comprobacion)
# --------------------------------------------------------------------------


def _checksum(payload: str) -> str:
    digest = hashlib.sha256(RECOVERY_CONTEXT + payload.encode("ascii")).digest()
    return "".join(RECOVERY_ALPHABET[byte % len(RECOVERY_ALPHABET)] for byte in digest[:RECOVERY_CHECK])


def new_recovery_code() -> str:
    payload = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_PAYLOAD))
    return format_recovery_code(payload + _checksum(payload))


def normalize_recovery_code(code: str) -> str:
    if not isinstance(code, str):
        return ""
    return "".join(ch for ch in code.upper() if ch.isalnum())


def format_recovery_code(code: str) -> str:
    clean = normalize_recovery_code(code)
    return "-".join(clean[index : index + 4] for index in range(0, len(clean), 4))


def is_valid_recovery_code(code: str) -> bool:
    clean = normalize_recovery_code(code)
    if len(clean) != RECOVERY_LEN:
        return False
    if any(ch not in RECOVERY_ALPHABET for ch in clean):
        return False
    payload, check = clean[:RECOVERY_PAYLOAD], clean[RECOVERY_PAYLOAD:]
    return _checksum(payload) == check


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise FormatError("base64 invalido") from exc


def wipe_key(key: bytearray | None) -> None:
    if key is None:
        return
    for index in range(len(key)):
        key[index] = 0
    key.clear()
