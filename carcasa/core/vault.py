"""Boveda cifrada: crear, abrir, cerrar y operar con archivos.

Estructura en disco (sin ningun nombre original visible):

    <boveda>/
        vault.hdr        cabecera en claro: version, KDF, salts, nonce base,
                         clave maestra envuelta con PIN y con codigo de
                         recuperacion (AES-256-GCM).
        index.enc        indice cifrado: id -> nombre, tamano, mtime, sha256.
        blobs/<id>.bin   contenido cifrado por trozos.
        work/            area de trabajo temporal (perfil privado), marcada
                         como no indexada y borrada al cerrar.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from . import crypto
from .errors import (
    DuplicateName,
    InvalidName,
    InvalidSecret,
    VaultCorrupted,
    VaultExists,
    VaultNotFound,
    VaultRevoked,
    VaultUnreadable,
)
from .winutil import (
    atomic_write_bytes,
    is_windows,
    make_temp_file,
    mark_not_indexed,
    mark_tree_not_indexed,
    secure_delete,
)

HEADER_MAGIC = "CARCASA"
HEADER_VERSION = 1
HEADER_NAME = "vault.hdr"
INDEX_NAME = "index.enc"
INDEX_MAGIC = b"CRCI1"
BLOBS_DIR = "blobs"
WORK_DIR = "work"
RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    size: int
    mtime: float
    sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Header:
    magic: str = HEADER_MAGIC
    version: int = HEADER_VERSION
    vault_id: str = ""
    created: str = ""
    kdf: dict = field(default_factory=crypto.kdf_params)
    salt_pin: str = ""
    salt_rec: str = ""
    nonce_base: str = ""
    wrap_pin: str | None = None
    wrap_rec: str | None = None


class _HashingReader:
    def __init__(self, handle) -> None:
        self._handle = handle
        self.digest = hashlib.sha256()
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        block = self._handle.read(size)
        if block:
            self.digest.update(block)
            self.count += len(block)
        return block


class _HashingWriter:
    def __init__(self) -> None:
        self.digest = hashlib.sha256()
        self.count = 0

    def write(self, block: bytes) -> int:
        self.digest.update(block)
        self.count += len(block)
        return len(block)


# --------------------------------------------------------------------------
# Cabecera
# --------------------------------------------------------------------------


def _binding(header: Header) -> bytes:
    payload = {
        "magic": header.magic,
        "version": header.version,
        "vault_id": header.vault_id,
        "nonce_base": header.nonce_base,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _wrap_aad(header: Header, purpose: str) -> bytes:
    return b"carcasa-wrap-v1|" + purpose.encode("ascii") + b"|" + _binding(header)


def _index_aad(header: Header) -> bytes:
    return b"carcasa-index-v1|" + header.vault_id.encode("ascii") + b"|" + header.nonce_base.encode("ascii")


def _blob_aad(header: Header, entry_id: str) -> bytes:
    return (
        b"carcasa-blob-v1|"
        + header.vault_id.encode("ascii")
        + b"|"
        + header.nonce_base.encode("ascii")
        + b"|"
        + entry_id.encode("ascii")
    )


def _header_to_json(header: Header) -> bytes:
    return json.dumps(asdict(header), sort_keys=True, indent=2).encode("utf-8") + b"\n"


def _header_from_json(raw: bytes) -> Header:
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise VaultCorrupted("cabecera ilegible") from exc
    if not isinstance(data, dict) or data.get("magic") != HEADER_MAGIC:
        raise VaultCorrupted("cabecera invalida")
    if data.get("version") != HEADER_VERSION:
        raise VaultCorrupted("version no compatible")
    try:
        header = Header(
            magic=HEADER_MAGIC,
            version=HEADER_VERSION,
            vault_id=str(data["vault_id"]),
            created=str(data.get("created", "")),
            kdf=crypto.validate_kdf_params(data["kdf"]),
            salt_pin=str(data.get("salt_pin", "")),
            salt_rec=str(data.get("salt_rec", "")),
            nonce_base=str(data["nonce_base"]),
            wrap_pin=data.get("wrap_pin"),
            wrap_rec=data.get("wrap_rec"),
        )
    except KeyError as exc:
        raise VaultCorrupted("cabecera incompleta") from exc
    if len(header.vault_id) != 32:
        raise VaultCorrupted("cabecera invalida")
    return header


def _wrap(vk: bytearray, secret: str, salt: bytes, header: Header, purpose: str) -> str:
    kek = crypto.derive_key(secret, salt, **header.kdf)
    try:
        wrapped = crypto.aes_encrypt(kek, bytes(vk), _wrap_aad(header, purpose))
    finally:
        del kek
    return crypto.b64e(wrapped)


def _unwrap(wrapped: str, secret: str, salt_b64: str, header: Header, purpose: str) -> bytearray:
    try:
        salt = crypto.b64d(salt_b64)
        blob = crypto.b64d(wrapped)
    except crypto.FormatError as exc:
        raise VaultCorrupted("cabecera invalida") from exc
    kek = crypto.derive_key(secret, salt, **header.kdf)
    try:
        key = crypto.aes_decrypt(kek, blob, _wrap_aad(header, purpose))
    finally:
        del kek
    if len(key) != crypto.KEY_LEN:
        raise VaultCorrupted("clave invalida")
    return bytearray(key)


# --------------------------------------------------------------------------
# Boveda
# --------------------------------------------------------------------------


class Vault:
    def __init__(
        self,
        path: Path,
        header: Header,
        key: bytearray,
        index: dict,
        *,
        chunk_size: int = crypto.DEFAULT_CHUNK,
        opened_with: str = "pin",
    ) -> None:
        self.path = Path(path)
        self.header = header
        self._key: bytearray | None = key
        self._index = index
        self.chunk_size = chunk_size
        self.opened_with = opened_with
        self._closed = False

    # -- construccion -----------------------------------------------------

    @classmethod
    def create(
        cls,
        path: str | Path,
        pin: str,
        *,
        params: dict | None = None,
        chunk_size: int = crypto.DEFAULT_CHUNK,
    ) -> tuple["Vault", str]:
        pin = crypto.validate_pin(pin)
        path = Path(path)
        if path.exists() and (not path.is_dir() or any(path.iterdir())):
            raise VaultExists("La carpeta de la boveda ya existe.")

        kdf = crypto.validate_kdf_params(params or crypto.kdf_params())
        vault_key = crypto.new_vault_key()
        header = Header(
            vault_id=secrets.token_hex(16),
            created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            kdf=kdf,
            salt_pin=crypto.b64e(crypto.new_salt()),
            salt_rec=crypto.b64e(crypto.new_salt()),
            nonce_base=crypto.b64e(os.urandom(16)),
        )
        recovery = crypto.new_recovery_code()
        try:
            header.wrap_pin = _wrap(
                vault_key, pin, crypto.b64d(header.salt_pin), header, "pin"
            )
            header.wrap_rec = _wrap(
                vault_key,
                crypto.normalize_recovery_code(recovery),
                crypto.b64d(header.salt_rec),
                header,
                "rec",
            )
        except Exception:
            crypto.wipe_key(vault_key)
            raise

        staging = path.parent / f".{path.name}.new-{secrets.token_hex(6)}"
        try:
            staging.mkdir(parents=True)
            (staging / BLOBS_DIR).mkdir()
            (staging / WORK_DIR).mkdir()
            vault = cls(staging, header, vault_key, {"version": 1, "entries": {}}, chunk_size=chunk_size)
            vault._save_index()
            vault._save_header()
            mark_tree_not_indexed(staging)
            if path.exists():
                path.rmdir()
            os.replace(staging, path)
            mark_tree_not_indexed(path)
        except Exception:
            crypto.wipe_key(vault_key)
            secure_delete(staging)
            raise

        vault.path = path
        return vault, recovery

    @classmethod
    def open(cls, path: str | Path, secret: str, *, chunk_size: int = crypto.DEFAULT_CHUNK) -> "Vault":
        path = Path(path)
        if not path.is_dir():
            raise VaultNotFound("La boveda no existe.")
        header_path = path / HEADER_NAME
        if not header_path.is_file():
            raise VaultNotFound("La boveda no esta inicializada.")
        header = _header_from_json(header_path.read_bytes())
        if header.wrap_pin is None and header.wrap_rec is None:
            raise VaultRevoked("Acceso revocado.")

        secret = secret if isinstance(secret, str) else ""
        candidates: list[tuple[str, str, str]] = []
        wants_recovery = crypto.is_valid_recovery_code(secret)
        if wants_recovery and header.wrap_rec:
            candidates.append(("rec", header.wrap_rec, header.salt_rec))
        if header.wrap_pin:
            candidates.append(("pin", header.wrap_pin, header.salt_pin))
        if header.wrap_rec and not wants_recovery:
            candidates.append(("rec", header.wrap_rec, header.salt_rec))

        key: bytearray | None = None
        opened_with = ""
        for kind, wrapped, salt in candidates:
            candidate_secret = (
                crypto.normalize_recovery_code(secret) if kind == "rec" else secret
            )
            try:
                key = _unwrap(wrapped, candidate_secret, salt, header, kind)
                opened_with = kind
                break
            except (crypto.AuthenticationError, crypto.FormatError, VaultCorrupted):
                continue
        if key is None:
            if header.wrap_pin is None:
                raise VaultRevoked("Acceso con PIN revocado.")
            raise InvalidSecret()

        vault = cls(path, header, key, {"version": 1, "entries": {}}, chunk_size=chunk_size, opened_with=opened_with)
        try:
            vault._load_index()
            vault._clean_stale_temps()
        except Exception:
            vault.close(cleanup=False)
            raise
        return vault

    # -- estado -----------------------------------------------------------

    def _require_open(self) -> bytearray:
        if self._closed or self._key is None:
            raise VaultUnreadable("La boveda esta cerrada.")
        return self._key

    @property
    def is_open(self) -> bool:
        return not self._closed and self._key is not None

    @property
    def is_revoked(self) -> bool:
        return self.header.wrap_pin is None

    def _blob_path(self, entry_id: str) -> Path:
        return self.path / BLOBS_DIR / f"{entry_id}.bin"

    def _save_header(self) -> None:
        atomic_write_bytes(self.path / HEADER_NAME, _header_to_json(self.header))

    def _load_index(self) -> None:
        key = self._require_open()
        try:
            raw = (self.path / INDEX_NAME).read_bytes()
        except OSError as exc:
            raise VaultCorrupted("indice ilegible") from exc
        if not raw.startswith(INDEX_MAGIC):
            raise VaultCorrupted("indice invalido")
        try:
            plain = crypto.aes_decrypt(key, raw[len(INDEX_MAGIC) :], _index_aad(self.header))
            data = json.loads(plain.decode("utf-8"))
        except crypto.AuthenticationError as exc:
            raise VaultCorrupted("indice alterado") from exc
        except (crypto.FormatError, ValueError, UnicodeDecodeError) as exc:
            raise VaultCorrupted("indice invalido") from exc
        if not isinstance(data, dict) or data.get("version") != 1:
            raise VaultCorrupted("indice invalido")
        entries = data.get("entries")
        if not isinstance(entries, dict):
            raise VaultCorrupted("indice invalido")
        clean: dict[str, dict] = {}
        for entry_id, meta in entries.items():
            if not isinstance(entry_id, str) or len(entry_id) != 32:
                raise VaultCorrupted("indice invalido")
            try:
                int(entry_id, 16)
            except ValueError as exc:
                raise VaultCorrupted("indice invalido") from exc
            if not isinstance(meta, dict):
                raise VaultCorrupted("indice invalido")
            try:
                clean[entry_id] = {
                    "name": self._validate_name(str(meta["name"])),
                    "size": int(meta["size"]),
                    "mtime": float(meta["mtime"]),
                    "sha256": str(meta["sha256"]),
                }
            except (KeyError, TypeError, ValueError, InvalidName) as exc:
                raise VaultCorrupted("indice invalido") from exc
            if len(clean[entry_id]["sha256"]) != 64:
                raise VaultCorrupted("indice invalido")
        self._index = {"version": 1, "entries": clean}

    def _save_index(self) -> None:
        key = self._require_open()
        payload = json.dumps(self._index, sort_keys=True, separators=(",", ":")).encode("utf-8")
        blob = INDEX_MAGIC + crypto.aes_encrypt(key, payload, _index_aad(self.header))
        atomic_write_bytes(self.path / INDEX_NAME, blob)

    def _clean_stale_temps(self) -> None:
        for folder in (self.path, self.path / BLOBS_DIR, self.path / WORK_DIR):
            if not folder.is_dir():
                continue
            for item in folder.iterdir():
                if item.name.startswith(".tmp-") or item.name.endswith(".tmp"):
                    secure_delete(item)

    def _cleanup_work_if_needed(self) -> None:
        """Al abrir, cualquier resto de trabajo es basura de un cierre brusco."""
        self.cleanup_work()

    # -- nombres ----------------------------------------------------------

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str):
            raise InvalidName("Nombre invalido.")
        name = name.strip()
        if not name or len(name) > 255 or name in (".", ".."):
            raise InvalidName("Nombre invalido.")
        if any(ch in name for ch in '<>:"/\\|?*') or any(ord(ch) < 32 for ch in name):
            raise InvalidName("Nombre invalido.")
        stem = name.split(".")[0].casefold()
        if stem in RESERVED_NAMES:
            raise InvalidName("Nombre reservado.")
        return name

    def _check_unique(self, name: str, *, ignore: str | None = None) -> None:
        folded = name.casefold()
        for entry_id, meta in self._index["entries"].items():
            if entry_id == ignore:
                continue
            if meta["name"].casefold() == folded:
                raise DuplicateName("Ya existe un archivo con ese nombre.")

    # -- operaciones ------------------------------------------------------

    def entries(self) -> list[Entry]:
        self._require_open()
        result = [
            Entry(
                id=entry_id,
                name=meta["name"],
                size=meta["size"],
                mtime=meta["mtime"],
                sha256=meta["sha256"],
            )
            for entry_id, meta in self._index["entries"].items()
        ]
        return sorted(result, key=lambda item: (item.name.casefold(), item.id))

    def get(self, entry_id: str) -> Entry:
        self._require_open()
        meta = self._index["entries"].get(entry_id)
        if meta is None:
            raise VaultCorrupted("archivo no encontrado")
        return Entry(entry_id, meta["name"], meta["size"], meta["mtime"], meta["sha256"])

    def find(self, name: str) -> Entry | None:
        folded = name.casefold()
        for entry in self.entries():
            if entry.name.casefold() == folded:
                return entry
        return None

    def _store(self, name: str, src, *, mtime: float) -> Entry:
        key = self._require_open()
        name = self._validate_name(name)
        self._check_unique(name)
        entry_id = secrets.token_hex(16)
        blobs = self.path / BLOBS_DIR
        blobs.mkdir(parents=True, exist_ok=True)
        temp = make_temp_file(blobs)
        reader = _HashingReader(src)
        try:
            with open(temp, "wb") as handle:
                crypto.encrypt_stream(
                    key,
                    reader,
                    handle,
                    _blob_aad(self.header, entry_id),
                    chunk_size=self.chunk_size,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self._blob_path(entry_id))
        finally:
            if temp.exists():
                secure_delete(temp)

        meta = {
            "name": name,
            "size": reader.count,
            "mtime": float(mtime),
            "sha256": reader.digest.hexdigest(),
        }
        self._index["entries"][entry_id] = meta
        try:
            self._save_index()
        except Exception:
            self._index["entries"].pop(entry_id, None)
            secure_delete(self._blob_path(entry_id))
            raise
        return Entry(entry_id, name, meta["size"], meta["mtime"], meta["sha256"])

    def add_bytes(self, name: str, data: bytes, *, mtime: float | None = None) -> Entry:
        return self._store(name, io.BytesIO(data), mtime=time.time() if mtime is None else mtime)

    def add_file(self, name: str, source: str | Path) -> Entry:
        source = Path(source)
        with open(source, "rb") as handle:
            return self._store(name, handle, mtime=source.stat().st_mtime)

    def read_bytes(self, entry_id: str) -> bytes:
        key = self._require_open()
        entry = self.get(entry_id)
        out = io.BytesIO()
        try:
            with open(self._blob_path(entry_id), "rb") as handle:
                crypto.decrypt_stream(
                    key,
                    handle,
                    out,
                    _blob_aad(self.header, entry_id),
                    max_bytes=entry.size,
                )
        except crypto.CryptoError as exc:
            raise VaultCorrupted("archivo alterado") from exc
        data = out.getvalue()
        if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.sha256:
            raise VaultCorrupted("archivo alterado")
        return data

    def extract(self, entry_id: str, destination: str | Path) -> Path:
        key = self._require_open()
        entry = self.get(entry_id)
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.parent / f".{destination.name}.{secrets.token_hex(6)}.part"
        writer = _HashingWriter()
        try:
            with open(self._blob_path(entry_id), "rb") as source, open(temp, "wb") as out:
                try:
                    crypto.decrypt_stream(
                        key,
                        source,
                        _TeeWriter(out, writer),
                        _blob_aad(self.header, entry_id),
                        max_bytes=entry.size,
                    )
                except crypto.CryptoError as exc:
                    raise VaultCorrupted("archivo alterado") from exc
                out.flush()
                os.fsync(out.fileno())
            if writer.count != entry.size or writer.digest.hexdigest() != entry.sha256:
                raise VaultCorrupted("archivo alterado")
            os.replace(temp, destination)
            try:
                os.utime(destination, (entry.mtime, entry.mtime))
            except OSError:
                pass
        finally:
            if temp.exists():
                secure_delete(temp)
        return destination

    def rename(self, entry_id: str, new_name: str) -> Entry:
        self._require_open()
        new_name = self._validate_name(new_name)
        self._check_unique(new_name, ignore=entry_id)
        meta = self._index["entries"].get(entry_id)
        if meta is None:
            raise VaultCorrupted("archivo no encontrado")
        meta["name"] = new_name
        self._save_index()
        return self.get(entry_id)

    def remove(self, entry_id: str) -> None:
        self._require_open()
        meta = self._index["entries"].pop(entry_id, None)
        if meta is None:
            return
        self._save_index()
        secure_delete(self._blob_path(entry_id))

    def verify(self) -> list[str]:
        self._require_open()
        problems: list[str] = []
        for entry in self.entries():
            try:
                self.read_bytes(entry.id)
            except Exception:
                problems.append(entry.name)
        return problems

    # -- trabajo temporal -------------------------------------------------

    @property
    def work_dir(self) -> Path:
        folder = self.path / WORK_DIR
        folder.mkdir(parents=True, exist_ok=True)
        mark_not_indexed(folder)
        return folder

    def cleanup_work(self, *, secure: bool = True) -> None:
        folder = self.path / WORK_DIR
        if not folder.is_dir():
            return
        for item in list(folder.iterdir()):
            if secure:
                secure_delete(item)
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                try:
                    item.unlink()
                except OSError:
                    pass
            if item.exists():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    try:
                        item.unlink()
                    except OSError:
                        pass

    # -- credenciales -----------------------------------------------------

    def set_pin(self, new_pin: str) -> None:
        key = self._require_open()
        new_pin = crypto.validate_pin(new_pin)
        salt = crypto.new_salt()
        self.header.salt_pin = crypto.b64e(salt)
        self.header.wrap_pin = _wrap(key, new_pin, salt, self.header, "pin")
        self._save_header()
        self.opened_with = "pin"

    def rotate_recovery_code(self) -> str:
        key = self._require_open()
        code = crypto.new_recovery_code()
        salt = crypto.new_salt()
        self.header.salt_rec = crypto.b64e(salt)
        self.header.wrap_rec = _wrap(
            key, crypto.normalize_recovery_code(code), salt, self.header, "rec"
        )
        self._save_header()
        return code

    def revoke_pin(self) -> None:
        """L4: inutiliza el PIN. Solo el codigo de recuperacion puede reabrir."""
        self._require_open()
        if self.header.wrap_rec is None:
            raise VaultRevoked("No hay codigo de recuperacion: no se puede revocar.")
        self.header.wrap_pin = None
        self._save_header()

    def destroy(self, confirmation: str) -> None:
        """Destruccion irreversible de toda la boveda."""
        self._require_open()
        if confirmation != "DESTRUIR":
            raise ValueError("Confirmacion incorrecta.")
        secure_delete(self.path)
        crypto.wipe_key(self._key)
        self._key = None
        self._closed = True
        self._index = {"version": 1, "entries": {}}

    # -- cierre -----------------------------------------------------------

    def close(self, *, cleanup: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        if cleanup:
            try:
                self.cleanup_work()
            except OSError:
                pass
            try:
                self._clean_stale_temps()
            except OSError:
                pass
        crypto.wipe_key(self._key)
        self._key = None
        self._index = {"version": 1, "entries": {}}

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __iter__(self) -> Iterator[Entry]:
        return iter(self.entries())


class _TeeWriter:
    def __init__(self, handle, hasher: _HashingWriter) -> None:
        self._handle = handle
        self._hasher = hasher

    def write(self, block: bytes) -> int:
        self._hasher.write(block)
        return self._handle.write(block)


def header_summary(path: str | Path) -> dict:
    """Datos publicos de la cabecera, utiles para diagnostico sin secretos."""
    header = _header_from_json((Path(path) / HEADER_NAME).read_bytes())
    return {
        "version": header.version,
        "vault_id": header.vault_id,
        "created": header.created,
        "kdf": dict(header.kdf),
        "pin": header.wrap_pin is not None,
        "recovery": header.wrap_rec is not None,
    }


def revoke_pin_on_disk(path: str | Path) -> None:
    """L4 con la boveda cerrada: elimina la envoltura del PIN sin abrirla."""
    path = Path(path)
    header_path = path / HEADER_NAME
    header = _header_from_json(header_path.read_bytes())
    if header.wrap_rec is None:
        raise VaultRevoked("No hay codigo de recuperacion: no se puede revocar.")
    header.wrap_pin = None
    atomic_write_bytes(header_path, _header_to_json(header))
