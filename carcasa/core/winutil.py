"""Utilidades de sistema de archivos para Windows y sustitutos para tests.

Todo lo que escribe en disco pasa por aqui para poder:
  * marcar la boveda como no indexada (INV5),
  * escribir de forma atomica (INV9),
  * borrar de forma segura los temporales,
  * impedir tocar el proyecto publico (INV3).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
import tempfile
from pathlib import Path

FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

PROTECTED_ROOTS = ("C:\\dev\\proyecto",)


def is_windows() -> bool:
    return os.name == "nt"


def _guard(path: Path) -> Path:
    """Rechaza cualquier escritura dentro del proyecto publico (INV3)."""
    resolved = Path(os.path.abspath(str(path)))
    text = str(resolved).rstrip("\\/").lower()
    for root in PROTECTED_ROOTS:
        low = root.lower()
        if text == low or text.startswith(low + "\\"):
            raise PermissionError("ruta protegida")
    return resolved


def mark_not_indexed(path: Path) -> None:
    """Marca la carpeta como no indexada (INV5). Best-effort en no-Windows."""
    path = _guard(path)
    if not is_windows():
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    attrs = kernel32.GetFileAttributesW(str(path))
    if attrs == 0xFFFFFFFF:
        return
    kernel32.SetFileAttributesW(str(path), attrs | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def mark_tree_not_indexed(root: Path) -> None:
    root = _guard(root)
    for dirpath, dirnames, _ in os.walk(root):
        mark_not_indexed(Path(dirpath))


def attributes(path: Path) -> int:
    if not is_windows():
        return 0
    import ctypes

    return int(ctypes.windll.kernel32.GetFileAttributesW(str(path)))


def has_attribute(path: Path, attribute: int) -> bool:
    attrs = attributes(path)
    return attrs != -1 and bool(attrs & attribute)


def fsync_dir(path: Path) -> None:
    """fsync de carpeta; en Windows no es posible y se ignora."""
    if is_windows():
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Escribe con temporal en la misma carpeta y rename atomico."""
    path = _guard(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{secrets.token_hex(6)}.tmp"
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    finally:
        if tmp.exists():
            secure_delete(tmp)


def secure_delete(path: Path, passes: int = 1) -> None:
    """Sobrescribe y borra. Best-effort: algunos sistemas no dejan escribir."""
    path = Path(path)
    try:
        if path.is_dir() and not path.is_symlink():
            for child in list(path.rglob("*")):
                if child.is_file():
                    _overwrite(child, passes)
            shutil.rmtree(path, ignore_errors=True)
            return
        if path.exists():
            _overwrite(path, passes)
            try:
                path.chmod(stat.S_IWRITE)
            except OSError:
                pass
            path.unlink()
    except OSError:
        pass


def _overwrite(path: Path, passes: int) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    try:
        with open(path, "r+b", buffering=0) as handle:
            for _ in range(max(1, passes)):
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    block = min(65536, remaining)
                    handle.write(os.urandom(block))
                    remaining -= block
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        pass


def wipe_buffer(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
    buffer.clear()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def ensure_private_dir(path: Path) -> Path:
    """Crea una carpeta solo para el usuario actual y la marca no indexada."""
    path = _guard(path)
    path.mkdir(parents=True, exist_ok=True)
    if is_windows():
        try:
            import win32security

            user = win32security.GetTokenInformation(
                win32security.OpenProcessToken(
                    win32security.GetCurrentProcess(),
                    win32security.TOKEN_QUERY,
                ),
                win32security.TokenUser,
            )[0]
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, win32security.ACL(), 0)
            sd.GetSecurityDescriptorDacl().AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32security.GENERIC_ALL,
                user,
            )
            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION,
                sd,
            )
        except Exception:
            pass
    mark_not_indexed(path)
    return path


def make_temp_file(directory: Path, prefix: str = ".tmp-") -> Path:
    directory = _guard(directory)
    directory.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=prefix, dir=str(directory))
    os.close(handle)
    return Path(name)


def file_sha_list(paths: list[Path]) -> list[str]:
    return [sha256_file(path) for path in paths if path.is_file()]
