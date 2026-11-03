"""Registro en Ejecutar (App Paths) y purga de RunMRU / TypedPaths.

No se toca el PATH ni se pide administrador: solo HKCU.
El nombre es corto, configurable y se valida contra colisiones reales.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from .errors import CarcasaError
from .paths import AppPaths
from .registry import Registry, get_default_registry
from .winutil import atomic_write_bytes

APP_PATHS = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
RUN_MRU = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
TYPED_PATHS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
BLOCKED_WORDS = (
    "carcasa",
    "vault",
    "boveda",
    "privado",
    "private",
    "secreto",
    "secret",
    "oculto",
    "hide",
    "stealth",
    "pin",
    "password",
    "clave",
)


class NameRejected(CarcasaError):
    pass


class NameCollision(CarcasaError):
    pass


def validate_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise NameRejected("Nombre no valido.")
    lowered = name.casefold()
    if any(word in lowered for word in BLOCKED_WORDS):
        raise NameRejected("Nombre no valido.")
    return name


def _clean_run_value(raw: str) -> str:
    text = str(raw)
    if text.endswith("\\1"):
        text = text[:-2]
    return text.strip().casefold()


class RunEntry:
    def __init__(
        self,
        paths: AppPaths | None = None,
        registry: Registry | None = None,
        *,
        which=shutil.which,
    ) -> None:
        self.paths = paths or AppPaths.default()
        self.registry = registry or get_default_registry()
        self.which = which

    @property
    def state_file(self) -> Path:
        return self.paths.state / "runentry.json"

    def collision(self, name: str) -> str | None:
        target = f"{name}.exe"
        for hive in ("HKCU", "HKLM"):
            if self.registry.key_exists(hive, f"{APP_PATHS}\\{target}"):
                return "registro"
            for sub in self.registry.list_subkeys(hive, APP_PATHS):
                if sub.casefold() == target.casefold():
                    return "registro"
        if self.registry.key_exists("HKCR", f"Applications\\{target}"):
            return "registro"
        if self.which(name) or self.which(target):
            return "PATH"
        system32 = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32"
        if (system32 / target).exists():
            return "sistema"
        return None

    def install(self, exe_path: str | Path, name: str | None = None) -> str:
        name = validate_name(name or self._configured_name())
        exe_path = Path(exe_path).resolve()
        if not exe_path.is_file():
            raise NameRejected("Ejecutable no encontrado.")
        collision = self.collision(name)
        if collision:
            raise NameCollision("Ese nombre ya existe. Elige otro.")
        self.registry.write_value("HKCU", f"{APP_PATHS}\\{name}.exe", "", str(exe_path))
        self.paths.ensure()
        atomic_write_bytes(
            self.state_file,
            json.dumps({"name": name, "exe": str(exe_path)}, sort_keys=True).encode("utf-8"),
        )
        return name

    def uninstall(self, name: str | None = None) -> None:
        name = name or self._installed_name() or self._configured_name()
        self.registry.delete_key("HKCU", f"{APP_PATHS}\\{name}.exe")
        try:
            self.state_file.unlink()
        except OSError:
            pass

    def is_installed(self, name: str | None = None) -> bool:
        name = name or self._installed_name()
        if not name:
            return False
        return self.registry.key_exists("HKCU", f"{APP_PATHS}\\{name}.exe")

    def _installed_name(self) -> str | None:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return str(data.get("name"))
        except (OSError, ValueError):
            return None

    def _configured_name(self) -> str:
        from .paths import read_config

        return str(read_config(self.paths).get("run_name") or "wrun")

    # -- purga ------------------------------------------------------------

    def purge_run_mru(self, name: str | None = None) -> int:
        name = name or self._installed_name() or self._configured_name()
        wanted = name.casefold()
        values = self.registry.read_values("HKCU", RUN_MRU)
        removed: set[str] = set()
        for key, value in values.items():
            if key == "MRUList":
                continue
            if _clean_run_value(value.data) == wanted:
                removed.add(key)
        for key in removed:
            self.registry.delete_value("HKCU", RUN_MRU, key)
        order = values.get("MRUList")
        if order is not None and removed:
            new_order = "".join(ch for ch in str(order.data) if ch not in removed)
            self.registry.write_value("HKCU", RUN_MRU, "MRUList", new_order, order.kind)
        return len(removed)

    def purge_typed_paths(self, name: str | None = None) -> int:
        name = name or self._installed_name() or self._configured_name()
        wanted = name.casefold()
        removed = 0
        for key, value in self.registry.read_values("HKCU", TYPED_PATHS).items():
            if _clean_run_value(value.data) == wanted:
                self.registry.delete_value("HKCU", TYPED_PATHS, key)
                removed += 1
        return removed

    def purge(self, name: str | None = None) -> tuple[int, int]:
        return self.purge_run_mru(name), self.purge_typed_paths(name)
