"""Acceso al registro de Windows con una implementacion en memoria para tests.

Nunca se escribe fuera de HKCU salvo lectura. Todo lo que la app modifica vive
en el perfil del usuario actual.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

try:  # pragma: no cover - solo Windows
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7

HIVES = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE", "HKCR": "HKEY_CLASSES_ROOT"}


@dataclass(frozen=True)
class RegValue:
    name: str
    data: object
    kind: int


class Registry(Protocol):
    def read_values(self, hive: str, key: str) -> dict[str, RegValue]: ...
    def read_value(self, hive: str, key: str, name: str) -> RegValue | None: ...
    def write_value(self, hive: str, key: str, name: str, data, kind: int = REG_SZ) -> None: ...
    def delete_value(self, hive: str, key: str, name: str) -> None: ...
    def list_subkeys(self, hive: str, key: str) -> list[str]: ...
    def delete_key(self, hive: str, key: str) -> None: ...
    def key_exists(self, hive: str, key: str) -> bool: ...


def _norm(key: str) -> str:
    return key.strip("\\")


class RealRegistry:
    def __init__(self) -> None:
        if winreg is None:
            raise RuntimeError("registro no disponible")

    def _hive(self, hive: str):
        try:
            return getattr(winreg, HIVES[hive.upper()])
        except KeyError as exc:
            raise ValueError(f"hive desconocido: {hive}") from exc

    def read_values(self, hive: str, key: str) -> dict[str, RegValue]:
        result: dict[str, RegValue] = {}
        try:
            with winreg.OpenKey(self._hive(hive), _norm(key), 0, winreg.KEY_READ) as handle:
                index = 0
                while True:
                    try:
                        name, data, kind = winreg.EnumValue(handle, index)
                    except OSError:
                        break
                    result[name] = RegValue(name, data, kind)
                    index += 1
        except OSError:
            return {}
        return result

    def read_value(self, hive: str, key: str, name: str) -> RegValue | None:
        try:
            with winreg.OpenKey(self._hive(hive), _norm(key), 0, winreg.KEY_READ) as handle:
                data, kind = winreg.QueryValueEx(handle, name)
                return RegValue(name, data, kind)
        except OSError:
            return None

    def write_value(self, hive: str, key: str, name: str, data, kind: int = REG_SZ) -> None:
        with winreg.CreateKeyEx(self._hive(hive), _norm(key), 0, winreg.KEY_WRITE) as handle:
            winreg.SetValueEx(handle, name, 0, kind, data)

    def delete_value(self, hive: str, key: str, name: str) -> None:
        try:
            with winreg.OpenKey(self._hive(hive), _norm(key), 0, winreg.KEY_WRITE) as handle:
                winreg.DeleteValue(handle, name)
        except OSError:
            pass

    def list_subkeys(self, hive: str, key: str) -> list[str]:
        result: list[str] = []
        try:
            with winreg.OpenKey(self._hive(hive), _norm(key), 0, winreg.KEY_READ) as handle:
                index = 0
                while True:
                    try:
                        result.append(winreg.EnumKey(handle, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            return []
        return result

    def delete_key(self, hive: str, key: str) -> None:
        key = _norm(key)
        for child in self.list_subkeys(hive, key):
            self.delete_key(hive, f"{key}\\{child}")
        try:
            with winreg.OpenKey(self._hive(hive), key, 0, winreg.KEY_WRITE) as handle:
                winreg.DeleteKey(handle, "")
        except OSError:
            pass

    def key_exists(self, hive: str, key: str) -> bool:
        try:
            with winreg.OpenKey(self._hive(hive), _norm(key), 0, winreg.KEY_READ):
                return True
        except OSError:
            return False


class MemoryRegistry:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], dict[str, RegValue]] = {}

    def read_values(self, hive: str, key: str) -> dict[str, RegValue]:
        return dict(self._values.get((hive.upper(), _norm(key)), {}))

    def read_value(self, hive: str, key: str, name: str) -> RegValue | None:
        return self._values.get((hive.upper(), _norm(key)), {}).get(name)

    def write_value(self, hive: str, key: str, name: str, data, kind: int = REG_SZ) -> None:
        bucket = self._values.setdefault((hive.upper(), _norm(key)), {})
        bucket[name] = RegValue(name, data, kind)

    def delete_value(self, hive: str, key: str, name: str) -> None:
        bucket = self._values.get((hive.upper(), _norm(key)))
        if bucket:
            bucket.pop(name, None)

    def list_subkeys(self, hive: str, key: str) -> list[str]:
        prefix = (hive.upper(), _norm(key) + "\\")
        names = set()
        for h, k in self._values:
            if h == prefix[0] and k.startswith(prefix[1]):
                names.add(k[len(prefix[1]) :].split("\\")[0])
        return sorted(names)

    def delete_key(self, hive: str, key: str) -> None:
        hive = hive.upper()
        key = _norm(key)
        for (h, k) in list(self._values):
            if h == hive and (k == key or k.startswith(key + "\\")):
                del self._values[(h, k)]

    def key_exists(self, hive: str, key: str) -> bool:
        hive = hive.upper()
        key = _norm(key)
        return any(h == hive and (k == key or k.startswith(key + "\\")) for h, k in self._values)


def get_default_registry() -> Registry:
    if os.name == "nt":
        return RealRegistry()
    return MemoryRegistry()
