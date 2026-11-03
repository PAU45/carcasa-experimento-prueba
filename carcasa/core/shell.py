"""Conmutacion del estado visible (escritorio, barra, fondo, tema).

Invariantes que cubre este modulo:
  * INV1: al arrancar siempre se restaura el estado publico.
  * INV3: nunca se toca el proyecto publico.
  * INV8: se valida el hash de la instantanea antes de dar el cambio por bueno.
  * INV9: cada conmutacion se puede revertir; si no, queda diario y se avisa.

El diario se escribe ANTES de tocar nada y sobrevive a un kill. Un arranque
posterior siempre aplica la instantanea publica guardada y la verifica.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .errors import PathNotAllowed, RecoveryRequired, SwitchFailed
from .paths import AppPaths, pinned_taskbar_dir, public_desktop
from .registry import REG_DWORD, REG_EXPAND_SZ, REG_SZ, MemoryRegistry, Registry, get_default_registry
from .winutil import atomic_write_bytes, is_windows, sha256_file

USER_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
DESKTOP_KEY = r"Control Panel\Desktop"
PERSONALIZE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
DWM_KEY = r"Software\Microsoft\Windows\DWM"
BAGS_KEY = r"Software\Microsoft\Windows\Shell\Bags\1\Desktop"

SPI_SETDESKWALLPAPER = 0x0014
SPIF_UPDATEINIFILE = 0x01
SPIF_SENDWININICHANGE = 0x02
SHCNE_ASSOCCHANGED = 0x08000000
SHCNF_IDLIST = 0x0000


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PinnedItem:
    name: str
    sha256: str


@dataclass(frozen=True)
class ShellState:
    desktop_dir: str
    wallpaper: str = ""
    wallpaper_style: str = "10"
    wallpaper_tile: str = "0"
    apps_light: int = 1
    system_light: int = 1
    accent: int = 0
    color_prevalence: int = 0
    pinned: tuple[PinnedItem, ...] = ()
    icons_digest: str = ""

    def to_dict(self) -> dict:
        return {
            "desktop_dir": self.desktop_dir,
            "wallpaper": self.wallpaper,
            "wallpaper_style": self.wallpaper_style,
            "wallpaper_tile": self.wallpaper_tile,
            "apps_light": int(self.apps_light),
            "system_light": int(self.system_light),
            "accent": int(self.accent),
            "color_prevalence": int(self.color_prevalence),
            "pinned": [asdict(item) for item in self.pinned],
            "icons_digest": self.icons_digest,
        }


@dataclass(frozen=True)
class ShellProfile:
    desktop_dir: str
    wallpaper: str = ""
    wallpaper_style: str = "10"
    wallpaper_tile: str = "0"
    apps_light: int = 1
    system_light: int = 1
    accent: int = 0
    color_prevalence: int = 0
    pinned_source: Path | None = None

    def state(self) -> ShellState:
        pins = read_pinned(self.pinned_source) if self.pinned_source else ()
        return ShellState(
            desktop_dir=os.path.expandvars(self.desktop_dir),
            wallpaper=os.path.expandvars(self.wallpaper),
            wallpaper_style=str(self.wallpaper_style),
            wallpaper_tile=str(self.wallpaper_tile),
            apps_light=int(self.apps_light),
            system_light=int(self.system_light),
            accent=int(self.accent),
            color_prevalence=int(self.color_prevalence),
            pinned=pins,
        )


@dataclass(frozen=True)
class SwitchResult:
    phase: str
    changed: bool
    digest: str
    previous: str
    elapsed_ms: float


def state_from_dict(data: dict) -> ShellState:
    pins = tuple(
        PinnedItem(str(item["name"]), str(item["sha256"]))
        for item in data.get("pinned", [])
    )
    return ShellState(
        desktop_dir=str(data["desktop_dir"]),
        wallpaper=str(data.get("wallpaper", "")),
        wallpaper_style=str(data.get("wallpaper_style", "10")),
        wallpaper_tile=str(data.get("wallpaper_tile", "0")),
        apps_light=int(data.get("apps_light", 1)),
        system_light=int(data.get("system_light", 1)),
        accent=int(data.get("accent", 0)),
        color_prevalence=int(data.get("color_prevalence", 0)),
        pinned=pins,
        icons_digest=str(data.get("icons_digest", "")),
    )


def state_digest(state: ShellState) -> str:
    """Hash estable de lo visible: escritorio, barra y fondo. Sin timestamps."""
    payload = {
        "desktop_dir": os.path.normcase(os.path.expandvars(state.desktop_dir)),
        "wallpaper": os.path.normcase(os.path.expandvars(state.wallpaper)),
        "wallpaper_style": str(state.wallpaper_style),
        "wallpaper_tile": str(state.wallpaper_tile),
        "apps_light": int(state.apps_light),
        "system_light": int(state.system_light),
        "accent": int(state.accent) & 0xFFFFFFFF,
        "color_prevalence": int(state.color_prevalence),
        "pinned": sorted([item.name.casefold(), item.sha256] for item in state.pinned),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def read_pinned(source: Path | None) -> tuple[PinnedItem, ...]:
    if source is None or not Path(source).is_dir():
        return ()
    items = []
    for path in sorted(Path(source).glob("*.lnk"), key=lambda item: item.name.casefold()):
        items.append(PinnedItem(path.name, sha256_file(path)))
    return tuple(items)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.expandvars(str(path)))


# --------------------------------------------------------------------------
# Backend real
# --------------------------------------------------------------------------


class RealShellBackend:
    def __init__(
        self,
        registry: Registry | None = None,
        pinned_dir: Path | None = None,
        *,
        notify: bool = True,
        allow_explorer_restart: bool = True,
    ) -> None:
        self.registry = registry or get_default_registry()
        self.pinned_dir = pinned_dir or pinned_taskbar_dir()
        self.notify_enabled = notify
        self.allow_explorer_restart = allow_explorer_restart

    # -- lectura ----------------------------------------------------------

    def _value(self, key: str, name: str, default):
        value = self.registry.read_value("HKCU", key, name)
        if value is None:
            return default
        return value.data

    def read_state(self) -> ShellState:
        desktop = str(self._value(USER_SHELL_FOLDERS, "Desktop", str(public_desktop())))
        wallpaper = str(self._value(DESKTOP_KEY, "Wallpaper", "") or "")
        return ShellState(
            desktop_dir=os.path.expandvars(desktop),
            wallpaper=os.path.expandvars(wallpaper),
            wallpaper_style=str(self._value(DESKTOP_KEY, "WallpaperStyle", "10")),
            wallpaper_tile=str(self._value(DESKTOP_KEY, "TileWallpaper", "0")),
            apps_light=int(self._value(PERSONALIZE_KEY, "AppsUseLightTheme", 1) or 0),
            system_light=int(self._value(PERSONALIZE_KEY, "SystemUsesLightTheme", 1) or 0),
            accent=int(self._value(DWM_KEY, "AccentColor", 0) or 0),
            color_prevalence=int(self._value(DWM_KEY, "ColorPrevalence", 0) or 0),
            pinned=read_pinned(self.pinned_dir),
            icons_digest=self.layout_digest(),
        )

    def layout_digest(self) -> str:
        values = self.registry.read_values("HKCU", BAGS_KEY)
        payload = {
            name: str(value.data)
            for name, value in sorted(values.items())
            if name not in ("NodeSlots",)
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    # -- escritura --------------------------------------------------------

    def set_desktop(self, path: str) -> None:
        path = os.path.expandvars(str(path))
        self.registry.write_value("HKCU", USER_SHELL_FOLDERS, "Desktop", path, REG_EXPAND_SZ)

    def set_wallpaper(self, path: str, style: str = "10", tile: str = "0") -> None:
        path = os.path.expandvars(str(path))
        self.registry.write_value("HKCU", DESKTOP_KEY, "Wallpaper", path, REG_SZ)
        self.registry.write_value("HKCU", DESKTOP_KEY, "WallpaperStyle", str(style), REG_SZ)
        self.registry.write_value("HKCU", DESKTOP_KEY, "TileWallpaper", str(tile), REG_SZ)
        if is_windows() and path:
            try:
                ctypes.windll.user32.SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER,
                    0,
                    ctypes.c_wchar_p(path),
                    SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE,
                )
            except Exception:
                pass

    def set_theme(self, apps_light: int, system_light: int, accent: int, prevalence: int) -> None:
        self.registry.write_value("HKCU", PERSONALIZE_KEY, "AppsUseLightTheme", int(apps_light), REG_DWORD)
        self.registry.write_value("HKCU", PERSONALIZE_KEY, "SystemUsesLightTheme", int(system_light), REG_DWORD)
        self.registry.write_value("HKCU", DWM_KEY, "AccentColor", int(accent) & 0xFFFFFFFF, REG_DWORD)
        self.registry.write_value("HKCU", DWM_KEY, "ColorPrevalence", int(prevalence), REG_DWORD)

    def set_pinned(self, source: Path) -> bool:
        source = Path(source)
        if not source.is_dir():
            raise SwitchFailed("No estan los accesos de la barra.")
        wanted = read_pinned(source)
        current = read_pinned(self.pinned_dir)
        if wanted == current:
            return False
        self.pinned_dir.mkdir(parents=True, exist_ok=True)
        for old in self.pinned_dir.glob("*.lnk"):
            try:
                old.unlink()
            except OSError:
                pass
        for item in sorted(source.glob("*.lnk"), key=lambda path: path.name.casefold()):
            shutil.copy2(item, self.pinned_dir / item.name)
        return True

    def notify(self) -> None:
        if not self.notify_enabled or not is_windows():
            return
        try:
            ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        except Exception:
            pass

    def restart_explorer(self) -> None:
        if not self.allow_explorer_restart or not is_windows():
            return
        try:
            subprocess.run(
                ["taskkill", "/f", "/im", "explorer.exe"],
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass
        try:
            subprocess.Popen(
                ["explorer.exe"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass


# --------------------------------------------------------------------------
# Backend falso (tests)
# --------------------------------------------------------------------------


class FakeShellBackend:
    def __init__(self, state: ShellState, pinned_files: dict[str, bytes] | None = None) -> None:
        self._state = state
        self.pinned_files = dict(pinned_files or {})
        self.calls: list[str] = []
        self.failures: dict[str, int] = {}
        self.ignore: set[str] = set()
        self.restarts = 0
        self.on_call = None

    def _tick(self, name: str) -> None:
        self.calls.append(name)
        if self.on_call is not None:
            self.on_call(name)
        remaining = self.failures.get(name, 0)
        if remaining > 0:
            self.failures[name] = remaining - 1
            raise OSError(f"fallo simulado en {name}")

    def read_state(self) -> ShellState:
        pins = tuple(
            PinnedItem(name, hashlib.sha256(data).hexdigest())
            for name, data in sorted(self.pinned_files.items(), key=lambda pair: pair[0].casefold())
        )
        return replace(self._state, pinned=pins)

    def set_desktop(self, path: str) -> None:
        self._tick("set_desktop")
        if "set_desktop" not in self.ignore:
            self._state = replace(self._state, desktop_dir=os.path.expandvars(path))

    def set_wallpaper(self, path: str, style: str = "10", tile: str = "0") -> None:
        self._tick("set_wallpaper")
        if "set_wallpaper" not in self.ignore:
            self._state = replace(
                self._state,
                wallpaper=os.path.expandvars(path),
                wallpaper_style=str(style),
                wallpaper_tile=str(tile),
            )

    def set_theme(self, apps_light: int, system_light: int, accent: int, prevalence: int) -> None:
        self._tick("set_theme")
        if "set_theme" not in self.ignore:
            self._state = replace(
                self._state,
                apps_light=int(apps_light),
                system_light=int(system_light),
                accent=int(accent),
                color_prevalence=int(prevalence),
            )

    def set_pinned(self, source: Path) -> bool:
        self._tick("set_pinned")
        if "set_pinned" in self.ignore:
            return False
        source = Path(source)
        files = {path.name: path.read_bytes() for path in source.glob("*.lnk")}
        if files == self.pinned_files:
            return False
        self.pinned_files = files
        return True

    def notify(self) -> None:
        self.calls.append("notify")

    def restart_explorer(self) -> None:
        self.calls.append("restart_explorer")
        self.restarts += 1


# --------------------------------------------------------------------------
# Diario
# --------------------------------------------------------------------------


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def read(self) -> dict | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("version") == 1:
                return data
        except (OSError, ValueError):
            pass
        return None

    @property
    def pending(self) -> bool:
        return self.read() is not None

    def begin(self, phase: str, restore: ShellState, restore_pinned: Path | None) -> None:
        payload = {
            "version": 1,
            "phase": phase,
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "restore": restore.to_dict(),
            "restore_pinned": str(restore_pinned) if restore_pinned else None,
        }
        atomic_write_bytes(self.path, json.dumps(payload, sort_keys=True).encode("utf-8"))

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Conmutador
# --------------------------------------------------------------------------


class ShellSwitcher:
    def __init__(
        self,
        backend: RealShellBackend | FakeShellBackend,
        journal: Journal,
        public: ShellProfile,
        private: ShellProfile,
        *,
        restart_explorer: bool = False,
        clock=time.monotonic,
    ) -> None:
        self.backend = backend
        self.journal = journal
        self.public = public
        self.private = private
        self.restart_explorer = restart_explorer
        self.clock = clock

    # -- utilidades -------------------------------------------------------

    def _profile_state(self, profile: ShellProfile) -> ShellState:
        state = profile.state()
        self._guard(state)
        if profile.pinned_source is not None:
            text = os.path.normcase(os.path.abspath(str(profile.pinned_source)))
            protected = os.path.normcase(os.path.abspath("C:\\dev\\proyecto"))
            if text == protected or text.startswith(protected + "\\"):
                raise PathNotAllowed("ruta protegida")
        return state

    @staticmethod
    def _guard(state: ShellState) -> None:
        protected = "c:\\dev\\proyecto"
        for value in (state.desktop_dir, state.wallpaper):
            if not value:
                continue
            text = os.path.normcase(os.path.abspath(os.path.expandvars(value)))
            if text == protected or text.startswith(protected + "\\"):
                raise PathNotAllowed("ruta protegida")

    def _verify(self, target: ShellState, part: str) -> None:
        current = self.backend.read_state()
        ok = True
        if part == "desktop":
            ok = _norm(current.desktop_dir) == _norm(target.desktop_dir)
        elif part == "wallpaper":
            ok = (
                _norm(current.wallpaper) == _norm(target.wallpaper)
                and str(current.wallpaper_style) == str(target.wallpaper_style)
                and str(current.wallpaper_tile) == str(target.wallpaper_tile)
            )
        elif part == "theme":
            ok = (
                int(current.apps_light) == int(target.apps_light)
                and int(current.system_light) == int(target.system_light)
                and int(current.accent) & 0xFFFFFFFF == int(target.accent) & 0xFFFFFFFF
                and int(current.color_prevalence) == int(target.color_prevalence)
            )
        elif part == "pinned":
            ok = tuple((item.name, item.sha256) for item in current.pinned) == tuple(
                (item.name, item.sha256) for item in target.pinned
            )
        if not ok:
            raise SwitchFailed(f"La parte {part} no se aplico.")

    def _apply(self, target: ShellState, pinned_source: Path | None) -> bool:
        pins_changed = False
        self.backend.set_desktop(target.desktop_dir)
        self._verify(target, "desktop")
        self.backend.set_wallpaper(target.wallpaper, target.wallpaper_style, target.wallpaper_tile)
        self._verify(target, "wallpaper")
        self.backend.set_theme(target.apps_light, target.system_light, target.accent, target.color_prevalence)
        self._verify(target, "theme")
        if pinned_source is not None:
            pins_changed = self.backend.set_pinned(pinned_source)
            self._verify(target, "pinned")
        elif target.pinned:
            raise SwitchFailed("Faltan los accesos de la barra.")
        self.backend.notify()
        return pins_changed

    # -- API --------------------------------------------------------------

    def switch_to_private(self) -> SwitchResult:
        target = self._profile_state(self.private)
        before = self.backend.read_state()
        started = self.clock()
        if state_digest(before) == state_digest(target):
            return SwitchResult("private", False, state_digest(before), state_digest(before), 0.0)
        public_state = self._profile_state(self.public)
        self.journal.begin("private", public_state, self.public.pinned_source)
        try:
            pins_changed = self._apply(target, self.private.pinned_source)
        except Exception as exc:
            try:
                self._apply(before, self.public.pinned_source)
            except Exception as rb:
                raise RecoveryRequired("No se pudo revertir el cambio.") from rb
            self.journal.clear()
            raise SwitchFailed("No se pudo abrir el estado privado.") from exc
        after = self.backend.read_state()
        if state_digest(after) != state_digest(target):
            try:
                self._apply(before, self.public.pinned_source)
            except Exception as rb:
                raise RecoveryRequired("No se pudo revertir el cambio.") from rb
            self.journal.clear()
            raise SwitchFailed("La verificacion del estado privado fallo.")
        self.journal.clear()
        if pins_changed and self.restart_explorer:
            self.backend.restart_explorer()
        return SwitchResult(
            "private",
            True,
            state_digest(after),
            state_digest(before),
            (self.clock() - started) * 1000,
        )

    def switch_to_public(self) -> SwitchResult:
        target = self._profile_state(self.public)
        before = self.backend.read_state()
        started = self.clock()
        if state_digest(before) == state_digest(target):
            self.journal.clear()
            return SwitchResult("public", False, state_digest(before), state_digest(before), 0.0)
        self.journal.begin("public", target, self.public.pinned_source)
        try:
            pins_changed = self._apply(target, self.public.pinned_source)
        except Exception as exc:
            try:
                self._apply(before, self.private.pinned_source)
            except Exception as rb:
                raise RecoveryRequired("No se pudo revertir el cambio.") from rb
            self.journal.clear()
            raise SwitchFailed("No se pudo volver al estado publico.") from exc
        after = self.backend.read_state()
        if state_digest(after) != state_digest(target):
            try:
                self._apply(before, self.private.pinned_source)
            except Exception as rb:
                raise RecoveryRequired("No se pudo revertir el cambio.") from rb
            self.journal.clear()
            raise SwitchFailed("La verificacion del estado publico fallo.")
        self.journal.clear()
        if pins_changed and self.restart_explorer:
            self.backend.restart_explorer()
        return SwitchResult(
            "public",
            True,
            state_digest(after),
            state_digest(before),
            (self.clock() - started) * 1000,
        )

    def recover_on_boot(self) -> SwitchResult | None:
        entry = self.journal.read()
        if entry is None:
            return None
        restore = state_from_dict(entry["restore"])
        source_raw = entry.get("restore_pinned")
        source = Path(source_raw) if source_raw else None
        started = self.clock()
        before = self.backend.read_state()
        try:
            self._apply(restore, source)
        except Exception as exc:
            raise RecoveryRequired("La restauracion al arrancar fallo.") from exc
        after = self.backend.read_state()
        if state_digest(after) != state_digest(restore):
            raise RecoveryRequired("La instantanea restaurada no coincide.")
        self.journal.clear()
        return SwitchResult(
            "recovery",
            state_digest(before) != state_digest(after),
            state_digest(after),
            state_digest(before),
            (self.clock() - started) * 1000,
        )
