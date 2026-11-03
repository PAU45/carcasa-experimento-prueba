"""Ocultacion declarativa de aplicaciones.

Nunca se desinstala nada ni se toca Configuracion > Aplicaciones.
Solo se mueven accesos, se purgan listas de saltos y recientes de la app y,
en la cesion, se cierran sus procesos si estan en la lista.

La lista blanca (VS Code, Git, Node) no se toca jamas.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .paths import (
    AppPaths,
    jump_list_dirs,
    read_config,
    recent_dir,
    start_menu_dirs,
)
from .winutil import atomic_write_bytes, is_windows

VISIBLE_DEFAULT = {"vs code", "visual studio code", "git", "node"}
VISIBLE_ALIASES = {"vs code": "vs code", "visual studio code": "vs code", "vscode": "vs code"}
HIDDEN_DEFAULT = ["Docker", "Gemini", "Antigravity", "GitHub Desktop", "OpenCode", "Trae"]


@dataclass(frozen=True)
class AppSpec:
    name: str
    patterns: tuple[str, ...]
    app_ids: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()
    close_on_cede: bool = True

    def matches(self, text: str) -> bool:
        lowered = text.casefold()
        return any(pattern.casefold() in lowered for pattern in self.patterns)


DEFAULT_SPECS: dict[str, AppSpec] = {
    "docker": AppSpec("Docker", ("docker",), ("docker",), ("docker desktop.exe", "docker.exe")),
    "gemini": AppSpec("Gemini", ("gemini",), (), ("gemini.exe",)),
    "antigravity": AppSpec("Antigravity", ("antigravity",), (), ("antigravity.exe",)),
    "github desktop": AppSpec(
        "GitHub Desktop",
        ("github desktop", "githubdesktop"),
        ("githubdesktop",),
        ("githubdesktop.exe",),
    ),
    "opencode": AppSpec("OpenCode", ("opencode",), ("opencode",), ("opencode.exe",)),
    "trae": AppSpec("Trae", ("trae",), ("trae",), ("trae.exe",)),
}


def spec_for(name: str) -> AppSpec:
    normalized = name.strip().casefold()
    if normalized in DEFAULT_SPECS:
        return DEFAULT_SPECS[normalized]
    return AppSpec(name.strip(), (normalized,), (), (normalized + ".exe",))


def canonical_name(name: str) -> str:
    lowered = name.strip().casefold()
    return VISIBLE_ALIASES.get(lowered, lowered)


def default_specs(hide_names: list[str] | None = None, visible: set[str] | None = None) -> list[AppSpec]:
    visible = {canonical_name(item) for item in (visible or VISIBLE_DEFAULT)}
    names = list(hide_names or HIDDEN_DEFAULT)
    specs: list[AppSpec] = []
    for name in names:
        if canonical_name(name) in visible:
            continue
        specs.append(spec_for(name))
    return specs


def windows_shortcut_target(path: Path) -> str:
    if not is_windows():
        return ""
    try:
        import win32com.client

        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(str(path))
        return str(shortcut.TargetPath or "")
    except Exception:
        return ""


class ProcessBackend(Protocol):
    def find(self, names: list[str]) -> list[tuple[int, str]]: ...
    def request_close(self, pid: int) -> None: ...
    def is_running(self, pid: int) -> bool: ...
    def kill(self, pid: int) -> None: ...


class RealProcesses:
    def find(self, names: list[str]) -> list[tuple[int, str]]:
        import psutil

        wanted = {name.casefold() for name in names}
        found = []
        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (process.info.get("name") or "").casefold()
                exe = (process.info.get("exe") or "").casefold()
                if name in wanted or any(name == item or exe.endswith("\\" + item) for item in wanted):
                    found.append((process.info["pid"], name))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found

    def request_close(self, pid: int) -> None:
        import subprocess

        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid)],
                capture_output=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    def is_running(self, pid: int) -> bool:
        import psutil

        try:
            return psutil.Process(pid).is_running()
        except Exception:
            return False

    def kill(self, pid: int) -> None:
        import psutil

        try:
            process = psutil.Process(pid)
            process.kill()
            process.wait(timeout=3)
        except Exception:
            pass


class FakeProcesses:
    def __init__(self, processes: list[tuple[int, str]] | None = None) -> None:
        self.processes = list(processes or [])
        self.calls: list[tuple[str, int]] = []

    def find(self, names: list[str]) -> list[tuple[int, str]]:
        self.calls.append(("find", 0))
        wanted = {name.casefold() for name in names}
        return [(pid, name) for pid, name in self.processes if name.casefold() in wanted]

    def request_close(self, pid: int) -> None:
        self.calls.append(("request_close", pid))
        self.processes = [item for item in self.processes if item[0] != pid]

    def is_running(self, pid: int) -> bool:
        return any(item[0] == pid for item in self.processes)

    def kill(self, pid: int) -> None:
        self.calls.append(("kill", pid))
        self.processes = [item for item in self.processes if item[0] != pid]


@dataclass
class HiddenItem:
    original: str
    hidden: str
    app: str
    kind: str

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "hidden": self.hidden,
            "app": self.app,
            "kind": self.kind,
        }


class AppHider:
    def __init__(
        self,
        paths: AppPaths | None = None,
        *,
        hide_names: list[str] | None = None,
        visible_names: set[str] | None = None,
        desktop_dirs: list[Path] | None = None,
        menus: list[Path] | None = None,
        recent: Path | None = None,
        jumps: list[Path] | None = None,
        hidden_dir: Path | None = None,
        processes: ProcessBackend | None = None,
        target_reader: Callable[[Path], str] = windows_shortcut_target,
        mover: Callable[[str, str], object] = shutil.move,
        close_timeout: float = 4.0,
    ) -> None:
        self.paths = paths or AppPaths.default()
        settings = read_config(self.paths)
        self.visible = {canonical_name(item) for item in (visible_names or settings.get("visible_apps") or VISIBLE_DEFAULT)}
        self.specs = default_specs(hide_names or settings.get("hide_apps") or HIDDEN_DEFAULT, self.visible)
        self.desktop_dirs = desktop_dirs if desktop_dirs is not None else self._desktop_dirs()
        self.menus = menus if menus is not None else start_menu_dirs()
        self.recent = recent if recent is not None else recent_dir()
        self.jumps = jumps if jumps is not None else jump_list_dirs()
        self.hidden_dir = hidden_dir or self.paths.hidden_links
        self.processes = processes or RealProcesses()
        self.target_reader = target_reader
        self.mover = mover or shutil.move
        self.close_timeout = close_timeout
        self.problems: list[str] = []

    @staticmethod
    def _desktop_dirs() -> list[Path]:
        home = Path(os.environ.get("USERPROFILE", str(Path.home())))
        options = [home / "Desktop", home / "OneDrive" / "Desktop", home / "Escritorio"]
        seen: list[Path] = []
        for path in options:
            if path.is_dir() and path not in seen:
                seen.append(path)
        if not seen:
            seen.append(home / "Desktop")
        return seen

    # -- manifiesto -------------------------------------------------------

    @property
    def manifest_path(self) -> Path:
        return self.paths.state / "hidden.json"

    def load_manifest(self) -> list[HiddenItem]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        items = []
        for raw in data.get("items", []) if isinstance(data, dict) else []:
            try:
                items.append(
                    HiddenItem(
                        original=str(raw["original"]),
                        hidden=str(raw["hidden"]),
                        app=str(raw["app"]),
                        kind=str(raw["kind"]),
                    )
                )
            except (KeyError, TypeError):
                continue
        return items

    def _save_manifest(self, items: list[HiddenItem]) -> None:
        payload = {"version": 1, "items": [item.to_dict() for item in items]}
        atomic_write_bytes(self.manifest_path, json.dumps(payload, indent=2).encode("utf-8"))

    # -- busqueda ---------------------------------------------------------

    def _shortcuts(self, folder: Path, recursive: bool) -> list[Path]:
        if not folder.is_dir():
            return []
        pattern = "**/*.lnk" if recursive else "*.lnk"
        return [path for path in folder.glob(pattern) if path.is_file()]

    def candidates(self) -> list[tuple[AppSpec, Path, str]]:
        found: list[tuple[AppSpec, Path, str]] = []
        seen: set[Path] = set()
        sources: list[tuple[Path, bool, str]] = []
        for folder in self.desktop_dirs:
            sources.append((folder, False, "escritorio"))
        for folder in self.menus:
            sources.append((folder, True, "inicio"))
        for folder, recursive, kind in sources:
            for path in self._shortcuts(folder, recursive):
                if path in seen:
                    continue
                seen.add(path)
                label = path.name
                target = ""
                try:
                    target = self.target_reader(path)
                except Exception:
                    target = ""
                for spec in self.specs:
                    if spec.matches(label) or (target and spec.matches(target)):
                        found.append((spec, path, kind))
                        break
        return found

    # -- ocultar / restaurar ---------------------------------------------

    def hide(self) -> dict[str, int]:
        self.problems = []
        items = self.load_manifest()
        known = {item.original for item in items}
        moved = 0
        for spec, source, kind in self.candidates():
            if str(source) in known:
                continue
            destination = self._destination(source, kind)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                self.mover(str(source), str(destination))
                items.append(HiddenItem(str(source), str(destination), spec.name, kind))
                known.add(str(source))
                moved += 1
            except OSError as exc:
                if self._is_program_data(source):
                    self.problems.append(f"{spec.name}: sin permiso en ProgramData")
                else:
                    self.problems.append(f"{spec.name}: no se pudo mover el acceso ({type(exc).__name__})")
        jumps = self.purge_jump_lists()
        recent = self.purge_recent()
        self._save_manifest(items)
        return {"moved": moved, "jump_lists": jumps, "recent": recent, "problems": len(self.problems)}

    def _destination(self, source: Path, kind: str) -> Path:
        base = self.hidden_dir / kind
        candidate = base / source.name
        index = 1
        while candidate.exists():
            candidate = base / f"{source.stem}-{index}{source.suffix}"
            index += 1
        return candidate

    @staticmethod
    def _is_program_data(path: Path) -> bool:
        root = os.environ.get("PROGRAMDATA")
        if not root:
            return False
        try:
            return os.path.commonpath([str(path).casefold(), root.casefold()]) == root.casefold()
        except ValueError:
            return False

    def restore(self) -> int:
        items = self.load_manifest()
        restored = 0
        remaining: list[HiddenItem] = []
        for item in items:
            hidden = Path(item.hidden)
            original = Path(item.original)
            if not hidden.exists():
                continue
            try:
                original.parent.mkdir(parents=True, exist_ok=True)
                if original.exists():
                    original = original.with_name(f"{original.stem}-recuperado{original.suffix}")
                self.mover(str(hidden), str(original))
                restored += 1
            except OSError:
                remaining.append(item)
        self._save_manifest(remaining)
        return restored

    # -- purgas -----------------------------------------------------------

    def purge_jump_lists(self) -> int:
        removed = 0
        for folder in self.jumps:
            if not folder.is_dir():
                continue
            for path in folder.glob("*.automaticDestinations-ms"):
                if self._jump_matches(path):
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        self.problems.append("lista de saltos bloqueada")
            for path in folder.glob("*.customDestinations-ms"):
                if self._jump_matches(path):
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        self.problems.append("lista de saltos bloqueada")
        return removed

    def _jump_matches(self, path: Path) -> bool:
        stem = path.name.split(".")[0].casefold()
        for spec in self.specs:
            if spec.matches(stem) or any(app_id.casefold() == stem for app_id in spec.app_ids):
                return True
        try:
            raw = path.read_bytes()[: 2 * 1024 * 1024]
        except OSError:
            return False
        haystacks = [raw.lower(), raw.decode("utf-16-le", "ignore").casefold().encode("utf-8")]
        for spec in self.specs:
            for pattern in spec.patterns:
                needle = pattern.casefold()
                if any(needle.encode("utf-8") in haystack for haystack in haystacks):
                    return True
        return False

    def purge_recent(self) -> int:
        if not self.recent.is_dir():
            return 0
        removed = 0
        for path in self.recent.glob("*.lnk"):
            label = path.name
            target = ""
            try:
                target = self.target_reader(path)
            except Exception:
                target = ""
            if any(spec.matches(label) or (target and spec.matches(target)) for spec in self.specs):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    self.problems.append("reciente bloqueado")
        return removed

    # -- procesos ---------------------------------------------------------

    def stop_processes(self) -> int:
        names: list[str] = []
        for spec in self.specs:
            if spec.close_on_cede:
                names.extend(spec.process_names)
        if not names:
            return 0
        found = self.processes.find(names)
        if not found:
            return 0
        for pid, _name in found:
            self.processes.request_close(pid)
        deadline = time.monotonic() + max(0.0, self.close_timeout)
        while time.monotonic() < deadline:
            if not any(self.processes.is_running(pid) for pid, _ in found):
                break
            time.sleep(0.1)
        for pid, _name in found:
            if self.processes.is_running(pid):
                self.processes.kill(pid)
        return len(found)

    # -- cesion -----------------------------------------------------------

    def apply_on_cede(self) -> dict[str, int]:
        stopped = self.stop_processes()
        result = self.hide()
        result["stopped"] = stopped
        return result
