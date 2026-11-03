"""Rutas de la aplicacion.

El nombre de la carpeta es aburrido y configurable. Todo lo privado vive dentro
de la boveda; aqui solo hay estado no sensible (diario, instantaneas, copias de
accesos publicos) y la configuracion.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .winutil import atomic_write_bytes, is_windows

DEFAULT_FOLDER = "statcache"
DEFAULT_RUN_NAME = "wrun"
PUBLIC_PROJECT = Path("C:\\dev\\proyecto")


def local_appdata() -> Path:
    raw = os.environ.get("LOCALAPPDATA")
    if raw:
        return Path(raw)
    return Path.home() / "AppData" / "Local"


def roaming_appdata() -> Path:
    raw = os.environ.get("APPDATA")
    if raw:
        return Path(raw)
    return Path.home() / "AppData" / "Roaming"


@dataclass
class AppPaths:
    root: Path

    @classmethod
    def default(cls, folder: str | None = None) -> "AppPaths":
        config = read_config()
        name = folder or config.get("folder") or DEFAULT_FOLDER
        return cls(local_appdata() / name)

    @property
    def vault(self) -> Path:
        return self.root / "store"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def journal(self) -> Path:
        return self.state / "journal.json"

    @property
    def config_file(self) -> Path:
        return self.root / "settings.json"

    @property
    def pinned_public(self) -> Path:
        return self.state / "pinned-public"

    @property
    def pinned_private(self) -> Path:
        return self.root / "private-pins"

    @property
    def hidden_links(self) -> Path:
        return self.state / "links-ocultos"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def log(self) -> Path:
        return self.state / "activity.log"

    @property
    def session_marker(self) -> Path:
        return self.state / "session.json"

    def ensure(self) -> "AppPaths":
        for folder in (self.root, self.state):
            folder.mkdir(parents=True, exist_ok=True)
        return self


CONFIG_DEFAULTS = {
    "folder": DEFAULT_FOLDER,
    "run_name": DEFAULT_RUN_NAME,
    "public_project": str(PUBLIC_PROJECT),
    "hide_apps": [
        "Docker",
        "Gemini",
        "Antigravity",
        "GitHub Desktop",
        "OpenCode",
        "Trae",
    ],
    "visible_apps": ["VS Code", "Git", "Node"],
    "idle_seconds": 180,
    "cancel_ms": 500,
    "browser": {
        "public_executable": "",
        "private_executable": "",
        "private_args": [],
        "public_args": [],
    },
    "backup_minutes": 10,
    "usb_key_volume": "",
    "schedule": {"start": "07:00", "end": "22:00", "enabled": False},
    "log_encrypted": True,
}


def read_config(paths: AppPaths | None = None) -> dict:
    paths = paths or AppPaths(local_appdata() / DEFAULT_FOLDER)
    config = json.loads(json.dumps(CONFIG_DEFAULTS))
    try:
        raw = json.loads(paths.config_file.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            _merge(config, raw)
    except (OSError, ValueError):
        pass
    return config


def _merge(base: dict, extra: dict) -> None:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value


def write_config(config: dict, paths: AppPaths | None = None) -> None:
    paths = (paths or AppPaths.default()).ensure()
    payload = json.dumps(config, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write_bytes(paths.config_file, payload)


def public_desktop() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"


def start_menu_dirs() -> list[Path]:
    dirs = [
        roaming_appdata() / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        dirs.append(Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs")
    return dirs


def recent_dir() -> Path:
    return roaming_appdata() / "Microsoft" / "Windows" / "Recent"


def jump_list_dirs() -> list[Path]:
    base = recent_dir()
    return [base / "AutomaticDestinations", base / "CustomDestinations"]


def pinned_taskbar_dir() -> Path:
    return (
        roaming_appdata()
        / "Microsoft"
        / "Internet Explorer"
        / "Quick Launch"
        / "User Pinned"
        / "TaskBar"
    )


def not_indexed(paths: list[Path]) -> None:
    from .winutil import mark_not_indexed

    if is_windows():
        for path in paths:
            mark_not_indexed(path)
