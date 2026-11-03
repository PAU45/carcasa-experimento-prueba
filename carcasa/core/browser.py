"""Navegador: perfil publico limpio y perfil privado dentro de la boveda.

Reglas:
  * INV7: con la boveda cerrada, cualquier apertura cae en el perfil publico.
  * El perfil privado solo se usa si la boveda esta abierta.
  * El perfil privado se guarda cifrado como zip dentro de la boveda cada
    10 minutos de sesion y se restaura si se corrompe.
  * El cierre de la cesion es ordenado: primero se pide cerrar, luego se fuerza.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .errors import SessionError, VaultError
from .paths import AppPaths, local_appdata
from .session import SessionManager
from .winutil import secure_delete

SEED_VISITS = [
    ("https://docs.python.org/3/", "Python 3 documentation"),
    ("https://developer.mozilla.org/es/", "MDN Web Docs"),
    ("https://stackoverflow.com/questions", "Stack Overflow"),
    ("https://git-scm.com/doc", "Git documentation"),
    ("https://learn.microsoft.com/es-es/windows/", "Documentacion de Windows"),
]

ACCOUNT_FILES = (
    "Cookies",
    "Cookies-journal",
    "Login Data",
    "Login Data-journal",
    "Web Data",
    "Web Data-journal",
    "Bookmarks",
    "Bookmarks.bak",
    "Top Sites",
    "Top Sites-journal",
    "Favicons",
    "Favicons-journal",
    "Visited Links",
)

ACCOUNT_DIRS = ("Sessions", "Session Storage", "Local Storage", "IndexedDB", "Service Worker")

ACCOUNT_KEYS = ("account_info", "signin", "sync", "gaia_cookie", "google")

BROWSER_NAMES = {"chrome.exe", "msedge.exe", "chromium.exe", "brave.exe", "vivaldi.exe"}


def chrome_time(epoch: float | None = None) -> int:
    epoch = time.time() if epoch is None else epoch
    return int((epoch + 11_644_473_600) * 1_000_000)


def detect_executable() -> str | None:
    env = os.environ
    candidates = [
        Path(env.get("PROGRAMFILES", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(env.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(local_appdata()) / "Google/Chrome/Application/chrome.exe",
        Path(env.get("PROGRAMFILES", "C:\\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
        Path(env.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def detect_user_data_dir() -> Path:
    env = os.environ
    candidates = [
        local_appdata() / "Google/Chrome/User Data",
        local_appdata() / "Microsoft/Edge/User Data",
        local_appdata() / "Chromium/User Data",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[0]


@dataclass
class BrowserConfig:
    executable: str | None = None
    public_user_data: Path | None = None
    public_profile: str = "Default"
    private_args: list[str] = field(default_factory=lambda: ["--no-first-run", "--no-default-browser-check"])
    public_args: list[str] = field(default_factory=list)
    startup_urls: list[str] = field(default_factory=list)
    backup_minutes: int = 10
    keep_backups: int = 3

    @classmethod
    def from_settings(cls, settings: dict) -> "BrowserConfig":
        raw = settings.get("browser", {}) if isinstance(settings, dict) else {}
        public = raw.get("public_user_data")
        return cls(
            executable=raw.get("executable") or detect_executable(),
            public_user_data=Path(public) if public else detect_user_data_dir(),
            public_profile=str(raw.get("public_profile", "Default")),
            private_args=list(raw.get("private_args") or ["--no-first-run", "--no-default-browser-check"]),
            public_args=list(raw.get("public_args") or []),
            startup_urls=list(raw.get("startup_urls") or settings.get("ai_urls") or []),
            backup_minutes=int(settings.get("backup_minutes", 10) or 10),
            keep_backups=int(raw.get("keep_backups", 3) or 3),
        )


class ProcessBackend(Protocol):
    def find(self, marker: str) -> list[int]: ...
    def request_close(self, pid: int) -> None: ...
    def is_running(self, pid: int) -> bool: ...
    def kill(self, pid: int) -> None: ...


class RealProcesses:
    def find(self, marker: str) -> list[int]:
        import psutil

        needle = os.path.normcase(str(marker))
        pids = []
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (process.info.get("name") or "").casefold()
                if name not in BROWSER_NAMES:
                    continue
                command = os.path.normcase(" ".join(process.info.get("cmdline") or []))
                if needle in command:
                    pids.append(process.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return pids

    def request_close(self, pid: int) -> None:
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
    def __init__(self, pids: list[int] | None = None) -> None:
        self.pids = list(pids or [])
        self.calls: list[tuple[str, int]] = []

    def find(self, marker: str) -> list[int]:
        self.calls.append(("find", 0))
        return list(self.pids)

    def request_close(self, pid: int) -> None:
        self.calls.append(("request_close", pid))
        if pid in self.pids:
            self.pids.remove(pid)

    def is_running(self, pid: int) -> bool:
        return pid in self.pids

    def kill(self, pid: int) -> None:
        self.calls.append(("kill", pid))
        if pid in self.pids:
            self.pids.remove(pid)


class BrowserManager:
    def __init__(
        self,
        vault,
        paths: AppPaths | None = None,
        config: BrowserConfig | None = None,
        *,
        processes: ProcessBackend | None = None,
        clock=time.time,
        sleep=time.sleep,
    ) -> None:
        self.vault = vault
        self.paths = paths or AppPaths.default()
        self.config = config or BrowserConfig()
        self.processes = processes or RealProcesses()
        self.clock = clock
        self.sleep = sleep
        self._last_backup: float | None = None
        self._backup_name: str | None = None

    # -- perfiles ---------------------------------------------------------

    @property
    def public_profile_dir(self) -> Path:
        base = self.config.public_user_data or detect_user_data_dir()
        return Path(base) / self.config.public_profile

    @property
    def private_user_data(self) -> Path:
        if self.vault is None:
            raise SessionError("La boveda esta cerrada.")
        return self.vault.work_dir / "browser"

    @property
    def private_profile_dir(self) -> Path:
        return self.private_user_data / "Default"

    def choose_profile(self, vault_open: bool, requested: str | None = None) -> str:
        if not vault_open:
            return "public"
        if requested == "public":
            return "public"
        return "private"

    # -- lanzamiento ------------------------------------------------------

    def launch_command(self, vault_open: bool, *, url: str | None = None, requested: str | None = None) -> list[str]:
        profile = self.choose_profile(vault_open, requested)
        executable = self.config.executable or detect_executable()
        if not executable:
            raise SessionError("No se encontro el navegador.")
        if profile == "public":
            return [executable, *self.config.public_args, *([url] if url else [])]
        self.prepare_private()
        command = [
            executable,
            f"--user-data-dir={self.private_user_data}",
            f"--profile-directory={self.config.public_profile}",
            *self.config.private_args,
            *self.config.startup_urls,
        ]
        if url:
            command.append(url)
        return command

    def launch(self, vault_open: bool, *, url: str | None = None) -> subprocess.Popen:
        command = self.launch_command(vault_open, url=url)
        return subprocess.Popen(command, close_fds=True)

    # -- perfil privado ---------------------------------------------------

    def prepare_private(self) -> Path:
        if self.vault is None:
            raise SessionError("La boveda esta cerrada.")
        self.private_user_data.mkdir(parents=True, exist_ok=True)
        self.private_profile_dir.mkdir(parents=True, exist_ok=True)
        if self.is_corrupt(self.private_profile_dir):
            self.restore_latest()
        self._mark_ready()
        return self.private_profile_dir

    def _mark_ready(self) -> None:
        marker = self.private_user_data / "perfil.json"
        payload = {"version": 1, "ready": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def is_corrupt(self, profile_dir: Path | None = None) -> bool:
        profile_dir = Path(profile_dir or self.private_profile_dir)
        for name in ("Preferences", "Local State"):
            candidate = profile_dir / name
            if candidate.is_file():
                try:
                    json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, ValueError, UnicodeDecodeError):
                    return True
        return False

    # -- copias -----------------------------------------------------------

    def maybe_backup(self) -> str | None:
        if self.vault is None or not self.vault.is_open:
            return None
        now = self.clock()
        interval = max(1, int(self.config.backup_minutes)) * 60
        if self._last_backup is not None and now - self._last_backup < interval:
            return None
        return self.backup_now()

    def backup_now(self) -> str | None:
        if self.vault is None or not self.vault.is_open:
            raise SessionError("La boveda esta cerrada.")
        source = self.private_user_data
        if not source.is_dir():
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        name = f"perfil-{stamp}.zip"
        temporary = self.vault.work_dir / f".respaldo-{stamp}.zip"
        snapshot = self.vault.work_dir / f".respaldo-{stamp}"
        try:
            _snapshot_tree(source, snapshot)
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in snapshot.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(snapshot))
            existing = self.vault.find(name)
            if existing is None:
                self.vault.add_file(name, temporary)
            self._last_backup = self.clock()
            self._backup_name = name
            self._rotate_backups()
            return name
        finally:
            secure_delete(temporary)
            secure_delete(snapshot)

    def _rotate_backups(self) -> None:
        if self.vault is None:
            return
        backups = sorted(
            (entry for entry in self.vault.entries() if entry.name.startswith("perfil-") and entry.name.endswith(".zip")),
            key=lambda entry: entry.mtime,
        )
        keep = max(1, int(self.config.keep_backups))
        for entry in backups[:-keep]:
            self.vault.remove(entry.id)

    def latest_backup(self):
        if self.vault is None:
            return None
        backups = [
            entry
            for entry in self.vault.entries()
            if entry.name.startswith("perfil-") and entry.name.endswith(".zip")
        ]
        if not backups:
            return None
        return max(backups, key=lambda entry: entry.mtime)

    def restore_latest(self) -> bool:
        if self.vault is None:
            raise SessionError("La boveda esta cerrada.")
        entry = self.latest_backup()
        if entry is None:
            return False
        restore_root = self.vault.work_dir / ".restauracion"
        secure_delete(restore_root)
        restore_root.mkdir(parents=True, exist_ok=True)
        archive_path = self.vault.extract(entry.id, restore_root / "perfil.zip")
        target = restore_root / "contenido"
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    name = member.filename.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/"):
                        continue
                    archive.extract(member, target)
        except (OSError, zipfile.BadZipFile) as exc:
            secure_delete(restore_root)
            raise VaultError("La copia del perfil no es valida.") from exc
        if not target.is_dir():
            secure_delete(restore_root)
            raise VaultError("La copia del perfil esta vacia.")
        secure_delete(self.private_user_data)
        shutil.copytree(target, self.private_user_data)
        secure_delete(restore_root)
        self._mark_ready()
        return True

    # -- cierre -----------------------------------------------------------

    def close_private(self, *, timeout: float = 5.0) -> int:
        """Cierra el navegador privado de forma ordenada. No toca el publico."""
        marker = str(self.private_user_data)
        pids = self.processes.find(marker)
        if not pids:
            return 0
        for pid in pids:
            self.processes.request_close(pid)
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            if not any(self.processes.is_running(pid) for pid in pids):
                break
            self.sleep(0.1)
        remaining = [pid for pid in pids if self.processes.is_running(pid)]
        for pid in remaining:
            self.processes.kill(pid)
        return len(pids)

    # -- perfil publico ---------------------------------------------------

    def sanitize_public(self) -> dict[str, int]:
        """Quita cuentas, cookies y marcadores del perfil publico.

        No borra el historial: se conserva y, si falta, se siembra con
        documentacion y foros para que no parezca un perfil recien creado.
        """
        profile = self.public_profile_dir
        removed = 0
        for name in ACCOUNT_FILES:
            path = profile / name
            if path.is_file():
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        for name in ACCOUNT_DIRS:
            path = profile / name
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        for name in ("Preferences", "Local State"):
            path = profile / name
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            changed = _strip_accounts(data)
            if changed:
                path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        seeded = self.seed_history()
        return {"removed": removed, "seeded": seeded}

    def is_public_clean(self) -> bool:
        profile = self.public_profile_dir
        for name in ("Cookies", "Login Data", "Bookmarks"):
            if (profile / name).is_file():
                return False
        for name in ("Preferences", "Local State"):
            path = profile / name
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            if isinstance(data, dict) and _has_accounts(data):
                return False
        return True

    def history_rows(self) -> int:
        history = self.public_profile_dir / "History"
        if not history.is_file():
            return 0
        try:
            with sqlite3.connect(f"file:{history}?mode=ro", uri=True) as connection:
                return int(connection.execute("SELECT COUNT(*) FROM urls").fetchone()[0])
        except sqlite3.Error:
            return 0

    def seed_history(self) -> int:
        profile = self.public_profile_dir
        profile.mkdir(parents=True, exist_ok=True)
        history = profile / "History"
        if self.history_rows() > 0:
            return 0
        try:
            connection = sqlite3.connect(str(history))
        except sqlite3.Error:
            return 0
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS urls(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url LONGVARCHAR,
                    title LONGVARCHAR,
                    visit_count INTEGER DEFAULT 0 NOT NULL,
                    typed_count INTEGER DEFAULT 0 NOT NULL,
                    last_visit_time INTEGER NOT NULL,
                    hidden INTEGER DEFAULT 0 NOT NULL
                );
                CREATE TABLE IF NOT EXISTS visits(
                    id INTEGER PRIMARY KEY,
                    url INTEGER NOT NULL,
                    visit_time INTEGER NOT NULL,
                    from_visit INTEGER,
                    transition INTEGER DEFAULT 0 NOT NULL,
                    segment_id INTEGER,
                    visit_duration INTEGER DEFAULT 0 NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
                """
            )
            now = chrome_time()
            count = 0
            for index, (url, title) in enumerate(SEED_VISITS):
                cursor = connection.execute(
                    "INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?,?,?,?,?,0)",
                    (url, title, 1, 0, now - index * 60_000_000),
                )
                connection.execute(
                    "INSERT INTO visits(url, visit_time, transition, visit_duration) VALUES (?,?,0,0)",
                    (cursor.lastrowid, now - index * 60_000_000),
                )
                count += 1
            connection.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('version', '1')"
            )
            connection.commit()
            return count
        except sqlite3.Error:
            return 0
        finally:
            connection.close()


def _strip_accounts(data: dict) -> bool:
    changed = False
    for key in list(data.keys()):
        lowered = key.casefold()
        if any(needle in lowered for needle in ACCOUNT_KEYS):
            del data[key]
            changed = True
        elif isinstance(data[key], dict):
            changed = _strip_accounts(data[key]) or changed
    return changed


def _has_accounts(data: dict) -> bool:
    for key, value in data.items():
        lowered = str(key).casefold()
        if any(needle in lowered for needle in ("account_info", "signin", "gaia_cookie")):
            return True
        if isinstance(value, dict) and _has_accounts(value):
            return True
    return False


def _snapshot_tree(source: Path, target: Path) -> None:
    """Copia el perfil evitando caches y archivos bloqueados."""
    skip = {"Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache", "DawnCache"}
    target.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(source):
        relative = Path(root).relative_to(source)
        if any(part in skip for part in relative.parts):
            dirs[:] = []
            continue
        destination = target / relative
        destination.mkdir(parents=True, exist_ok=True)
        for name in files:
            try:
                shutil.copy2(Path(root) / name, destination / name)
            except OSError:
                continue


class BackupScheduler:
    """Copia cada N minutos de sesion. Reloj inyectable para tests."""

    def __init__(self, manager: BrowserManager, clock=time.monotonic) -> None:
        self.manager = manager
        self.clock = clock
        self.last: float | None = None

    def tick(self) -> str | None:
        if self.manager.vault is None:
            return None
        interval = max(1, int(self.manager.config.backup_minutes)) * 60
        now = self.clock()
        if self.last is not None and now - self.last < interval:
            return None
        name = self.manager.backup_now()
        if name:
            self.last = now
        return name
