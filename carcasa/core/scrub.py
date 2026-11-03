"""Purga por niveles independientes.

  L1  solo bloqueo.
  L2  recientes, listas de saltos, RunMRU, TypedPaths, busqueda del Explorador,
      portapapeles, miniaturas y papelera de la boveda.
  L3  L2 + borrado seguro de temporales propios y cache del perfil privado.
  L4  L3 + revocacion de la clave del PIN. Solo manual o por USB, nunca por
      inactividad. El codigo de recuperacion sigue permitiendo entrar.

Todo borrado pasa por una lista de raices permitidas y rechaza el proyecto
publico (INV3). Prefetch y Amcache solo se detectan: requieren administrador.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .apphide import AppHider
from .errors import PathNotAllowed, ScrubError
from .paths import AppPaths, local_appdata, recent_dir
from .registry import Registry, get_default_registry
from .runentry import RunEntry
from .vault import Vault, revoke_pin_on_disk
from .winutil import is_windows, secure_delete

WORDWHEEL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
CACHE_DIRS = ("Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache", "DawnCache")
PROTECTED = "c:\\dev\\proyecto"


@dataclass
class ScrubReport:
    level: int
    recent: int = 0
    jump_lists: int = 0
    run_entries: int = 0
    search: int = 0
    clipboard: bool = False
    thumbnails: int = 0
    trash: int = 0
    temps: int = 0
    cache: int = 0
    revoked: bool = False
    admin: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "recent": self.recent,
            "jump_lists": self.jump_lists,
            "run_entries": self.run_entries,
            "search": self.search,
            "clipboard": self.clipboard,
            "thumbnails": self.thumbnails,
            "trash": self.trash,
            "temps": self.temps,
            "cache": self.cache,
            "revoked": self.revoked,
            "admin": list(self.admin),
            "problems": list(self.problems),
        }


def clear_clipboard() -> bool:
    if not is_windows():
        return False
    try:
        user32 = ctypes.windll.user32
        for _ in range(5):
            if user32.OpenClipboard(None):
                user32.EmptyClipboard()
                user32.CloseClipboard()
                return True
            time.sleep(0.01)
    except Exception:
        return False
    return False


def _decode_reg(data) -> str:
    if isinstance(data, bytes):
        for encoding in ("utf-16-le", "utf-8", "latin-1"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return ""
    return str(data)


class Scrubber:
    def __init__(
        self,
        paths: AppPaths | None = None,
        *,
        registry: Registry | None = None,
        run_entry: RunEntry | None = None,
        hider: AppHider | None = None,
        vault: Vault | None = None,
        recent: Path | None = None,
        thumbnail_dir: Path | None = None,
        private_profile_dir: Path | None = None,
        vault_trash: Path | None = None,
        clipboard_clear: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.paths = (paths or AppPaths.default()).ensure()
        self.registry = registry or get_default_registry()
        self.run_entry = run_entry or RunEntry(self.paths, self.registry)
        self.hider = hider
        self.vault = vault
        self.recent = Path(recent) if recent else recent_dir()
        self.thumbnail_dir = Path(thumbnail_dir) if thumbnail_dir else local_appdata() / "Microsoft/Windows/Explorer"
        self.clipboard_clear = clipboard_clear or clear_clipboard
        self.clock = clock
        self.private_profile_dir = (
            Path(private_profile_dir)
            if private_profile_dir is not None
            else (vault.work_dir / "browser" / "Default" if vault is not None else None)
        )
        self.vault_trash = (
            Path(vault_trash)
            if vault_trash is not None
            else (vault.work_dir / "trash" if vault is not None else None)
        )
        self.problems: list[str] = []

    # -- API --------------------------------------------------------------

    def run(self, level: int, *, reason: str = "manual", session_start: float | None = None) -> ScrubReport:
        if level not in (1, 2, 3, 4):
            raise ScrubError("Nivel no valido.")
        report = ScrubReport(level=level)
        self.problems = []
        if level == 1:
            report.problems = tuple(self.problems)
            return report
        if level == 4:
            if reason not in ("manual", "usb"):
                raise ScrubError("El nivel 4 solo se ejecuta a mano o con la llave USB.")
            report.revoked = self.revoke()
        start = self.clock() if session_start is None else float(session_start)
        self._l2(report, start)
        if level >= 3:
            self._l3(report)
        report.admin = tuple(self.admin_artifacts())
        report.problems = tuple(self.problems)
        return report

    # -- L2 ---------------------------------------------------------------

    def _l2(self, report: ScrubReport, start: float) -> None:
        report.recent = self.purge_recent(start)
        if self.hider is not None:
            report.jump_lists = self.hider.purge_jump_lists()
            report.recent += self.hider.purge_recent()
            self.problems.extend(self.hider.problems)
        report.run_entries = self.run_entry.purge_run_mru() + self.run_entry.purge_typed_paths()
        report.search = self.purge_search_history()
        report.clipboard = bool(self.clipboard_clear())
        report.thumbnails = self.purge_thumbnails()
        report.trash = self.purge_vault_trash()

    def purge_recent(self, session_start: float) -> int:
        if not self.recent.is_dir():
            return 0
        limit = float(session_start) - 2.0
        removed = 0
        for path in self.recent.iterdir():
            if not path.is_file() or path.suffix.casefold() != ".lnk":
                continue
            try:
                if path.stat().st_mtime < limit:
                    continue
            except OSError:
                continue
            try:
                self._safe_delete(path)
                removed += 1
            except (OSError, PathNotAllowed):
                self.problems.append("reciente no borrado")
        return removed

    def purge_search_history(self) -> int:
        values = self.registry.read_values("HKCU", WORDWHEEL)
        if not values:
            return 0
        needles = self._needles()
        removed: set[str] = set()
        for name, value in values.items():
            if name == "MRUList":
                continue
            text = _decode_reg(value.data).casefold()
            if any(needle in text for needle in needles):
                removed.add(name)
        for name in removed:
            self.registry.delete_value("HKCU", WORDWHEEL, name)
        order_value = values.get("MRUList")
        if order_value is not None and removed:
            order = _decode_reg(order_value.data)
            new_order = "".join(ch for ch in order if ch not in removed)
            self.registry.write_value("HKCU", WORDWHEEL, "MRUList", new_order, order_value.kind)
        return len(removed)

    def _needles(self) -> set[str]:
        names = {self.run_entry._configured_name(), self.paths.root.name}
        return {name.casefold() for name in names if name}

    def purge_thumbnails(self) -> int:
        if not self.thumbnail_dir.is_dir():
            return 0
        removed = 0
        for pattern in ("thumbcache_*.db", "iconcache_*.db"):
            for path in self.thumbnail_dir.glob(pattern):
                try:
                    self._safe_delete(path)
                    removed += 1
                except (OSError, PathNotAllowed):
                    self.problems.append("cache de miniaturas en uso")
        return removed

    def purge_vault_trash(self) -> int:
        if self.vault_trash is None or not self.vault_trash.is_dir():
            return 0
        removed = 0
        for path in list(self.vault_trash.iterdir()):
            removed += 1 if path.is_file() else max(1, len(list(path.rglob("*"))))
            try:
                self._safe_delete(path)
            except (OSError, PathNotAllowed):
                self.problems.append("papelera de la boveda bloqueada")
        return removed

    # -- L3 ---------------------------------------------------------------

    def _l3(self, report: ScrubReport) -> None:
        report.temps = self.shred_own_temps()
        report.cache = self.shred_private_cache()

    def shred_own_temps(self) -> int:
        removed = 0
        tmp = self.paths.tmp
        if tmp.is_dir():
            removed += self._clear_folder(tmp)
        state = self.paths.state
        if state.is_dir():
            for path in state.glob("*.tmp"):
                try:
                    self._safe_delete(path)
                    removed += 1
                except (OSError, PathNotAllowed):
                    self.problems.append("temporal propio en uso")
        if self.vault is not None:
            work = self.vault.work_dir
            for pattern in (".respaldo-*", ".restauracion", "*.part"):
                for path in work.glob(pattern):
                    try:
                        self._safe_delete(path)
                        removed += 1
                    except (OSError, PathNotAllowed):
                        self.problems.append("temporal de la boveda en uso")
        return removed

    def shred_private_cache(self) -> int:
        profile = self.private_profile_dir
        if profile is None or not profile.is_dir():
            return 0
        removed = 0
        for name in CACHE_DIRS:
            folder = profile / name
            if folder.is_dir():
                try:
                    self._safe_delete(folder)
                    removed += 1
                except (OSError, PathNotAllowed):
                    self.problems.append("cache del perfil privado en uso")
        return removed

    def _clear_folder(self, folder: Path) -> int:
        count = 0
        for path in list(folder.iterdir()):
            try:
                self._safe_delete(path)
                count += 1
            except (OSError, PathNotAllowed):
                self.problems.append("temporal propio en uso")
        return count

    # -- L4 ---------------------------------------------------------------

    def revoke(self) -> bool:
        if self.vault is not None and self.vault.is_open:
            self.vault.revoke_pin()
            return True
        target = self.vault.path if self.vault is not None else self.paths.vault
        if (Path(target) / "vault.hdr").is_file():
            revoke_pin_on_disk(target)
            return True
        raise ScrubError("No hay boveda que revocar.")

    # -- admin ------------------------------------------------------------

    def admin_artifacts(self) -> list[str]:
        messages: list[str] = []
        try:
            prefetch = Path(os.environ.get("WINDIR", "C:\\Windows")) / "Prefetch"
            wanted = {"docker", "gemini", "antigravity", "githubdesktop", "opencode", "trae"}
            if prefetch.is_dir():
                hits = [
                    path
                    for path in prefetch.glob("*.pf")
                    if any(word in path.name.casefold() for word in wanted)
                ]
                if hits:
                    messages.append("Prefetch: requiere administrador")
        except OSError:
            pass
        try:
            amcache = Path(os.environ.get("WINDIR", "C:\\Windows")) / "AppCompat/Programs/Amcache.hve"
            if amcache.is_file():
                messages.append("Amcache: requiere administrador")
        except OSError:
            messages.append("Amcache: requiere administrador")
        return messages

    # -- guardas ----------------------------------------------------------

    def _allowed_roots(self) -> list[str]:
        roots = [self.paths.root]
        if self.recent:
            roots.append(self.recent)
        if self.thumbnail_dir:
            roots.append(self.thumbnail_dir)
        if self.private_profile_dir is not None:
            roots.append(self.private_profile_dir)
        if self.vault_trash is not None:
            roots.append(self.vault_trash)
        if self.vault is not None:
            roots.append(self.vault.path)
        return [os.path.normcase(os.path.abspath(str(root))) for root in roots]

    def _safe_delete(self, path: Path) -> None:
        text = os.path.normcase(os.path.abspath(str(path)))
        if text == PROTECTED or text.startswith(PROTECTED + os.sep):
            raise PathNotAllowed("ruta protegida")
        allowed = self._allowed_roots()
        if not any(text == root or text.startswith(root + os.sep) for root in allowed):
            raise PathNotAllowed("ruta fuera de lo permitido")
        secure_delete(path)

    # -- registro ---------------------------------------------------------

    def log(self, action: str, path: Path | None = None) -> None:
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {action}"
        if path is not None:
            digest = hashlib.sha256(os.path.normcase(str(path)).encode("utf-8", "ignore")).hexdigest()[:12]
            line += f" h={digest}"
        try:
            self.paths.log.parent.mkdir(parents=True, exist_ok=True)
            with open(self.paths.log, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass
