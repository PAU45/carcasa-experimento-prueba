"""Sesion privada: boveda principal, boveda senuelo y limite de intentos."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .errors import InvalidSecret, LockedOut, VaultNotFound, VaultRevoked
from .lockout import AttemptLimiter
from .paths import AppPaths
from .vault import Vault
from .winutil import atomic_write_bytes


@dataclass
class SessionStatus:
    open: bool
    mode: str | None
    since: str | None


class SessionManager:
    def __init__(
        self,
        paths: AppPaths | None = None,
        *,
        clock=time.time,
        limiter: AttemptLimiter | None = None,
    ) -> None:
        self.paths = paths or AppPaths.default()
        self.paths.ensure()
        self.clock = clock
        self.limiter = limiter or AttemptLimiter(self.paths.state / "attempts.json", clock=clock)
        self.vault: Vault | None = None
        self.mode: str | None = None
        self.since: str | None = None

    # -- construccion -----------------------------------------------------

    @property
    def decoy_path(self) -> Path:
        return self.paths.root / "decoy"

    def create(
        self,
        pin: str,
        *,
        decoy_pin: str | None = None,
        params: dict | None = None,
        chunk_size: int = crypto.DEFAULT_CHUNK,
    ) -> str:
        self.paths.ensure()
        vault, recovery = Vault.create(self.paths.vault, pin, params=params, chunk_size=chunk_size)
        vault.close()
        if decoy_pin:
            decoy, _ = Vault.create(self.decoy_path, decoy_pin, params=params, chunk_size=chunk_size)
            decoy.close()
        return recovery

    def has_vault(self) -> bool:
        return (self.paths.vault / "vault.hdr").is_file()

    def has_decoy(self) -> bool:
        return (self.decoy_path / "vault.hdr").is_file()

    # -- estado -----------------------------------------------------------

    def status(self) -> SessionStatus:
        return SessionStatus(self.vault is not None, self.mode, self.since)

    @property
    def is_open(self) -> bool:
        return self.vault is not None and self.vault.is_open

    # -- entrada / salida -------------------------------------------------

    def unlock(self, pin: str) -> str:
        if self.is_open:
            return self.mode or "private"
        remaining = self.limiter.remaining()
        if remaining > 0:
            raise LockedOut(remaining)
        if not self.has_vault():
            raise VaultNotFound("La boveda no existe.")

        vault: Vault | None = None
        mode = ""
        try:
            vault = Vault.open(self.paths.vault, pin)
            mode = "private"
        except (InvalidSecret, VaultRevoked):
            if self.has_decoy():
                try:
                    vault = Vault.open(self.decoy_path, pin)
                    mode = "decoy"
                except (InvalidSecret, VaultRevoked):
                    vault = None
        if vault is None:
            self.limiter.register_failure()
            raise InvalidSecret()

        self.limiter.reset()
        self.vault = vault
        self.mode = mode
        self.since = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._write_marker()
        return mode

    def lock(self) -> None:
        if self.vault is not None:
            try:
                self.vault.close()
            except Exception:
                pass
        self.vault = None
        self.mode = None
        self.since = None
        self._clear_marker()

    # -- marca de sesion --------------------------------------------------

    def _write_marker(self) -> None:
        payload = {
            "version": 1,
            "open": True,
            "since": self.since,
        }
        atomic_write_bytes(self.paths.session_marker, json.dumps(payload, sort_keys=True).encode("utf-8"))

    def _clear_marker(self) -> None:
        try:
            self.paths.session_marker.unlink()
        except OSError:
            pass

    def marker_pending(self) -> bool:
        return self.paths.session_marker.exists()

    def clear_stale_marker(self) -> None:
        if self.marker_pending() and not self.is_open:
            self._clear_marker()
