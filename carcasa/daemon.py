"""Demonio local: mantiene la sesion privada y atiende al lanzador.

Sin ventana, sin bandeja, sin red. El proceso se llama como un servicio
generico y no escribe nada en consola.
"""

from __future__ import annotations

import threading
import time

from .core.errors import InvalidSecret, LockedOut
from .core.ipc import IpcServer, pipe_config
from .core.paths import AppPaths
from .core.session import SessionManager


class Daemon:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or AppPaths.default()
        self.paths.ensure()
        self.session = SessionManager(self.paths)
        self.address, self.authkey = pipe_config(self.paths)
        self.server = IpcServer(self.address, self.authkey, self.handle)
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def handle(self, message: dict) -> dict:
        if not isinstance(message, dict):
            return {"ok": False, "reason": "bad"}
        command = str(message.get("cmd", ""))
        if command == "ping":
            return {
                "ok": True,
                "open": self.session.is_open,
                "initialized": self.session.has_vault(),
            }
        if command == "status":
            status = self.session.status()
            return {
                "ok": True,
                "open": status.open,
                "mode": status.mode,
                "initialized": self.session.has_vault(),
            }
        if command == "unlock":
            pin = str(message.get("pin", ""))
            with self._lock:
                try:
                    mode = self.session.unlock(pin)
                    return {"ok": True, "mode": mode}
                except LockedOut as exc:
                    return {"ok": False, "reason": "wait", "remaining": exc.remaining}
                except InvalidSecret:
                    return {"ok": False, "reason": "denied"}
                except Exception:
                    return {"ok": False, "reason": "error"}
        if command == "lock":
            with self._lock:
                self.session.lock()
            return {"ok": True}
        if command == "quit":
            self._stop.set()
            return {"ok": True}
        return {"ok": False, "reason": "unknown"}

    def start(self) -> None:
        self.session.clear_stale_marker()
        self.server.start()

    def wait(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.25)

    def stop(self) -> None:
        self._stop.set()
        self.server.stop()
        with self._lock:
            self.session.lock()


def main() -> int:
    daemon = Daemon()
    daemon.start()
    try:
        daemon.wait()
    except KeyboardInterrupt:
        pass
    finally:
        daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
