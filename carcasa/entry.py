"""Lanzador sin consola. Se invoca desde Ejecutar con el nombre configurado.

No muestra nada si la sesion ya esta abierta. Si el demonio no vive, lo arranca.
El unico elemento visible es el cuadro de PIN, generico.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .core.ipc import ping, request, wait_ready
from .core.paths import AppPaths
from .core.pinbox import PinBox

MUTEX_NAME = "Local\\statcache-single"


def _acquire_single_instance():
    try:
        import win32api
        import win32event

        handle = win32event.CreateMutex(None, False, MUTEX_NAME)
        if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            return None
        return handle
    except Exception:
        return object()


def _daemon_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--daemon"]
    executable = Path(sys.executable)
    pythonw = executable.with_name("pythonw.exe")
    runner = pythonw if pythonw.is_file() else executable
    return [str(runner), "-m", "carcasa.daemon"]


def ensure_daemon(address: str, authkey: bytes) -> bool:
    if ping(address, authkey) is not None:
        return True
    creation = 0
    if os.name == "nt":
        creation = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )
    try:
        subprocess.Popen(
            _daemon_command(),
            cwd=str(Path(__file__).resolve().parents[1]),
            close_fds=True,
            creationflags=creation,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        return False
    return wait_ready(address, authkey)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--daemon" in argv:
        from .daemon import main as daemon_main

        return daemon_main()

    guard = _acquire_single_instance()
    if guard is None:
        return 0

    paths = AppPaths.default()
    paths.ensure()
    try:
        from .core.ipc import pipe_config

        address, authkey = pipe_config(paths)
    except Exception:
        return 1
    if not ensure_daemon(address, authkey):
        return 1

    state = ping(address, authkey)
    if not state or not state.get("initialized"):
        return 0
    if state.get("open"):
        return 0

    def verify(pin: str) -> bool:
        try:
            response = request(address, authkey, {"cmd": "unlock", "pin": pin})
            return bool(response.get("ok"))
        except Exception:
            return False

    PinBox(verify).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
