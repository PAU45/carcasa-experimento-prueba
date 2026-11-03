"""Canal local entre el lanzador y el demonio.

Es una tuberia con nombre de Windows: no abre puertos, no usa la red y solo
acepta conexiones del mismo usuario.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path
from typing import Callable

from multiprocessing.connection import Client, Listener

from .paths import AppPaths
from .winutil import atomic_write_bytes


def pipe_config(paths: AppPaths) -> tuple[str, bytes]:
    paths.ensure()
    config_path = paths.state / "pipe.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        address = str(data["address"])
        authkey = bytes.fromhex(str(data["authkey"]))
        if address and authkey:
            return address, authkey
    except (OSError, ValueError, KeyError, TypeError):
        pass
    token = secrets.token_hex(16)
    address = rf"\\.\pipe\{token}"
    authkey = secrets.token_bytes(32)
    payload = json.dumps({"address": address, "authkey": authkey.hex()}, sort_keys=True)
    atomic_write_bytes(config_path, payload.encode("utf-8"))
    return address, authkey


class IpcServer:
    def __init__(self, address: str, authkey: bytes, handler: Callable[[dict], dict]) -> None:
        self.address = address
        self.authkey = authkey
        self.handler = handler
        self._listener: Listener | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._listener = Listener(self.address, family="AF_PIPE", authkey=self.authkey)
        self._thread = threading.Thread(target=self._serve, name="ipc", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection = self._listener.accept()
            except (OSError, EOFError):
                break
            with connection:
                try:
                    message = connection.recv()
                    response = self.handler(message)
                    connection.send(response)
                except Exception:
                    try:
                        connection.send({"ok": False, "reason": "error"})
                    except Exception:
                        pass

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except Exception:
                pass
            self._listener = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


def request(address: str, authkey: bytes, payload: dict, *, timeout: float = 3.0) -> dict:
    connection = Client(address, family="AF_PIPE", authkey=authkey)
    try:
        connection.send(payload)
        if not connection.poll(timeout):
            raise TimeoutError("sin respuesta")
        response = connection.recv()
        if not isinstance(response, dict):
            raise ValueError("respuesta invalida")
        return response
    finally:
        try:
            connection.close()
        except Exception:
            pass


def ping(address: str, authkey: bytes, *, timeout: float = 0.6) -> dict | None:
    try:
        return request(address, authkey, {"cmd": "ping"}, timeout=timeout)
    except Exception:
        return None


def wait_ready(address: str, authkey: bytes, *, timeout: float = 6.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ping(address, authkey, timeout=0.4) is not None:
            return True
        time.sleep(0.05)
    return False
