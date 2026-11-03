from __future__ import annotations

import os
import uuid

import pytest

from carcasa.core import crypto
from carcasa.core.ipc import IpcServer, request, wait_ready
from carcasa.core.paths import AppPaths
from carcasa.core.session import SessionManager
from carcasa.daemon import Daemon

FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)
PIN = "482913"


def make_daemon(tmp_path):
    paths = AppPaths(tmp_path / "root")
    paths.ensure()
    manager = SessionManager(paths)
    manager.create(PIN, params=FAST)
    daemon = Daemon(paths)
    return daemon, paths


def test_daemon_ping_and_status(tmp_path):
    daemon, paths = make_daemon(tmp_path)
    assert daemon.handle({"cmd": "ping"}) == {"ok": True, "open": False, "initialized": True}
    assert daemon.handle({"cmd": "status"})["mode"] is None


def test_daemon_unlock_lock(tmp_path):
    daemon, paths = make_daemon(tmp_path)
    response = daemon.handle({"cmd": "unlock", "pin": PIN})
    assert response == {"ok": True, "mode": "private"}
    assert daemon.session.is_open
    assert daemon.handle({"cmd": "status"})["open"] is True
    assert daemon.handle({"cmd": "lock"}) == {"ok": True}
    assert not daemon.session.is_open


def test_daemon_denies_wrong_pin(tmp_path):
    daemon, paths = make_daemon(tmp_path)
    assert daemon.handle({"cmd": "unlock", "pin": "000000"})["ok"] is False
    assert daemon.handle({"cmd": "unlock", "pin": "000000"})["reason"] == "denied"


def test_daemon_handles_garbage(tmp_path):
    daemon, paths = make_daemon(tmp_path)
    assert daemon.handle("no").get("ok") is False
    assert daemon.handle({"cmd": "nada"}).get("ok") is False


@pytest.mark.windows
def test_ipc_roundtrip():
    address = rf"\\.\pipe\test-{uuid.uuid4().hex}"
    authkey = os.urandom(32)

    def handler(message):
        return {"ok": True, "echo": message.get("cmd")}

    server = IpcServer(address, authkey, handler)
    server.start()
    try:
        assert wait_ready(address, authkey, timeout=2)
        assert request(address, authkey, {"cmd": "hola"}) == {"ok": True, "echo": "hola"}
    finally:
        server.stop()
