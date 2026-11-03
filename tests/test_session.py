from __future__ import annotations

import time

import pytest

from carcasa.core import crypto
from carcasa.core.errors import InvalidSecret, LockedOut
from carcasa.core.lockout import AttemptLimiter
from carcasa.core.paths import AppPaths
from carcasa.core.session import SessionManager

FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)
PIN = "482913"
DECOY = "111222"


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make(tmp_path, decoy=True):
    paths = AppPaths(tmp_path / "root")
    clock = Clock()
    limiter = AttemptLimiter(paths.state / "attempts.json", free_attempts=2, clock=clock)
    manager = SessionManager(paths, clock=clock, limiter=limiter)
    code = manager.create(PIN, decoy_pin=DECOY if decoy else None, params=FAST)
    return manager, paths, clock, code


def test_unlock_and_lock(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    assert crypto.is_valid_recovery_code(code)
    assert not manager.is_open
    assert manager.unlock(PIN) == "private"
    assert manager.is_open
    assert manager.status().mode == "private"
    assert paths.session_marker.exists()
    manager.lock()
    assert not manager.is_open
    assert not paths.session_marker.exists()


def test_wrong_pin_then_correct(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    with pytest.raises(InvalidSecret):
        manager.unlock("000000")
    assert manager.limiter.failures == 1
    assert manager.unlock(PIN) == "private"
    assert manager.limiter.failures == 0


def test_three_failures_lock_out(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    for _ in range(3):
        with pytest.raises(InvalidSecret):
            manager.unlock("000000")
    with pytest.raises(LockedOut) as error:
        manager.unlock(PIN)
    assert error.value.remaining > 0
    clock.advance(5)
    assert manager.unlock(PIN) == "private"


def test_decoy_pin_opens_decoy(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    assert manager.unlock(DECOY) == "decoy"
    assert manager.status().mode == "decoy"
    manager.lock()


def test_decoy_is_optional(tmp_path):
    manager, paths, clock, code = make(tmp_path, decoy=False)
    with pytest.raises(InvalidSecret):
        manager.unlock(DECOY)
    assert manager.unlock(PIN) == "private"


def test_open_is_idempotent(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    assert manager.unlock(PIN) == "private"
    assert manager.unlock("otra cosa") == "private"
    assert manager.limiter.failures == 0


def test_second_session_reads_same_vault(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    manager.unlock(PIN)
    manager.vault.add_bytes("nota.txt", b"hola")
    manager.lock()

    other = SessionManager(paths)
    assert other.unlock(PIN) == "private"
    assert [item.name for item in other.vault.entries()] == ["nota.txt"]
    other.lock()


def test_marker_survives_as_stale_and_can_be_cleared(tmp_path):
    manager, paths, clock, code = make(tmp_path)
    manager.unlock(PIN)
    paths.session_marker.write_text('{"open": true}', encoding="utf-8")
    fresh = SessionManager(paths)
    assert fresh.marker_pending()
    fresh.clear_stale_marker()
    assert not fresh.marker_pending()


def test_unlock_without_vault_raises(tmp_path):
    from carcasa.core.errors import VaultNotFound

    paths = AppPaths(tmp_path / "root")
    manager = SessionManager(paths)
    with pytest.raises(VaultNotFound):
        manager.unlock(PIN)
