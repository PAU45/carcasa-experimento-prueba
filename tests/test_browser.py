from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from carcasa.core import crypto
from carcasa.core.browser import (
    BackupScheduler,
    BrowserConfig,
    BrowserManager,
    FakeProcesses,
    SEED_VISITS,
)
from carcasa.core.paths import AppPaths
from carcasa.core.vault import Vault

FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def vault(tmp_path):
    instance, _ = Vault.create(tmp_path / "store", "482913", params=FAST, chunk_size=4096)
    yield instance
    instance.close()


def manager(vault, tmp_path, *, keep=3, minutes=10):
    config = BrowserConfig(
        executable=str(tmp_path / "chrome.exe"),
        public_user_data=tmp_path / "public-data",
        public_profile="Default",
        startup_urls=["https://ejemplo.test/uno", "https://ejemplo.test/dos"],
        backup_minutes=minutes,
        keep_backups=keep,
    )
    return BrowserManager(vault, AppPaths(tmp_path / "root"), config)


def test_choose_profile_matrix(vault, tmp_path):
    browser = manager(vault, tmp_path)
    assert browser.choose_profile(False) == "public"
    assert browser.choose_profile(False, "private") == "public"
    assert browser.choose_profile(True) == "private"
    assert browser.choose_profile(True, "private") == "private"
    assert browser.choose_profile(True, "public") == "public"


def test_launch_private_uses_vault_and_public_never_does(vault, tmp_path):
    browser = manager(vault, tmp_path)
    private = browser.launch_command(True)
    assert any(arg.startswith("--user-data-dir=") for arg in private)
    assert str(browser.private_user_data) in " ".join(private)
    assert "https://ejemplo.test/uno" in private

    public = browser.launch_command(False, url="https://ejemplo.test")
    assert not any(arg.startswith("--user-data-dir=") for arg in public)
    assert public[-1] == "https://ejemplo.test"


def test_private_profile_lives_inside_vault(vault, tmp_path):
    browser = manager(vault, tmp_path)
    profile = browser.prepare_private()
    assert vault.path in profile.parents
    assert profile.is_dir()


def test_sanitize_public_removes_accounts_but_keeps_history(vault, tmp_path):
    browser = manager(vault, tmp_path)
    profile = browser.public_profile_dir
    profile.mkdir(parents=True)
    (profile / "Cookies").write_bytes(b"cookie")
    (profile / "Login Data").write_bytes(b"login")
    (profile / "Bookmarks").write_text("{}", encoding="utf-8")
    (profile / "Sessions").mkdir()
    (profile / "Preferences").write_text(
        json.dumps({"account_info": [{"email": "x@y"}], "profile": {"name": "Angel"}}),
        encoding="utf-8",
    )
    (profile / "Local State").write_text(
        json.dumps({"google": {"services": {"last_account": "x"}}, "os_crypt": {"encrypted_key": "k"}}),
        encoding="utf-8",
    )
    browser.seed_history()

    result = browser.sanitize_public()
    assert result["removed"] >= 4
    assert not (profile / "Cookies").exists()
    assert not (profile / "Login Data").exists()
    assert not (profile / "Bookmarks").exists()
    assert not (profile / "Sessions").exists()
    prefs = json.loads((profile / "Preferences").read_text(encoding="utf-8"))
    assert "account_info" not in prefs
    assert prefs["profile"]["name"] == "Angel"
    assert browser.is_public_clean()
    assert browser.history_rows() == len(SEED_VISITS)


def test_seed_history_is_idempotent(vault, tmp_path):
    browser = manager(vault, tmp_path)
    assert browser.seed_history() == len(SEED_VISITS)
    assert browser.seed_history() == 0
    assert browser.history_rows() == len(SEED_VISITS)


def test_backup_and_restore(vault, tmp_path):
    browser = manager(vault, tmp_path)
    profile = browser.prepare_private()
    (profile / "Preferences").write_text(json.dumps({"ok": True}), encoding="utf-8")
    (profile / "Marcadores").write_text("privado", encoding="utf-8")
    name = browser.backup_now()
    assert name and name.startswith("perfil-")

    (profile / "Preferences").write_text("{ roto", encoding="utf-8")
    assert browser.is_corrupt(profile)
    assert browser.prepare_private()
    assert json.loads((profile / "Preferences").read_text(encoding="utf-8")) == {"ok": True}
    assert (profile / "Marcadores").read_text(encoding="utf-8") == "privado"


def test_restore_without_backups_keeps_working(vault, tmp_path):
    browser = manager(vault, tmp_path)
    browser.prepare_private()
    assert browser.latest_backup() is None
    assert browser.restore_latest() is False


def test_backup_rotation(vault, tmp_path):
    browser = manager(vault, tmp_path, keep=2)
    for index in range(4):
        vault.add_bytes(f"perfil-2026010{index}-000000.zip", b"x")
    browser._rotate_backups()
    remaining = [entry.name for entry in vault.entries() if entry.name.startswith("perfil-")]
    assert len(remaining) == 2


def test_backup_scheduler_uses_session_minutes(vault, tmp_path):
    clock = Clock()
    browser = manager(vault, tmp_path, minutes=10)
    browser.prepare_private()
    BrowserManager.backup_now(browser)
    scheduler = BackupScheduler(browser, clock=clock)
    assert scheduler.tick() is not None
    clock.now = 60
    assert scheduler.tick() is None
    clock.now = 601
    assert scheduler.tick() is not None


def test_close_private_orders_graceful_then_force(vault, tmp_path):
    processes = FakeProcesses([10, 20])
    browser = manager(vault, tmp_path)
    browser.processes = processes
    assert browser.close_private() == 2
    assert processes.calls[:2] == [("find", 0), ("request_close", 10)]
    assert ("request_close", 20) in processes.calls
    assert processes.pids == []


def test_close_private_forces_stubborn_process(vault, tmp_path):
    class Stubborn(FakeProcesses):
        def request_close(self, pid):
            self.calls.append(("request_close", pid))

    processes = Stubborn([7])
    browser = manager(vault, tmp_path)
    browser.processes = processes
    browser.sleep = lambda seconds: None
    assert browser.close_private(timeout=0) == 1
    assert ("kill", 7) in processes.calls
    assert processes.pids == []
