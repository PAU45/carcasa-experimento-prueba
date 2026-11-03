from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from carcasa.core import crypto
from carcasa.core.errors import PathNotAllowed, ScrubError, VaultRevoked
from carcasa.core.paths import AppPaths
from carcasa.core.registry import MemoryRegistry
from carcasa.core.runentry import RUN_MRU, RunEntry
from carcasa.core.scrub import Scrubber, WORDWHEEL
from carcasa.core.vault import Vault

FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)
PIN = "482913"


class FakeHider:
    def __init__(self) -> None:
        self.problems = []

    def purge_jump_lists(self) -> int:
        return 2

    def purge_recent(self) -> int:
        return 1


def build(tmp_path, *, vault=None, clipboard=True):
    paths = AppPaths(tmp_path / "root")
    paths.ensure()
    recent = tmp_path / "Recent"
    recent.mkdir()
    thumbs = tmp_path / "Thumbs"
    thumbs.mkdir()
    registry = MemoryRegistry()
    run = RunEntry(paths, registry, which=lambda name: None)
    scrubber = Scrubber(
        paths,
        registry=registry,
        run_entry=run,
        hider=FakeHider(),
        vault=vault,
        recent=recent,
        thumbnail_dir=thumbs,
        clipboard_clear=lambda: clipboard,
    )
    return scrubber, paths, registry, recent, thumbs, run


def test_level1_only_locks(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    (recent / "algo.lnk").write_bytes(b"x")
    report = scrubber.run(1)
    assert report.level == 1
    assert (recent / "algo.lnk").exists()
    assert report.recent == 0


def test_recent_purge_only_touches_session_window(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    old = recent / "viejo.lnk"
    fresh = recent / "nuevo.lnk"
    old.write_bytes(b"a")
    fresh.write_bytes(b"b")
    old_time = 1_600_000_000
    os.utime(old, (old_time, old_time))
    start = time.time()
    report = scrubber.run(2, session_start=start - 30)
    assert report.recent >= 1
    assert old.exists()
    assert not fresh.exists()


def test_run_mru_and_typed_paths(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    registry.write_value("HKCU", RUN_MRU, "a", "proyecto\\1")
    registry.write_value("HKCU", RUN_MRU, "b", "wrun\\1")
    registry.write_value("HKCU", RUN_MRU, "MRUList", "ab")
    registry.write_value("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "url1", "wrun")
    report = scrubber.run(2)
    assert report.run_entries == 2
    values = registry.read_values("HKCU", RUN_MRU)
    assert values["MRUList"].data == "a"


def test_search_history_removes_only_app_entries(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    registry.write_value("HKCU", WORDWHEEL, "0", "wrun".encode("utf-16-le"), 3)
    registry.write_value("HKCU", WORDWHEEL, "1", "proyecto".encode("utf-16-le"), 3)
    registry.write_value("HKCU", WORDWHEEL, "MRUList", "01", 1)
    report = scrubber.run(2, session_start=time.time())
    assert report.search == 1
    values = registry.read_values("HKCU", WORDWHEEL)
    assert set(values) == {"1", "MRUList"}
    assert values["MRUList"].data == "1"


def test_clipboard_and_thumbnails(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    (thumbs / "thumbcache_1.db").write_bytes(b"x")
    (thumbs / "iconcache_1.db").write_bytes(b"x")
    (thumbs / "otra.db").write_bytes(b"x")
    report = scrubber.run(2, session_start=time.time())
    assert report.clipboard is True
    assert report.thumbnails == 2
    assert not (thumbs / "thumbcache_1.db").exists()
    assert (thumbs / "otra.db").exists()


def test_vault_trash_is_emptied(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    try:
        trash = vault.work_dir / "trash"
        trash.mkdir()
        (trash / "viejo.bin").write_bytes(b"x")
        scrubber, paths, registry, recent, thumbs, run = build(tmp_path, vault=vault)
        report = scrubber.run(2, session_start=time.time())
        assert report.trash >= 1
        assert not (trash / "viejo.bin").exists()
    finally:
        vault.close()


def test_level3_shreds_own_temps_and_private_cache(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    try:
        profile = vault.work_dir / "browser" / "Default"
        (profile / "Cache").mkdir(parents=True)
        (profile / "Cache" / "datos").write_bytes(b"x")
        (profile / "Preferences").write_text("{}", encoding="utf-8")
        paths = AppPaths(tmp_path / "root")
        paths.ensure()
        paths.tmp.mkdir()
        (paths.tmp / "temporal.bin").write_bytes(b"x")
        scrubber = Scrubber(paths, vault=vault, private_profile_dir=profile, clipboard_clear=lambda: True)
        report = scrubber.run(3, session_start=time.time())
        assert report.temps >= 1
        assert report.cache == 1
        assert not (profile / "Cache").exists()
        assert (profile / "Preferences").exists()
    finally:
        vault.close()


def test_level4_requires_manual_or_usb(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    try:
        scrubber, paths, registry, recent, thumbs, run = build(tmp_path, vault=vault)
        with pytest.raises(ScrubError):
            scrubber.run(4, reason="inactividad")
        assert not vault.is_revoked
    finally:
        vault.close()


def test_level4_revokes_pin_and_recovery_restores(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path, vault=vault)
    report = scrubber.run(4, reason="manual", session_start=time.time())
    assert report.revoked is True
    assert vault.is_revoked
    vault.close()
    with pytest.raises(VaultRevoked):
        Vault.open(tmp_path / "store", PIN)
    with Vault.open(tmp_path / "store", code) as recovered:
        assert recovered.is_open


def test_level4_works_with_closed_vault(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    vault.close()
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path, vault=vault)
    assert scrubber.run(4, reason="usb", session_start=time.time()).revoked
    with pytest.raises(VaultRevoked):
        Vault.open(tmp_path / "store", PIN)
    with Vault.open(tmp_path / "store", code) as recovered:
        assert recovered.is_open


def test_deletion_outside_allowed_roots_is_refused(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    with pytest.raises(PathNotAllowed):
        scrubber._safe_delete(tmp_path / "otro" / "archivo.txt")
    with pytest.raises(PathNotAllowed):
        scrubber._safe_delete(Path("C:\\dev\\proyecto\\x.txt"))


def test_log_hashes_paths(tmp_path):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    secret = recent / "nombre-secreto.lnk"
    secret.write_bytes(b"x")
    scrubber.log("prueba", secret)
    text = paths.log.read_text(encoding="utf-8")
    assert "nombre-secreto" not in text
    assert "h=" in text


def test_admin_artifacts_never_fails(tmp_path, monkeypatch):
    scrubber, paths, registry, recent, thumbs, run = build(tmp_path)
    monkeypatch.setenv("WINDIR", str(tmp_path / "Windows"))
    assert scrubber.admin_artifacts() == []
