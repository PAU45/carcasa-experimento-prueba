from __future__ import annotations

import pytest

from carcasa.core.paths import AppPaths
from carcasa.core.registry import MemoryRegistry
from carcasa.core.runentry import (
    APP_PATHS,
    RUN_MRU,
    TYPED_PATHS,
    NameCollision,
    NameRejected,
    RunEntry,
    validate_name,
)


def make(tmp_path, which=lambda name: None):
    paths = AppPaths(tmp_path / "root")
    paths.ensure()
    registry = MemoryRegistry()
    entry = RunEntry(paths, registry, which=which)
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    return entry, registry, exe, paths


def test_install_writes_only_hkcu_app_paths(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    name = entry.install(exe, "wrun")
    assert name == "wrun"
    value = registry.read_value("HKCU", f"{APP_PATHS}\\wrun.exe", "")
    assert value is not None and value.data == str(exe.resolve())
    assert entry.is_installed("wrun")
    assert entry.collision("wrun") is None  # es nuestra propia entrada


def test_reinstall_rewrites(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    entry.install(exe, "wrun")
    other = tmp_path / "otro.exe"
    other.write_bytes(b"MZ")
    entry.install(other, "wrun")
    assert registry.read_value("HKCU", f"{APP_PATHS}\\wrun.exe", "").data == str(other.resolve())


def test_uninstall_removes(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    entry.install(exe, "wrun")
    entry.uninstall("wrun")
    assert not registry.key_exists("HKCU", f"{APP_PATHS}\\wrun.exe")
    assert not entry.is_installed("wrun")


def test_collision_with_existing_app_path_is_rejected(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    registry.write_value("HKCU", f"{APP_PATHS}\\wrun.exe", "", "C:\\otra\\wrun.exe")
    with pytest.raises(NameCollision):
        entry.install(exe, "wrun")


def test_collision_is_case_insensitive(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    registry.write_value("HKCU", f"{APP_PATHS}\\WRUN.exe", "", "C:\\otra\\wrun.exe")
    with pytest.raises(NameCollision):
        entry.install(exe, "wrun")


def test_collision_with_path_is_rejected(tmp_path):
    entry, _, exe, _ = make(tmp_path, which=lambda name: "C:\\Windows\\wrun.exe" if name == "wrun" else None)
    with pytest.raises(NameCollision):
        entry.install(exe, "wrun")


def test_revealing_or_invalid_names_are_rejected(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    for bad in ("carcasa", "boveda", "secreto", "pin", "a", "con espacios", "x" * 40, ""):
        with pytest.raises(NameRejected):
            entry.install(exe, bad)


def test_purge_run_mru_keeps_angel_entries_in_order(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    registry.write_value("HKCU", RUN_MRU, "MRUList", "abcd")
    registry.write_value("HKCU", RUN_MRU, "a", "proyecto\\1")
    registry.write_value("HKCU", RUN_MRU, "b", "wrun\\1")
    registry.write_value("HKCU", RUN_MRU, "c", "git\\1")
    registry.write_value("HKCU", RUN_MRU, "d", "notas\\1")

    removed = entry.purge_run_mru("WRUN")
    assert removed == 1
    values = registry.read_values("HKCU", RUN_MRU)
    assert set(values) == {"MRUList", "a", "c", "d"}
    assert values["MRUList"].data == "acd"
    assert values["a"].data == "proyecto\\1"
    assert values["c"].data == "git\\1"
    assert values["d"].data == "notas\\1"


def test_purge_typed_paths(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    registry.write_value("HKCU", TYPED_PATHS, "url1", "wrun")
    registry.write_value("HKCU", TYPED_PATHS, "url2", "C:\\dev\\proyecto")
    removed = entry.purge_typed_paths("wrun")
    assert removed == 1
    values = registry.read_values("HKCU", TYPED_PATHS)
    assert set(values) == {"url2"}


def test_purge_without_keys_does_nothing(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    assert entry.purge("wrun") == (0, 0)


def test_configured_name_used_when_not_installed(tmp_path):
    entry, registry, exe, paths = make(tmp_path)
    registry.write_value("HKCU", RUN_MRU, "a", "xyz\\1")
    registry.write_value("HKCU", RUN_MRU, "b", "wrun\\1")
    registry.write_value("HKCU", RUN_MRU, "MRUList", "ab")
    assert entry.purge_run_mru() == 1


def test_validate_name_accepts_boring_short_names():
    for good in ("wrun", "ataljo", "Run_2", "abc-def"):
        assert validate_name(good) == good
