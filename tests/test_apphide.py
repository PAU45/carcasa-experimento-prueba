from __future__ import annotations

import json

import pytest

from carcasa.core.apphide import AppHider, FakeProcesses
from carcasa.core.paths import AppPaths


def build(tmp_path, monkeypatch, *, hide=("Docker", "Trae"), processes=None, mover=None, visible=None):
    paths = AppPaths(tmp_path / "root")
    paths.ensure()
    desktop = tmp_path / "Desktop"
    desktop.mkdir()
    menu = tmp_path / "StartMenu"
    (menu / "Programs" / "Docker").mkdir(parents=True)
    recent = tmp_path / "Recent"
    recent.mkdir()
    jumps_auto = tmp_path / "Jumps" / "AutomaticDestinations"
    jumps_custom = tmp_path / "Jumps" / "CustomDestinations"
    jumps_auto.mkdir(parents=True)
    jumps_custom.mkdir(parents=True)
    hidden = tmp_path / "links-ocultos"

    def shortcut(folder, name, target=""):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(target, encoding="utf-8")

    shortcut(desktop, "Docker Desktop.lnk")
    shortcut(desktop, "Visual Studio Code.lnk")
    shortcut(desktop, "Trae.lnk")
    shortcut(menu / "Programs" / "Docker", "Docker Desktop.lnk")
    shortcut(menu / "Programs", "Trae.lnk")
    shortcut(recent, "Docker Desktop.lnk")
    shortcut(recent, "proyecto.lnk")
    (jumps_auto / "a1b2.automaticDestinations-ms").write_bytes(b"\x00docker desktop.exe\x00")
    (jumps_auto / "c3d4.automaticDestinations-ms").write_bytes(b"\x00proyecto\x00")

    hider = AppHider(
        paths,
        hide_names=list(hide),
        visible_names=visible,
        desktop_dirs=[desktop],
        menus=[menu],
        recent=recent,
        jumps=[jumps_auto, jumps_custom],
        hidden_dir=hidden,
        processes=processes or FakeProcesses(),
        target_reader=lambda path: "",
        mover=mover,
    )
    return hider, paths, desktop, menu, recent, jumps_auto, hidden


def test_hide_moves_shortcuts_and_keeps_visible_app(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    result = hider.hide()
    assert result["moved"] == 4
    assert not (desktop / "Docker Desktop.lnk").exists()
    assert not (desktop / "Trae.lnk").exists()
    assert (desktop / "Visual Studio Code.lnk").exists()
    assert (hidden / "escritorio" / "Docker Desktop.lnk").exists()
    assert (hidden / "inicio" / "Docker Desktop.lnk").exists()
    assert len(hider.load_manifest()) == 4


def test_hide_purges_jump_lists_and_recent(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    result = hider.hide()
    assert result["jump_lists"] == 1
    assert not (jumps / "a1b2.automaticDestinations-ms").exists()
    assert (jumps / "c3d4.automaticDestinations-ms").exists()
    assert result["recent"] == 1
    assert not (recent / "Docker Desktop.lnk").exists()
    assert (recent / "proyecto.lnk").exists()


def test_hide_is_idempotent(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    hider.hide()
    second = hider.hide()
    assert second["moved"] == 0
    assert len(hider.load_manifest()) == 4


def test_visible_app_is_never_hidden_even_if_configured(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(
        tmp_path, monkeypatch, hide=("Visual Studio Code", "Docker"), visible={"VS Code"}
    )
    hider.hide()
    assert (desktop / "Visual Studio Code.lnk").exists()
    assert not (desktop / "Docker Desktop.lnk").exists()


def test_programdata_permission_failure_is_logged_and_skipped(tmp_path, monkeypatch):
    programdata = tmp_path / "ProgramData"
    programdata.mkdir()
    menu = programdata / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    (menu / "Docker").mkdir(parents=True)
    (menu / "Docker" / "Docker Desktop.lnk").write_text("", encoding="utf-8")
    monkeypatch.setenv("PROGRAMDATA", str(programdata))

    def mover(source, destination):
        if "ProgramData" in str(source):
            raise PermissionError("sin permiso")
        import shutil

        shutil.move(source, destination)

    hider, paths, desktop, menu_dir, recent, jumps, hidden = build(
        tmp_path, monkeypatch, mover=mover
    )
    hider.menus = [menu]
    result = hider.hide()
    assert result["problems"] == 1
    assert "sin permiso en ProgramData" in hider.problems[0]
    assert (menu / "Docker" / "Docker Desktop.lnk").exists()
    assert not (desktop / "Docker Desktop.lnk").exists()


def test_recent_entry_matched_by_target_is_removed(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    (recent / "acceso-raro.lnk").write_text("", encoding="utf-8")
    hider.target_reader = lambda path: "C:\\Apps\\Docker\\Docker Desktop.exe" if path.name == "acceso-raro.lnk" else ""
    hider.hide()
    assert not (recent / "acceso-raro.lnk").exists()


def test_jump_list_matched_by_content(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    (jumps / "ffff.automaticDestinations-ms").write_bytes("\x00Docker Desktop.exe\x00".encode("utf-16-le"))
    hider.hide()
    assert not (jumps / "ffff.automaticDestinations-ms").exists()


def test_restore_brings_shortcuts_back(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    hider.hide()
    assert hider.restore() == 4
    assert (desktop / "Docker Desktop.lnk").exists()
    assert (desktop / "Trae.lnk").exists()
    assert (menu / "Programs" / "Docker" / "Docker Desktop.lnk").exists()
    assert hider.load_manifest() == []


def test_restore_does_not_overwrite_original(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    hider.hide()
    (desktop / "Docker Desktop.lnk").write_text("nuevo", encoding="utf-8")
    hider.restore()
    assert (desktop / "Docker Desktop.lnk").read_text(encoding="utf-8") == "nuevo"
    assert (desktop / "Docker Desktop-recuperado.lnk").exists()


def test_stop_processes_only_touches_listed_apps(tmp_path, monkeypatch):
    processes = FakeProcesses([(10, "docker desktop.exe"), (11, "code.exe"), (12, "trae.exe")])
    hider, paths, desktop, menu, recent, jumps, hidden = build(
        tmp_path, monkeypatch, processes=processes
    )
    assert hider.stop_processes() == 2
    assert processes.processes == [(11, "code.exe")]
    assert ("request_close", 10) in processes.calls
    assert ("request_close", 12) in processes.calls


def test_apply_on_cede_stops_and_hides(tmp_path, monkeypatch):
    processes = FakeProcesses([(10, "docker desktop.exe")])
    hider, paths, desktop, menu, recent, jumps, hidden = build(
        tmp_path, monkeypatch, processes=processes
    )
    result = hider.apply_on_cede()
    assert result["stopped"] == 1
    assert result["moved"] == 4


def test_manifest_is_plain_json(tmp_path, monkeypatch):
    hider, paths, desktop, menu, recent, jumps, hidden = build(tmp_path, monkeypatch)
    hider.hide()
    data = json.loads(hider.manifest_path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert len(data["items"]) == 4
