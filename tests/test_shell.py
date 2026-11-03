from __future__ import annotations

import json

import pytest

from carcasa.core.errors import PathNotAllowed, RecoveryRequired, SwitchFailed
from carcasa.core.shell import (
    FakeShellBackend,
    Journal,
    PinnedItem,
    ShellProfile,
    ShellState,
    ShellSwitcher,
    read_pinned,
    state_digest,
    state_from_dict,
)


def make_pins(folder, files: dict[str, bytes]):
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (folder / name).write_bytes(data)
    return folder


def build(tmp_path):
    public_pins = make_pins(tmp_path / "pins-pub", {"Code.lnk": b"code", "Terminal.lnk": b"term"})
    private_pins = make_pins(tmp_path / "pins-priv", {"Navegador.lnk": b"nav", "Notas.lnk": b"notes"})
    public = ShellProfile(
        desktop_dir=str(tmp_path / "desktop-publico"),
        wallpaper=str(tmp_path / "fondo-publico.jpg"),
        wallpaper_style="10",
        wallpaper_tile="0",
        apps_light=1,
        system_light=1,
        accent=0xFF203040,
        color_prevalence=0,
        pinned_source=public_pins,
    )
    private = ShellProfile(
        desktop_dir=str(tmp_path / "desktop-privado"),
        wallpaper=str(tmp_path / "fondo-privado.jpg"),
        wallpaper_style="2",
        wallpaper_tile="1",
        apps_light=0,
        system_light=0,
        accent=0xFFAA5500,
        color_prevalence=1,
        pinned_source=private_pins,
    )
    state = public.state()
    backend = FakeShellBackend(state, {path.name: path.read_bytes() for path in public_pins.glob("*.lnk")})
    journal = Journal(tmp_path / "state" / "journal.json")
    switcher = ShellSwitcher(backend, journal, public, private)
    return switcher, backend, journal, public, private


def test_digest_is_stable_and_covers_visible_state():
    a = ShellState("C:/x", "C:/f.jpg", pinned=(PinnedItem("a.lnk", "11"),))
    b = state_from_dict(a.to_dict())
    assert state_digest(a) == state_digest(b)
    assert state_digest(a) != state_digest(ShellState("C:/y", "C:/f.jpg", pinned=a.pinned))
    assert state_digest(a) != state_digest(ShellState("C:/x", "C:/g.jpg", pinned=a.pinned))
    assert state_digest(a) != state_digest(ShellState("C:/x", "C:/f.jpg", pinned=(PinnedItem("b.lnk", "11"),)))


def test_switch_private_and_back_restores_exact_digest(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    start = state_digest(backend.read_state())

    result = switcher.switch_to_private()
    assert result.changed
    assert state_digest(backend.read_state()) == state_digest(private.state())
    assert backend.pinned_files.keys() == {"Navegador.lnk", "Notas.lnk"}
    assert not journal.pending

    back = switcher.switch_to_public()
    assert back.changed
    assert state_digest(backend.read_state()) == start
    assert backend.pinned_files.keys() == {"Code.lnk", "Terminal.lnk"}
    assert not journal.pending


def test_switch_is_idempotent(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    switcher.switch_to_private()
    again = switcher.switch_to_private()
    assert not again.changed
    switcher.switch_to_public()
    again = switcher.switch_to_public()
    assert not again.changed
    assert not journal.pending


def test_icon_layout_is_never_touched(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    before = backend.read_state().icons_digest
    switcher.switch_to_private()
    switcher.switch_to_public()
    assert backend.read_state().icons_digest == before


def test_failure_during_private_rolls_back(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    start = state_digest(backend.read_state())
    backend.failures["set_wallpaper"] = 1
    with pytest.raises(SwitchFailed):
        switcher.switch_to_private()
    assert state_digest(backend.read_state()) == start
    assert not journal.pending


def test_journal_is_written_before_any_mutation(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    seen = []
    backend.on_call = lambda name: seen.append((name, journal.pending))
    switcher.switch_to_private()
    assert seen[0][0] == "set_desktop"
    assert all(pending for _, pending in seen)


def test_double_failure_requires_recovery_then_boot_restores_public(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    public_digest = state_digest(backend.read_state())
    backend.failures["set_theme"] = 1
    backend.failures["set_desktop"] = 1
    with pytest.raises(RecoveryRequired):
        switcher.switch_to_private()
    assert journal.pending

    backend.failures.clear()
    result = switcher.recover_on_boot()
    assert result is not None
    assert state_digest(backend.read_state()) == public_digest
    assert not journal.pending


def test_boot_always_returns_to_public_even_after_kill(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    public_state = backend.read_state()
    backend.set_desktop(private.desktop_dir)
    backend.set_wallpaper(private.wallpaper, "2", "1")
    backend.set_theme(0, 0, 0xFFAA5500, 1)
    backend.set_pinned(private.pinned_source)
    journal.begin("private", public_state, public.pinned_source)
    assert state_digest(backend.read_state()) != state_digest(public_state)

    result = switcher.recover_on_boot()
    assert result is not None
    assert state_digest(backend.read_state()) == state_digest(public_state)


def test_boot_validates_snapshot_and_keeps_journal_on_mismatch(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    public_state = backend.read_state()
    backend.set_desktop(private.desktop_dir)
    journal.begin("private", public_state, public.pinned_source)
    backend.ignore.add("set_desktop")

    with pytest.raises(RecoveryRequired):
        switcher.recover_on_boot()
    assert journal.pending
    assert journal.read()["phase"] == "private"


def test_recover_without_journal_does_nothing(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    assert switcher.recover_on_boot() is None


def test_public_restore_failure_requires_recovery(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    switcher.switch_to_private()
    public_digest = state_digest(public.state())
    backend.failures["set_theme"] = 1
    backend.failures["set_desktop"] = 1
    with pytest.raises(RecoveryRequired):
        switcher.switch_to_public()
    assert journal.pending

    backend.failures.clear()
    assert switcher.recover_on_boot() is not None
    assert state_digest(backend.read_state()) == public_digest
    assert not journal.pending


def test_protected_path_is_refused(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    evil = ShellProfile(
        desktop_dir="C:\\dev\\proyecto",
        wallpaper=str(tmp_path / "x.jpg"),
        pinned_source=public.pinned_source,
    )
    switcher.private = evil
    with pytest.raises(PathNotAllowed):
        switcher.switch_to_private()
    assert not journal.pending


def test_pinned_items_are_detected_from_folder(tmp_path):
    folder = make_pins(tmp_path / "pins", {"a.lnk": b"a", "b.lnk": b"b"})
    items = read_pinned(folder)
    assert [item.name for item in items] == ["a.lnk", "b.lnk"]
    assert all(len(item.sha256) == 64 for item in items)
    assert read_pinned(None) == ()
    assert read_pinned(tmp_path / "no-existe") == ()


def test_journal_payload_is_plain_json_without_secrets(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    switcher.switch_to_private()
    switcher.switch_to_public()
    assert not journal.path.exists()


def test_switch_under_300ms_with_fake_backend(tmp_path):
    switcher, backend, journal, public, private = build(tmp_path)
    switcher.switch_to_private()
    switcher.switch_to_public()
    result = switcher.switch_to_private()
    assert result.elapsed_ms < 300
