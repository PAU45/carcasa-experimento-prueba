from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from carcasa.core import crypto
from carcasa.core.errors import (
    DuplicateName,
    InvalidName,
    InvalidSecret,
    VaultCorrupted,
    VaultExists,
    VaultNotFound,
    VaultRevoked,
    VaultUnreadable,
)
from carcasa.core.vault import HEADER_NAME, Vault, header_summary
from carcasa.core.winutil import has_attribute, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)
PIN = "482913"


@pytest.fixture()
def made(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST, chunk_size=4096)
    yield vault, code, tmp_path / "store"
    vault.close()


def test_create_open_and_read(made):
    vault, code, path = made
    assert crypto.is_valid_recovery_code(code)
    entry = vault.add_bytes("informe.txt", b"hola mundo")
    vault.close()
    with Vault.open(path, PIN) as again:
        assert [item.name for item in again.entries()] == ["informe.txt"]
        assert again.read_bytes(entry.id) == b"hola mundo"
        assert again.header.version == 1
        assert again.header.kdf["memory_cost"] == 8192


def test_wrong_pin_and_wrong_recovery_fail(made):
    vault, code, path = made
    vault.close()
    with pytest.raises(InvalidSecret):
        Vault.open(path, "000000")
    with pytest.raises(InvalidSecret):
        Vault.open(path, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")


def test_recovery_code_opens_and_rewraps(made):
    vault, code, path = made
    vault.close()
    with Vault.open(path, code) as again:
        assert again.opened_with == "rec"
        again.set_pin("999888")
    with Vault.open(path, "999888") as third:
        assert third.opened_with == "pin"
    with pytest.raises(InvalidSecret):
        Vault.open(path, PIN)


def test_nothing_readable_on_disk(made):
    vault, code, path = made
    name = "documento-secreto-2026.txt"
    payload = b"contenido ultra privado 1234567890"
    entry = vault.add_bytes(name, payload)
    vault.close()
    for item in path.rglob("*"):
        assert name.encode() not in str(item).encode()
        if item.is_file():
            raw = item.read_bytes()
            assert name.encode() not in raw
            assert payload not in raw
            assert PIN.encode() not in raw
    header = (path / HEADER_NAME).read_text(encoding="utf-8")
    assert PIN not in header
    assert "wrap_pin" in header


def test_blob_tamper_is_detected(made):
    vault, code, path = made
    entry = vault.add_bytes("a.txt", b"uno dos tres")
    blob = next((path / "blobs").glob("*.bin"))
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0x01
    blob.write_bytes(bytes(data))
    with pytest.raises(VaultCorrupted):
        vault.read_bytes(entry.id)
    assert vault.verify() == ["a.txt"]


def test_index_tamper_is_detected(made):
    vault, code, path = made
    vault.add_bytes("a.txt", b"datos")
    index = path / "index.enc"
    data = bytearray(index.read_bytes())
    data[-1] ^= 0x01
    index.write_bytes(bytes(data))
    vault.close()
    with pytest.raises(VaultCorrupted):
        Vault.open(path, PIN)


def test_duplicate_and_invalid_names(made):
    vault, code, path = made
    vault.add_bytes("nota.txt", b"1")
    with pytest.raises(DuplicateName):
        vault.add_bytes("NOTA.TXT", b"2")
    for bad in ("../fuera.txt", "a/b.txt", "con.txt", "   ", "x" * 300):
        with pytest.raises(InvalidName):
            vault.add_bytes(bad, b"x")


def test_extract_restores_content_and_mtime(made, tmp_path):
    vault, code, path = made
    entry = vault.add_bytes("copia.bin", b"abcdef" * 1000, mtime=1_600_000_000)
    target = tmp_path / "salida" / "copia.bin"
    vault.extract(entry.id, target)
    assert target.read_bytes() == b"abcdef" * 1000
    assert int(target.stat().st_mtime) == 1_600_000_000
    leftovers = list(target.parent.glob("*.part")) + list(target.parent.glob(".*.part"))
    assert leftovers == []


def test_remove_and_gc(made):
    vault, code, path = made
    entry = vault.add_bytes("borrar.txt", b"x")
    blob = path / "blobs" / f"{entry.id}.bin"
    assert blob.exists()
    vault.remove(entry.id)
    assert not blob.exists()
    assert vault.entries() == []


def test_rename(made):
    vault, code, path = made
    entry = vault.add_bytes("uno.txt", b"x")
    renamed = vault.rename(entry.id, "dos.txt")
    assert renamed.name == "dos.txt"
    with pytest.raises(DuplicateName):
        other = vault.add_bytes("tres.txt", b"y")
        vault.rename(other.id, "DOS.txt")


def test_close_wipes_key_and_blocks_use(made):
    vault, code, path = made
    vault.close()
    assert not vault.is_open
    with pytest.raises(VaultUnreadable):
        vault.add_bytes("x.txt", b"x")
    with pytest.raises(VaultUnreadable):
        vault.entries()


def test_create_refuses_existing_vault(made):
    vault, code, path = made
    with pytest.raises(VaultExists):
        Vault.create(path, PIN, params=FAST)


def test_open_missing_vault(tmp_path):
    with pytest.raises(VaultNotFound):
        Vault.open(tmp_path / "nada", PIN)
    (tmp_path / "vacia").mkdir()
    with pytest.raises(VaultNotFound):
        Vault.open(tmp_path / "vacia", PIN)


def test_revoke_requires_recovery(made):
    vault, code, path = made
    vault.add_bytes("a.txt", b"a")
    vault.revoke_pin()
    assert vault.is_revoked
    vault.close()
    with pytest.raises(VaultRevoked):
        Vault.open(path, PIN)
    with Vault.open(path, code) as recovered:
        assert recovered.read_bytes(recovered.find("a.txt").id) == b"a"
        recovered.set_pin("777777")
    with Vault.open(path, "777777") as again:
        assert again.is_open


def test_rotate_recovery_invalidates_old_code(made):
    vault, code, path = made
    new_code = vault.rotate_recovery_code()
    assert new_code != code
    vault.close()
    with pytest.raises(InvalidSecret):
        Vault.open(path, code)
    with Vault.open(path, new_code) as again:
        assert again.opened_with == "rec"


def test_destroy_is_irreversible(made):
    vault, code, path = made
    vault.add_bytes("a.txt", b"a")
    with pytest.raises(ValueError):
        vault.destroy("borrar")
    vault.destroy("DESTRUIR")
    assert not path.exists()
    with pytest.raises(VaultNotFound):
        Vault.open(path, code)


def test_header_summary_exposes_no_secrets(made):
    vault, code, path = made
    summary = header_summary(path)
    assert summary["pin"] is True
    assert summary["recovery"] is True
    assert PIN not in json.dumps(summary)
    assert code not in json.dumps(summary)


@pytest.mark.windows
def test_vault_folder_is_not_indexed(made):
    vault, code, path = made
    assert has_attribute(path, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
    assert has_attribute(path / "blobs", FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def test_work_dir_lives_inside_vault_and_is_cleaned(made):
    vault, code, path = made
    work = vault.work_dir
    (work / "perfil").mkdir()
    (work / "perfil" / "Cookies").write_bytes(b"datos")
    assert path in work.parents
    vault.close()
    assert list(work.iterdir()) == []


def test_large_file_multichunk(made, tmp_path):
    vault, code, path = made
    payload = os.urandom(20000)
    source = tmp_path / "grande.bin"
    source.write_bytes(payload)
    entry = vault.add_file("grande.bin", source)
    assert entry.size == 20000
    target = tmp_path / "vuelta.bin"
    vault.extract(entry.id, target)
    assert target.read_bytes() == payload


def test_create_leaves_no_partial_folder(tmp_path):
    vault, code = Vault.create(tmp_path / "store", PIN, params=FAST)
    vault.close()
    leftovers = [item for item in tmp_path.iterdir() if item.name.startswith(".store")]
    assert leftovers == []
