from __future__ import annotations

import io
import os

import pytest

from carcasa.core import crypto


FAST = crypto.kdf_params(time_cost=1, memory_cost=8192, parallelism=1)


def test_kdf_is_deterministic_and_salted():
    salt_a = b"a" * 16
    salt_b = b"b" * 16
    key_a = crypto.derive_key("123456", salt_a, **FAST)
    key_b = crypto.derive_key("123456", salt_a, **FAST)
    key_c = crypto.derive_key("123456", salt_b, **FAST)
    assert key_a == key_b
    assert key_a != key_c
    assert len(key_a) == 32


def test_kdf_does_not_return_pin():
    assert b"123456" not in crypto.derive_key("123456", b"s" * 16, **FAST)


def test_aes_roundtrip_and_aad_binding():
    key = os.urandom(32)
    blob = crypto.aes_encrypt(key, b"contenido", b"aad-1")
    assert crypto.aes_decrypt(key, blob, b"aad-1") == b"contenido"
    with pytest.raises(crypto.AuthenticationError):
        crypto.aes_decrypt(key, blob, b"aad-2")


def test_aes_detects_tampering():
    key = os.urandom(32)
    blob = bytearray(crypto.aes_encrypt(key, b"contenido", b"aad"))
    blob[-1] ^= 0x01
    with pytest.raises(crypto.AuthenticationError):
        crypto.aes_decrypt(key, bytes(blob), b"aad")


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 10000, 20000])
def test_stream_roundtrip_various_sizes(size):
    key = os.urandom(32)
    data = os.urandom(size)
    blob = crypto.encrypt_bytes(key, data, b"aad")
    assert crypto.decrypt_bytes(key, blob, b"aad") == data


def test_stream_detects_truncation():
    key = os.urandom(32)
    blob = crypto.encrypt_bytes(key, os.urandom(9000), b"aad")
    with pytest.raises(crypto.FormatError):
        crypto.decrypt_bytes(key, blob[: len(blob) // 2], b"aad")


def test_stream_detects_trailing_data():
    key = os.urandom(32)
    blob = crypto.encrypt_bytes(key, b"hola", b"aad") + b"x"
    with pytest.raises(crypto.FormatError):
        crypto.decrypt_bytes(key, blob, b"aad")


def test_stream_detects_chunk_swap():
    key = os.urandom(32)
    out = io.BytesIO()
    crypto.encrypt_stream(key, io.BytesIO(os.urandom(9000)), out, b"aad", chunk_size=4096)
    blob = bytearray(out.getvalue())

    def chunk_bounds(payload: bytes):
        pos = len(crypto.STREAM_MAGIC) + 4
        spans = []
        while pos < len(payload):
            start = pos
            pos += 1 + crypto.NONCE_LEN
            length = int.from_bytes(payload[pos : pos + 4], "little")
            pos += 4 + length
            spans.append((start, pos))
        return spans

    spans = chunk_bounds(bytes(blob))
    a, b = spans[0], spans[1]
    blob[a[0] : a[1]], blob[b[0] : b[1]] = blob[b[0] : b[1]], blob[a[0] : a[1]]
    with pytest.raises((crypto.AuthenticationError, crypto.FormatError)):
        crypto.decrypt_bytes(key, bytes(blob), b"aad")


def test_stream_rejects_bad_chunk_size():
    key = os.urandom(32)
    with pytest.raises(ValueError):
        crypto.encrypt_stream(key, io.BytesIO(b"x"), io.BytesIO(), b"aad", chunk_size=10)


def test_recovery_code_format_and_checksum():
    code = crypto.new_recovery_code()
    assert len(crypto.normalize_recovery_code(code)) == 24
    assert crypto.is_valid_recovery_code(code)
    assert crypto.is_valid_recovery_code(code.lower().replace("-", " "))
    assert crypto.format_recovery_code(code).count("-") == 5
    broken = list(crypto.normalize_recovery_code(code))
    broken[0] = "A" if broken[0] != "A" else "B"
    assert not crypto.is_valid_recovery_code("".join(broken))


def test_recovery_codes_are_unique():
    codes = {crypto.new_recovery_code() for _ in range(50)}
    assert len(codes) == 50


def test_recovery_alphabet_has_no_confusing_chars():
    assert not set("01OI") & set(crypto.RECOVERY_ALPHABET)


def test_pin_validation():
    assert crypto.validate_pin(" 123456 ") == "123456"
    for bad in ("", "12345", "x" * 65, "      "):
        with pytest.raises(ValueError):
            crypto.validate_pin(bad)


def test_kdf_params_validation_rejects_absurd_values():
    with pytest.raises(crypto.FormatError):
        crypto.validate_kdf_params({"time_cost": 99, "memory_cost": 8192, "parallelism": 1})
    with pytest.raises(crypto.FormatError):
        crypto.validate_kdf_params({"time_cost": 1, "memory_cost": 10, "parallelism": 1})


def test_wipe_key_zeroes():
    key = bytearray(b"x" * 32)
    crypto.wipe_key(key)
    assert len(key) == 0
