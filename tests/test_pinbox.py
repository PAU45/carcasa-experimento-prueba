from __future__ import annotations

import pytest

from carcasa.core.pinbox import PinController


def test_accepts_correct_pin():
    controller = PinController(lambda pin: pin == "123456")
    assert controller.submit("123456") == "ok"
    assert controller.closed


def test_empty_pin_does_not_count():
    controller = PinController(lambda pin: False)
    assert controller.submit("") == "retry"
    assert controller.attempts == 0


def test_three_failures_close():
    controller = PinController(lambda pin: False, max_attempts=3)
    assert controller.submit("000000") == "retry"
    assert controller.submit("111111") == "retry"
    assert controller.submit("222222") == "close"
    assert controller.closed


def test_success_resets_nothing_but_stops():
    controller = PinController(lambda pin: pin == "ok", max_attempts=3)
    controller.submit("mal")
    assert controller.submit("ok") == "ok"
    assert controller.attempts == 1


def test_verify_exception_is_denied():
    def broken(_pin):
        raise RuntimeError("fallo")

    controller = PinController(broken)
    assert controller.submit("123456") == "retry"


def test_timeout_closes():
    controller = PinController(lambda pin: True)
    assert controller.timeout() == "close"
    assert controller.closed
    assert controller.submit("123456") == "close"


def test_after_close_no_more_attempts():
    controller = PinController(lambda pin: False, max_attempts=1)
    controller.submit("000000")
    assert controller.submit("111111") == "close"
