from __future__ import annotations

import pytest

from carcasa.core.lockout import AttemptLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_no_delay_for_first_attempts(tmp_path):
    clock = Clock()
    limiter = AttemptLimiter(tmp_path / "state.json", free_attempts=2, clock=clock)
    assert limiter.remaining() == 0
    limiter.register_failure()
    limiter.register_failure()
    assert limiter.remaining() == 0


def test_exponential_delay(tmp_path):
    clock = Clock()
    limiter = AttemptLimiter(tmp_path / "state.json", free_attempts=2, base_delay=1, max_delay=8, clock=clock)
    limiter.register_failure()
    limiter.register_failure()
    assert limiter.register_failure() == pytest.approx(1)
    assert limiter.remaining() == pytest.approx(1)
    clock.advance(0.5)
    assert limiter.remaining() == pytest.approx(0.5)
    clock.advance(0.5)
    assert limiter.remaining() == 0
    assert limiter.register_failure() == pytest.approx(2)


def test_delay_is_capped(tmp_path):
    clock = Clock()
    limiter = AttemptLimiter(
        tmp_path / "state.json", free_attempts=0, base_delay=1, max_delay=5, clock=clock
    )
    for _ in range(10):
        limiter.register_failure()
    assert limiter.remaining() == pytest.approx(5)


def test_state_persists(tmp_path):
    clock = Clock()
    path = tmp_path / "state.json"
    limiter = AttemptLimiter(path, free_attempts=0, base_delay=1, clock=clock)
    limiter.register_failure()
    clock.advance(0.25)
    again = AttemptLimiter(path, free_attempts=0, base_delay=1, clock=clock)
    assert again.remaining() == pytest.approx(0.75)


def test_reset(tmp_path):
    clock = Clock()
    limiter = AttemptLimiter(tmp_path / "state.json", free_attempts=0, clock=clock)
    limiter.register_failure()
    limiter.reset()
    assert limiter.remaining() == 0
    assert limiter.failures == 0


def test_corrupt_state_is_ignored(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("no es json", encoding="utf-8")
    limiter = AttemptLimiter(path, clock=Clock())
    assert limiter.failures == 0
