"""Limite de intentos con retardo exponencial.

El estado vive junto a la boveda, no dentro (hace falta antes de abrirla) y
solo guarda un contador y una marca de tiempo. Nada del PIN.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

from .winutil import atomic_write_bytes


class AttemptLimiter:
    def __init__(
        self,
        state_path: str | Path,
        *,
        free_attempts: int = 2,
        base_delay: float = 1.0,
        max_delay: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.state_path = Path(state_path)
        self.free_attempts = max(0, int(free_attempts))
        self.base_delay = float(base_delay)
        self.max_delay = float(max_delay)
        self.clock = clock
        self._failures = 0
        self._last = 0.0
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            self._failures = max(0, int(data.get("failures", 0)))
            self._last = float(data.get("last", 0.0))
        except (OSError, ValueError, TypeError):
            self._failures = 0
            self._last = 0.0

    def _save(self) -> None:
        payload = json.dumps(
            {"failures": self._failures, "last": self._last},
            sort_keys=True,
        ).encode("utf-8")
        atomic_write_bytes(self.state_path, payload)

    @property
    def failures(self) -> int:
        return self._failures

    def required_delay(self) -> float:
        over = self._failures - self.free_attempts
        if over <= 0:
            return 0.0
        exponent = min(over - 1, 16)
        return min(self.max_delay, self.base_delay * (2 ** exponent))

    def remaining(self) -> float:
        delay = self.required_delay()
        if delay <= 0:
            return 0.0
        elapsed = max(0.0, self.clock() - self._last)
        return max(0.0, delay - elapsed)

    def register_failure(self) -> float:
        self._failures += 1
        self._last = self.clock()
        self._save()
        return self.remaining()

    def reset(self) -> None:
        if self._failures or self._last:
            self._failures = 0
            self._last = 0.0
            self._save()
