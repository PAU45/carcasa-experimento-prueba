"""Cesion: conmutacion visual primero, cierre ordenado despues, bloqueo diferido.

El orden importa:
  1. estado publico (rapido)
  2. purga de RunMRU/TypedPaths en el mismo instante
  3. cierre del navegador privado y de las apps de la lista
  4. purga L2/L3
  5. bloqueo de Windows 4 s despues, en segundo plano

Si un paso falla, los demas se intentan igualmente y se devuelve el error.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CedeResult:
    reason: str
    ok: bool
    steps: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "reason": self.reason,
            "ok": self.ok,
            "steps": dict(self.steps),
            "elapsed_ms": self.elapsed_ms,
        }


def _timer(delay: float, callback: Callable[[], None]) -> None:
    timer = threading.Timer(delay, callback)
    timer.daemon = True
    timer.start()


class CedeFlow:
    def __init__(
        self,
        *,
        switch_public: Callable[[], object],
        purge_run: Callable[[], object],
        close_private: Callable[[], object],
        hide_apps: Callable[[], object],
        scrub: Callable[[int], object],
        lock: Callable[[], object],
        level: int = 3,
        lock_delay: float = 4.0,
        scheduler: Callable[[float, Callable[[], None]], object] = _timer,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.switch_public = switch_public
        self.purge_run = purge_run
        self.close_private = close_private
        self.hide_apps = hide_apps
        self.scrub = scrub
        self.lock = lock
        self.level = int(level)
        self.lock_delay = float(lock_delay)
        self.scheduler = scheduler
        self.clock = clock

    def run(self, reason: str = "manual") -> CedeResult:
        result = CedeResult(reason=reason, ok=True)
        started = self.clock()

        def step(name: str, action: Callable[[], object]) -> None:
            try:
                action()
                result.steps[name] = "ok"
            except Exception as exc:
                result.steps[name] = f"error:{type(exc).__name__}"
                result.ok = False

        step("switch", self.switch_public)
        step("run", self.purge_run)
        step("close", self.close_private)
        step("hide", self.hide_apps)
        step("scrub", lambda: self.scrub(self.level))
        try:
            self.scheduler(self.lock_delay, self.lock)
            result.steps["lock"] = "programado"
        except Exception as exc:
            result.steps["lock"] = f"error:{type(exc).__name__}"
            result.ok = False
        result.elapsed_ms = (self.clock() - started) * 1000
        return result
