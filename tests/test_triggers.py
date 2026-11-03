from __future__ import annotations

import datetime as dt

import pytest

from carcasa.core.cede import CedeFlow
from carcasa.core.triggers import (
    IdleMonitor,
    TimeWindow,
    TimeWindowMonitor,
    TriggerManager,
    UsbKeyWatcher,
)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def manager(events, clock, **kwargs):
    return TriggerManager(
        lambda reason: events.append(reason),
        clock=clock,
        sleep=clock.sleep,
        **kwargs,
    )


def test_hotkey_is_never_cancelled():
    clock = Clock()
    events = []
    control = manager(events, clock, esc_source=lambda: True)
    assert control.request("hotkey") == "done"
    assert events == ["hotkey"]


def test_escape_cancels_within_margin():
    clock = Clock()
    events = []
    control = manager(events, clock, esc_source=lambda: True)
    assert control.request("idle") == "cancelled"
    assert events == []
    assert clock.now < 0.5


def test_cede_happens_after_margin():
    clock = Clock()
    events = []
    control = manager(events, clock)
    assert control.request("idle") == "done"
    assert events == ["idle"]
    assert clock.now >= 0.5


def test_activity_defers_close_until_quiet():
    clock = Clock()
    events = []
    control = manager(events, clock, activity_source=lambda: clock.now < 1.0)
    assert control.request("idle") == "done"
    assert events == ["idle"]
    assert 1.4 <= clock.now <= 1.8


def test_activity_hard_cap():
    clock = Clock()
    events = []
    control = manager(
        events, clock, activity_source=lambda: True, max_defer_ms=600
    )
    assert control.request("idle") == "done"
    assert clock.now <= 0.7


def test_duplicate_request_is_ignored():
    clock = Clock()
    events = []
    holder = {}

    def cede(reason):
        events.append(reason)
        assert holder["manager"].request("otra") == "ignored"

    holder["manager"] = TriggerManager(cede, clock=clock, sleep=clock.sleep)
    assert holder["manager"].request("manual") == "done"
    assert events == ["manual"]


def test_idle_monitor_triggers_once_per_tick():
    clock = Clock()
    events = []
    control = manager(events, clock, cancel_ms=0)
    age = {"value": 200.0}
    monitor = IdleMonitor(control, 180, input_age=lambda: age["value"])
    assert monitor.tick()
    assert events == ["idle"]
    age["value"] = 2
    assert not monitor.tick()
    assert events == ["idle"]


def test_usb_removal_triggers_once():
    clock = Clock()
    events = []
    control = manager(events, clock, cancel_ms=0)
    present = {"value": True}
    watcher = UsbKeyWatcher(control, "\\\\?\\Volume{abc}\\", present=lambda volume: present["value"])
    assert not watcher.tick()
    present["value"] = False
    assert watcher.tick()
    assert events == ["usb"]
    assert not watcher.tick()
    assert events == ["usb"]


def test_usb_not_configured_does_nothing():
    clock = Clock()
    events = []
    control = manager(events, clock, cancel_ms=0)
    watcher = UsbKeyWatcher(control, "", present=lambda volume: False)
    assert not watcher.tick()
    assert events == []


def test_time_window_day_and_night():
    assert TimeWindow("07:00", "22:00", enabled=False).allows(dt.datetime(2026, 1, 1, 3, 0))
    day = TimeWindow("07:00", "22:00", enabled=True)
    assert day.allows(dt.datetime(2026, 1, 1, 8, 0))
    assert not day.allows(dt.datetime(2026, 1, 1, 23, 0))
    night = TimeWindow("22:00", "07:00", enabled=True)
    assert night.allows(dt.datetime(2026, 1, 1, 23, 0))
    assert night.allows(dt.datetime(2026, 1, 1, 6, 0))
    assert not night.allows(dt.datetime(2026, 1, 1, 12, 0))


def test_time_window_monitor_triggers_outside():
    clock = Clock()
    events = []
    control = manager(events, clock, cancel_ms=0)
    monitor = TimeWindowMonitor(control, TimeWindow("07:00", "22:00", enabled=True))
    assert monitor.tick(dt.datetime(2026, 1, 1, 23, 0))
    assert events == ["horario"]
    assert not monitor.tick(dt.datetime(2026, 1, 1, 8, 0))


def test_cede_flow_order_and_deferred_lock():
    clock = Clock()
    calls = []
    scheduled = []
    flow = CedeFlow(
        switch_public=lambda: calls.append("switch"),
        purge_run=lambda: calls.append("purge"),
        close_private=lambda: calls.append("close"),
        hide_apps=lambda: calls.append("hide"),
        scrub=lambda level: calls.append(("scrub", level)),
        lock=lambda: calls.append("lock"),
        scheduler=lambda delay, fn: scheduled.append((delay, fn)),
        clock=clock,
    )
    result = flow.run("hotkey")
    assert result.ok
    assert calls == ["switch", "purge", "close", "hide", ("scrub", 3)]
    assert scheduled and scheduled[0][0] == 4.0
    scheduled[0][1]()
    assert calls[-1] == "lock"


def test_cede_flow_keeps_going_after_error():
    calls = []
    flow = CedeFlow(
        switch_public=lambda: (_ for _ in ()).throw(RuntimeError("fallo")),
        purge_run=lambda: calls.append("purge"),
        close_private=lambda: calls.append("close"),
        hide_apps=lambda: calls.append("hide"),
        scrub=lambda level: calls.append("scrub"),
        lock=lambda: calls.append("lock"),
        scheduler=lambda delay, fn: None,
        clock=Clock(),
    )
    result = flow.run("manual")
    assert not result.ok
    assert result.steps["switch"].startswith("error:")
    assert calls == ["purge", "close", "hide", "scrub"]


def test_cede_flow_with_cancel_zero_still_runs():
    clock = Clock()
    events = []
    control = manager(events, clock, cancel_ms=0)
    assert control.request("manual") == "done"
    assert events == ["manual"]
