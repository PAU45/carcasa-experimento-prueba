"""Disparadores de cesion.

Atajo Ctrl+Alt+F12: prioridad maxima, nunca se cancela.
Resto de disparadores: margen de 500 ms con Esc. Si hay actividad humana en ese
margen se espera (hasta un tope) y se cierra despues, sin cortar a nadie.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import threading
import time
from dataclasses import dataclass
from typing import Callable

MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_WIN = 0x0008
VK_ESCAPE = 0x1B
VK_F12 = 0x7B
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
WM_WTSSESSION_CHANGE = 0x02B1
WM_POWERBROADCAST = 0x0218
WTS_SESSION_LOCK = 0x7
PBT_APMSUSPEND = 0x0004
PBT_APMRESUMEAUTOMATIC = 0x0012


class TriggerManager:
    def __init__(
        self,
        cede: Callable[[str], object],
        *,
        cancel_ms: int = 500,
        max_defer_ms: int = 30_000,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        esc_source: Callable[[], bool] = lambda: False,
        activity_source: Callable[[], bool] = lambda: False,
    ) -> None:
        self.cede = cede
        self.cancel_ms = max(0, int(cancel_ms))
        self.max_defer_ms = max(self.cancel_ms, int(max_defer_ms))
        self.clock = clock
        self.sleep = sleep
        self.esc_source = esc_source
        self.activity_source = activity_source
        self._busy = False
        self._lock = threading.Lock()

    @property
    def busy(self) -> bool:
        return self._busy

    def request(self, reason: str) -> str:
        with self._lock:
            if self._busy:
                return "ignored"
            self._busy = True
        try:
            if reason == "hotkey":
                self.cede(reason)
                return "done"
            if self.cancel_ms <= 0:
                self.cede(reason)
                return "done"

            started = self.clock()
            deadline = started + self.cancel_ms / 1000.0
            hard_deadline = started + self.max_defer_ms / 1000.0
            while True:
                if self.esc_source():
                    return "cancelled"
                now = self.clock()
                if self.activity_source() and now < hard_deadline:
                    deadline = min(hard_deadline, max(deadline, now + self.cancel_ms / 1000.0))
                if now >= deadline:
                    break
                self.sleep(0.025)
            self.cede(reason)
            return "done"
        finally:
            with self._lock:
                self._busy = False


class IdleMonitor:
    def __init__(
        self,
        manager: TriggerManager,
        seconds: float = 180,
        *,
        input_age: Callable[[], float],
    ) -> None:
        self.manager = manager
        self.seconds = float(seconds)
        self.input_age = input_age

    def tick(self) -> bool:
        if self.input_age() >= self.seconds:
            self.manager.request("idle")
            return True
        return False


class UsbKeyWatcher:
    def __init__(self, manager: TriggerManager, volume: str, *, present: Callable[[str], bool]) -> None:
        self.manager = manager
        self.volume = volume
        self.present = present
        self.was_present = bool(present(volume)) if volume else False

    def tick(self) -> bool:
        if not self.volume:
            return False
        now = bool(self.present(self.volume))
        removed = self.was_present and not now
        self.was_present = now
        if removed:
            self.manager.request("usb")
        return removed


@dataclass
class TimeWindow:
    start: str = "07:00"
    end: str = "22:00"
    enabled: bool = False

    def allows(self, moment: dt.datetime | None = None) -> bool:
        if not self.enabled:
            return True
        moment = moment or dt.datetime.now()
        start = _minutes(self.start)
        end = _minutes(self.end)
        current = moment.hour * 60 + moment.minute
        if start == end:
            return True
        if start < end:
            return start <= current < end
        return current >= start or current < end


def _minutes(text: str) -> int:
    try:
        hours, minutes = str(text).split(":")
        return (int(hours) % 24) * 60 + (int(minutes) % 60)
    except (ValueError, AttributeError):
        return 0


class TimeWindowMonitor:
    def __init__(self, manager: TriggerManager, window: TimeWindow) -> None:
        self.manager = manager
        self.window = window

    def tick(self, moment: dt.datetime | None = None) -> bool:
        if not self.window.allows(moment):
            self.manager.request("horario")
            return True
        return False


class WindowsInput:
    @staticmethod
    def input_age() -> float:
        import ctypes.wintypes as wintypes

        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return 0.0
        elapsed = ctypes.windll.kernel32.GetTickCount() - info.dwTime
        return max(0.0, elapsed / 1000.0)

    @staticmethod
    def activity(threshold: float = 1.5) -> bool:
        return WindowsInput.input_age() < threshold

    @staticmethod
    def esc_pressed() -> bool:
        try:
            return bool(ctypes.windll.user32.GetAsyncKeyState(VK_ESCAPE) & 0x8000)
        except Exception:
            return False


class HotkeyListener:
    """Registro global de Ctrl+Alt+F12 en un hilo propio."""

    def __init__(self, callback: Callable[[], None], modifiers: int = MOD_CONTROL | MOD_ALT, key: int = VK_F12) -> None:
        self.callback = callback
        self.modifiers = modifiers
        self.key = key
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._ready = threading.Event()
        self.registered = False

    def start(self) -> bool:
        self._thread = threading.Thread(target=self._run, name="hotkey", daemon=True)
        self._thread.start()
        self._ready.wait(2)
        return self.registered

    def _run(self) -> None:
        import ctypes.wintypes as wintypes

        user32 = ctypes.windll.user32
        self._thread_id = ctypes.windll.kernel32.GetCurrentThreadId()
        self.registered = bool(user32.RegisterHotKey(None, 1, self.modifiers, self.key))
        self._ready.set()
        if not self.registered:
            return
        message = wintypes.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message == WM_HOTKEY:
                    try:
                        self.callback()
                    except Exception:
                        pass
        finally:
            user32.UnregisterHotKey(None, 1)

    def stop(self) -> None:
        if self._thread_id:
            ctypes.windll.user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=2)


class SessionWatcher:
    """Win+L y suspension/tapa mediante mensajes de Windows."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        self.callback = callback
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._stop = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="session", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            import win32gui

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = self._proc
            wc.lpszClassName = "statcache-session"
            wc.hInstance = win32gui.GetModuleHandle(None)
            try:
                win32gui.RegisterClass(wc)
            except Exception:
                pass
            self._hwnd = win32gui.CreateWindow(
                wc.lpszClassName, "", 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None
            )
            try:
                ctypes.windll.wtsapi32.WTSRegisterSessionNotification(self._hwnd, 0)
            except Exception:
                pass
            win32gui.PumpMessages()
        except Exception:
            return

    def _proc(self, hwnd, message, wparam, lparam):
        import win32gui

        if message == WM_WTSSESSION_CHANGE and wparam == WTS_SESSION_LOCK:
            try:
                self.callback("lock")
            except Exception:
                pass
        elif message == WM_POWERBROADCAST and wparam == PBT_APMSUSPEND:
            try:
                self.callback("suspend")
            except Exception:
                pass
        return win32gui.DefWindowProc(hwnd, message, wparam, lparam)

    def stop(self) -> None:
        self._stop = True
        if self._hwnd:
            try:
                import win32gui

                win32gui.PostMessage(self._hwnd, WM_QUIT, 0, 0)
            except Exception:
                pass


def volume_present(volume: str) -> bool:
    """Comprueba un GUID de volumen entre las letras montadas."""
    if not volume:
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        buffer = ctypes.create_unicode_buffer(128)
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = f"{chr(65 + index)}:\\"
            if kernel32.GetVolumeNameForVolumeMountPointW(root, buffer, 128):
                if buffer.value.casefold().strip("\\") == volume.casefold().strip("\\"):
                    return True
    except Exception:
        return False
    return False
