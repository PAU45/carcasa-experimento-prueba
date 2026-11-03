"""Cuadro de PIN: 300x140, sin barra, sin bandeja, topmost, 20 s.

El texto es siempre generico. Nunca aparece el nombre de la aplicacion ni la
ruta de la boveda. Tres fallos cierran en silencio.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

TIMEOUT_MS = 20_000
MAX_ATTEMPTS = 3
WIDTH = 300
HEIGHT = 140


@dataclass
class PinController:
    verify: Callable[[str], bool]
    max_attempts: int = MAX_ATTEMPTS
    attempts: int = 0
    closed: bool = False

    def submit(self, pin: str) -> str:
        """Devuelve 'ok', 'retry' o 'close'."""
        if self.closed:
            return "close"
        pin = pin or ""
        if not pin:
            return "retry"
        try:
            accepted = bool(self.verify(pin))
        except Exception:
            accepted = False
        if accepted:
            self.closed = True
            return "ok"
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            self.closed = True
            return "close"
        return "retry"

    def timeout(self) -> str:
        self.closed = True
        return "close"


class PinBox:
    """Dialogo modal minimo. Se construye solo cuando hay escritorio."""

    def __init__(
        self,
        verify: Callable[[str], bool],
        *,
        timeout_ms: int = TIMEOUT_MS,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self.controller = PinController(verify, max_attempts=max_attempts)
        self.timeout_ms = int(timeout_ms)
        self.result: str | None = None
        self._root = None
        self._entry = None
        self._label = None

    def run(self) -> str | None:
        import tkinter as tk

        root = tk.Tk()
        self._root = root
        root.withdraw()
        root.overrideredirect(True)
        try:
            root.attributes("-topmost", True)
        except tk.TclError:
            pass
        try:
            root.attributes("-toolwindow", True)
        except tk.TclError:
            pass
        root.configure(bg="#1b1b1b")

        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = max(0, (screen_w - WIDTH) // 2)
        y = max(0, (screen_h - HEIGHT) // 2)
        root.geometry(f"{WIDTH}x{HEIGHT}+{x}+{y}")

        frame = tk.Frame(root, bg="#1b1b1b")
        frame.pack(expand=True, fill="both", padx=18, pady=16)
        label = tk.Label(
            frame,
            text="PIN",
            fg="#f0f0f0",
            bg="#1b1b1b",
            font=("Segoe UI", 11),
            anchor="w",
        )
        label.pack(fill="x")
        entry = tk.Entry(
            frame,
            show="*",
            font=("Segoe UI", 14),
            bg="#262626",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            justify="center",
        )
        entry.pack(fill="x", pady=(8, 0), ipady=5)
        self._label = label
        self._entry = entry

        entry.focus_force()
        root.lift()
        entry.bind("<Return>", lambda _event: self._submit())
        root.bind("<Escape>", lambda _event: self._cancel())
        root.protocol("WM_DELETE_WINDOW", self._cancel)
        root.after(self.timeout_ms, self._timeout)
        root.mainloop()
        return self.result

    def _submit(self) -> None:
        pin = self._entry.get() if self._entry is not None else ""
        outcome = self.controller.submit(pin)
        if outcome == "ok":
            self.result = pin
            self._close()
            return
        if outcome == "close":
            self._close()
            return
        self._label.configure(text="PIN incorrecto", fg="#ff7676")
        self._entry.delete(0, "end")
        self._entry.focus_force()

    def _timeout(self) -> None:
        self.controller.timeout()
        self._close()

    def _cancel(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._root is not None:
            try:
                self._root.destroy()
            except Exception:
                pass
            self._root = None


def ask(verify: Callable[[str], bool], *, timeout_ms: int = TIMEOUT_MS) -> str | None:
    return PinBox(verify, timeout_ms=timeout_ms).run()
