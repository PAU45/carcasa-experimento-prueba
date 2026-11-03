"""Errores del nucleo. Los mensajes visibles son cortos y en espanol."""

from __future__ import annotations


class CarcasaError(Exception):
    """Error base de la aplicacion."""


class VaultError(CarcasaError):
    """Error de la boveda."""


class VaultNotFound(VaultError):
    pass


class VaultExists(VaultError):
    pass


class VaultCorrupted(VaultError):
    pass


class VaultUnreadable(VaultError):
    pass


class VaultRevoked(VaultError):
    pass


class InvalidSecret(VaultError):
    """PIN o codigo de recuperacion incorrecto."""

    def __init__(self) -> None:
        super().__init__("No se pudo abrir la boveda.")


class InvalidName(VaultError):
    pass


class DuplicateName(VaultError):
    pass


class PathNotAllowed(CarcasaError):
    """Ruta protegida: el proyecto publico nunca se toca."""


class SwitchFailed(CarcasaError):
    pass


class RecoveryRequired(CarcasaError):
    """La conmutacion no se pudo revertir sola; hay diario pendiente."""
