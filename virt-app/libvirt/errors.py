"""Shared exception definitions for libvirt helpers."""

from __future__ import annotations


class StorageError(RuntimeError):
    """Base error for storage-related failures."""


class StoragePoolNotFoundError(StorageError):
    def __init__(self, pool: str):
        super().__init__(f"Storage pool '{pool}' not found")
        self.pool = pool


class StoragePoolNotEmptyError(StorageError):
    def __init__(self, pool: str, volumes: list[str]):
        joined = ", ".join(volumes)
        super().__init__(f"Storage pool '{pool}' still contains volume(s): {joined}")
        self.pool = pool
        self.volumes = volumes


class StorageVolumeNotFoundError(StorageError):
    def __init__(self, pool: str, volume: str):
        super().__init__(f"Volume '{volume}' not found in pool '{pool}'")
        self.pool = pool
        self.volume = volume


class StorageVolumeInUseError(StorageError):
    def __init__(self, pool: str, volume: str, domains: list[str]):
        joined = ", ".join(domains)
        super().__init__(
            f"Volume '{volume}' in pool '{pool}' is attached to running domain(s): {joined}"
        )
        self.pool = pool
        self.volume = volume
        self.domains = domains


class StorageVolumeExistsError(StorageError):
    def __init__(self, pool: str, volume: str):
        super().__init__(f"Volume '{volume}' already exists in pool '{pool}'")
        self.pool = pool
        self.volume = volume


class DomainExistsError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' already exists")
        self.name = name


class DomainNotFoundError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' not found")
        self.name = name


class DomainActiveError(StorageError):
    def __init__(self, name: str):
        super().__init__(
            f"Domain '{name}' is currently running; stop it first or request a forced deletion"
        )
        self.name = name


class DomainNotRunningError(StorageError):
    def __init__(self, name: str):
        super().__init__(f"Domain '{name}' is not currently running")
        self.name = name


class DomainDeviceNotFoundError(StorageError):
    def __init__(self, name: str, device: str):
        super().__init__(f"Device '{device}' not found on domain '{name}'")
        self.name = name
        self.device = device

