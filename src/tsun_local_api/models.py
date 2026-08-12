"""Public data models for the TSUN local API."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Identity and capabilities reported for one micro-inverter."""

    logger_sn: int
    model: str
    protocol: str
    pv_count: int
    inverter_serial_number: str | None = None
    firmware_version: str | None = None
    mac_address: str | None = None


@dataclass(frozen=True, slots=True)
class LoggerMetadata:
    """Non-secret identity data exposed by the logger status page."""

    logger_sn: int | None = None
    inverter_serial_number: str | None = None
    firmware_version: str | None = None
    mac_address: str | None = None


@dataclass(frozen=True, slots=True)
class Telemetry:
    """One complete read-only telemetry update."""

    values: dict[str, float | int]
    device: DeviceInfo
    duration_ms: int
    blocks_ok: int
