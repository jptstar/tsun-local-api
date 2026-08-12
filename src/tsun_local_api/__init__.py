"""Asynchronous local API for supported TSUN micro-inverters."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiohttp import ClientSession

from .client import TsunClient
from .discovery import (
    async_discover_devices,
    async_discover_udp,
    bounded_ipv4_network,
    parse_discovery_network,
    parse_udp_discovery_reply,
)
from .exceptions import (
    TsunConnectionError,
    TsunError,
    TsunProtocolError,
    TsunUnsupportedDeviceError,
)
from .models import DeviceInfo, LoggerMetadata, Telemetry
from .trace import safe_error_details


async def async_read_logger_metadata(
    session: ClientSession, host: str, *, port: int = 8899
) -> LoggerMetadata:
    """Read logger metadata using the caller-provided HTTP session."""
    from .web import async_read_logger_metadata as _read

    return await _read(session, host, port=port)


def parse_logger_metadata(document: str) -> LoggerMetadata:
    """Parse logger metadata without exposing the internal Web module."""
    from .web import parse_logger_metadata as _parse

    return _parse(document)

__all__ = [
    "DeviceInfo",
    "LoggerMetadata",
    "Telemetry",
    "TsunClient",
    "TsunConnectionError",
    "TsunError",
    "TsunProtocolError",
    "TsunUnsupportedDeviceError",
    "async_discover_devices",
    "async_discover_udp",
    "async_read_logger_metadata",
    "bounded_ipv4_network",
    "parse_discovery_network",
    "parse_logger_metadata",
    "parse_udp_discovery_reply",
    "safe_error_details",
]
