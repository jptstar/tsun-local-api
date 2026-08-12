"""Privacy-safe protocol diagnostics."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from typing import Any

from .exceptions import TsunProtocolError


def safe_error_details(error: Exception) -> dict[str, str]:
    """Return an error description without network identifiers."""
    details = {"type": type(error).__name__}
    if isinstance(error, TsunProtocolError):
        details["detail"] = str(error)
    return details


class ProtocolTrace:
    """Keep a small circular trace without host, SN or AP envelope."""

    def __init__(self, max_events: int = 24) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)

    def record(
        self,
        *,
        protocol: str,
        function: int,
        start: int,
        end: int,
        stage: str,
        request_payload: bytes,
        address: int | None = None,
        response_payload: bytes | None = None,
        response_bytes: int | None = None,
        error: Exception | None = None,
    ) -> None:
        """Record a protocol exchange using only non-identifying payload data."""
        event: dict[str, Any] = {
            "protocol": protocol,
            "function": f"0x{function:02X}",
            "start_register": f"0x{start:04X}",
            "end_register": f"0x{end:04X}",
            "stage": stage,
            "request_payload": request_payload.hex(" ").upper(),
        }
        if address is not None:
            event["address_tag"] = f"0x{address:02X}"
        if response_payload is not None:
            event["response_payload"] = response_payload.hex(" ").upper()
        if response_bytes is not None:
            event["response_bytes"] = response_bytes
        if error is not None:
            event["error"] = safe_error_details(error)
        self._events.append(event)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        """Return a detached snapshot suitable for diagnostics export."""
        return tuple(deepcopy(event) for event in self._events)
