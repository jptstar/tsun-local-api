"""TSUN AP transport framing."""

from __future__ import annotations

import asyncio

from .exceptions import TsunProtocolError


def checksum(data: bytes) -> int:
    """Return the AP additive checksum."""
    return sum(data) & 0xFF


def build_frame(logger_sn: int, payload: bytes) -> bytes:
    """Wrap a local protocol payload in an AP request frame."""
    data = b"\x02\x00\x00" + bytes(12) + payload
    scope = (
        len(data).to_bytes(2, "little")
        + b"\x10\x45\x00\x00"
        + logger_sn.to_bytes(4, "little")
        + data
    )
    return b"\xA5" + scope + bytes((checksum(scope), 0x15))


def parse_frame(frame: bytes) -> bytes:
    """Validate an AP response and return its embedded payload."""
    _validate_frame(frame)
    if frame[11] != 0x02 or frame[12] != 0x01:
        raise TsunProtocolError("AP request was rejected")
    return frame[25:-2]


def _validate_frame(frame: bytes) -> None:
    """Validate the common AP envelope without interpreting its status."""
    if len(frame) < 27 or frame[0] != 0xA5 or frame[-1] != 0x15:
        raise TsunProtocolError("Invalid AP frame")
    if len(frame) != int.from_bytes(frame[1:3], "little") + 13:
        raise TsunProtocolError("Invalid AP frame length")
    if checksum(frame[1:-2]) != frame[-2]:
        raise TsunProtocolError("Invalid AP checksum")


def extract_logger_sn(frame: bytes) -> int:
    """Return the logger SN carried by a validated AP response."""
    _validate_frame(frame)
    logger_sn = int.from_bytes(frame[7:11], "little")
    if logger_sn == 0:
        raise TsunProtocolError("AP response contains no logger SN")
    return logger_sn


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one complete AP frame from a stream."""
    header = await reader.readexactly(3)
    if header[0] != 0xA5:
        raise TsunProtocolError("Invalid AP start marker")
    return header + await reader.readexactly(
        int.from_bytes(header[1:3], "little") + 10
    )
