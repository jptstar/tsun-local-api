"""Read non-secret identity data from a logger's local status page."""

from __future__ import annotations

import asyncio
import re
from html import unescape

from aiohttp import (
    BasicAuth,
    ClientError,
    ClientResponse,
    ClientSession,
    ClientTimeout,
)

from .ap import build_frame, extract_logger_sn, read_frame
from .exceptions import TsunProtocolError
from .models import LoggerMetadata
from .protocols import build_1511_request, build_modbus_request

STATUS_PATHS = ("/index_cn.html", "/index.html", "/status.html", "/")
WEB_TIMEOUT = 4.0
MAX_PAGE_SIZE = 512 * 1024

_NUMERIC_SN = r"([1-9]\d{7,9})"
_LABEL_PATTERNS = (
    re.compile(
        rf"device\s*(?:serial\s*(?:number|no\.?|#)|sn)"
        rf"[\s\S]{{0,500}}?{_NUMERIC_SN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"(?:设备|裝置|裝置資訊)[^\d]{{0,80}}(?:序列号|序號|SN)"
        rf"[\s\S]{{0,500}}?{_NUMERIC_SN}",
        re.IGNORECASE,
    ),
)
_KEY_PATTERNS = (
    re.compile(
        rf"\bcover[_-]mid\b[\s\S]{{0,160}}?{_NUMERIC_SN}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:device|logger|monitor)[_-]?(?:serial(?:_number)?|sn)\b"
        rf"[\s\S]{{0,160}}?{_NUMERIC_SN}",
        re.IGNORECASE,
    ),
    re.compile(rf"\bAP_{_NUMERIC_SN}\b", re.IGNORECASE),
)
_DEVICE_SECTION = re.compile(
    r"device\s*information|设备信息|設備資訊", re.IGNORECASE
)
_FIRMWARE_LABEL = re.compile(
    r"firmware\s*version\s+([A-Za-z0-9][A-Za-z0-9._-]{1,79})", re.IGNORECASE
)
_FIRMWARE_KEYS = (
    re.compile(
        r"\b(?:webdata|cover)[_-]ver\s*[:=]\s*[\"']"
        r"([A-Za-z0-9][A-Za-z0-9._-]{1,79})",
        re.IGNORECASE,
    ),
)
_MAC = r"([0-9A-F]{2}(?:[:-][0-9A-F]{2}){5})"
_MAC_LABEL = re.compile(rf"mac\s*address\s+{_MAC}", re.IGNORECASE)
_MAC_KEYS = (
    re.compile(
        rf"\b(?:webdata|cover)[_-](?:ap[_-]|sta[_-])?mac"
        rf"\s*[:=]\s*[\"']{_MAC}",
        re.IGNORECASE,
    ),
)
_INVERTER_SN_KEYS = (
    re.compile(
        r"\bwebdata[_-]sn\s*[:=]\s*[\"']\s*"
        r"([A-Za-z0-9][A-Za-z0-9_-]{3,63})\s*[\"']",
        re.IGNORECASE,
    ),
)


def _valid_logger_sn(value: str) -> int | None:
    logger_sn = int(value)
    return logger_sn if 0 < logger_sn <= 0xFFFFFFFF else None


def _parse_logger_sn(document: str) -> int | None:
    visible = unescape(re.sub(r"<[^>]*>", " ", document))
    for pattern, source in (
        *((pattern, visible) for pattern in _LABEL_PATTERNS),
        *((pattern, document) for pattern in _KEY_PATTERNS),
    ):
        for match in pattern.finditer(source):
            if logger_sn := _valid_logger_sn(match.group(1)):
                return logger_sn
    return None


def _first_match(patterns: tuple[re.Pattern[str], ...], document: str) -> str | None:
    for pattern in patterns:
        if match := pattern.search(document):
            return match.group(1)
    return None


def parse_logger_metadata(document: str) -> LoggerMetadata:
    """Extract the logger SN, inverter SN, firmware and MAC from HTML."""
    visible = unescape(re.sub(r"<[^>]*>", " ", document))
    device_section = ""
    if match := _DEVICE_SECTION.search(visible):
        device_section = visible[match.end() :]

    firmware = _first_match(_FIRMWARE_KEYS, document)
    if firmware is None and device_section:
        if match := _FIRMWARE_LABEL.search(device_section):
            firmware = match.group(1)

    mac = _first_match(_MAC_KEYS, document)
    if mac is None and device_section:
        if match := _MAC_LABEL.search(device_section):
            mac = match.group(1)
    if mac is not None:
        mac = mac.replace("-", ":").upper()

    return LoggerMetadata(
        logger_sn=_parse_logger_sn(document),
        inverter_serial_number=_first_match(_INVERTER_SN_KEYS, document),
        firmware_version=firmware,
        mac_address=mac,
    )


async def _async_read_limited(response: ClientResponse) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.content.iter_chunked(16 * 1024):
        total += len(chunk)
        if total > MAX_PAGE_SIZE:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _async_probe_logger_sn(host: str, port: int) -> int | None:
    """Best-effort SN discovery from an AP response when HTTP is absent."""
    probes = (
        build_1511_request(0xA1, 0x01, 0x0BB8, 0x0BD0),
        build_modbus_request(0x03, 0x3009, 0x301E),
    )
    for payload in probes:
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(WEB_TIMEOUT):
                reader, writer = await asyncio.open_connection(host, port)
                writer.write(build_frame(0, payload))
                await writer.drain()
                response = await read_frame(reader)
            return extract_logger_sn(response)
        except (
            OSError,
            TimeoutError,
            asyncio.IncompleteReadError,
            TsunProtocolError,
            ValueError,
        ):
            continue
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
    return None


def _merged(current: LoggerMetadata, update: LoggerMetadata) -> LoggerMetadata:
    return LoggerMetadata(
        logger_sn=current.logger_sn or update.logger_sn,
        inverter_serial_number=(
            current.inverter_serial_number or update.inverter_serial_number
        ),
        firmware_version=current.firmware_version or update.firmware_version,
        mac_address=current.mac_address or update.mac_address,
    )


async def async_read_logger_metadata(
    session: ClientSession, host: str, *, port: int = 8899
) -> LoggerMetadata:
    """Read metadata locally, falling back to a non-writing AP probe."""
    metadata = LoggerMetadata()
    for path in STATUS_PATHS:
        url = f"http://{host}{path}"
        for auth in (None, BasicAuth("admin", "admin")):
            try:
                async with session.get(
                    url,
                    auth=auth,
                    timeout=ClientTimeout(total=WEB_TIMEOUT),
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        continue
                    if response.content_length is not None and (
                        response.content_length > MAX_PAGE_SIZE
                    ):
                        continue
                    content = await _async_read_limited(response)
            except (ClientError, TimeoutError, UnicodeError, ValueError):
                continue
            if content is None:
                continue
            metadata = _merged(
                metadata,
                parse_logger_metadata(content.decode("utf-8", errors="replace")),
            )
            if all(
                (
                    metadata.logger_sn,
                    metadata.inverter_serial_number,
                    metadata.firmware_version,
                    metadata.mac_address,
                )
            ):
                return metadata

    if metadata.logger_sn is None:
        metadata = LoggerMetadata(
            logger_sn=await _async_probe_logger_sn(host, port),
            inverter_serial_number=metadata.inverter_serial_number,
            firmware_version=metadata.firmware_version,
            mac_address=metadata.mac_address,
        )
    return metadata
