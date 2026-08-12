"""Asynchronous TSUN local client."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .ap import build_frame, parse_frame, read_frame
from .exceptions import (
    TsunConnectionError,
    TsunError,
    TsunUnsupportedDeviceError,
)
from .models import DeviceInfo, LoggerMetadata, Telemetry
from .protocols import (
    PROTOCOL_02B0,
    PROTOCOL_1511,
    build_1511_request,
    build_modbus_request,
    decode_02b0,
    decode_02b0_alarms,
    decode_1511,
    decode_1511_alarms,
    detect_02b0_pv_count,
    detect_1511_pv_count,
    parse_1511_response,
    parse_modbus_response,
)
from .trace import ProtocolTrace


class TsunClient:
    """Read telemetry from one supported TSUN logger."""

    def __init__(
        self,
        host: str,
        logger_sn: int,
        *,
        port: int = 8899,
        timeout: float = 10,
        metadata: LoggerMetadata | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.logger_sn = logger_sn
        self.timeout = timeout
        self._protocol: str | None = None
        self._pv_count = 0
        self._metadata = metadata or LoggerMetadata(logger_sn=logger_sn)
        self._trace = ProtocolTrace()

    @property
    def device_info(self) -> DeviceInfo | None:
        """Return detected device information after a successful read."""
        if self._protocol is None:
            return None
        return DeviceInfo(
            logger_sn=self.logger_sn,
            model="TITAN" if self._protocol == PROTOCOL_1511 else "GEN3 / GEN3 PLUS",
            protocol=self._protocol,
            pv_count=self._pv_count,
            inverter_serial_number=self._metadata.inverter_serial_number,
            firmware_version=self._metadata.firmware_version,
            mac_address=self._metadata.mac_address,
        )

    @property
    def diagnostic_trace(self) -> tuple[dict[str, Any], ...]:
        """Return recent exchanges without the host, SN or AP envelope."""
        return self._trace.events

    async def _read(
        self,
        payload: bytes,
        *,
        protocol: str,
        function: int,
        start: int,
        end: int,
        address: int | None = None,
    ) -> bytes:
        writer: asyncio.StreamWriter | None = None
        stage = "connection"
        response: bytes | None = None
        protocol_response: bytes | None = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(self.host, self.port)
                stage = "send"
                writer.write(build_frame(self.logger_sn, payload))
                await writer.drain()
                stage = "receive"
                response = await read_frame(reader)
            stage = "validation"
            protocol_response = parse_frame(response)
            self._trace.record(
                protocol=protocol,
                function=function,
                start=start,
                end=end,
                stage="complete",
                request_payload=payload,
                address=address,
                response_payload=protocol_response,
                response_bytes=len(response),
            )
            return protocol_response
        except Exception as err:
            self._trace.record(
                protocol=protocol,
                function=function,
                start=start,
                end=end,
                stage=stage,
                request_payload=payload,
                address=address,
                response_payload=protocol_response,
                response_bytes=len(response) if response is not None else None,
                error=err,
            )
            if isinstance(err, (OSError, TimeoutError, asyncio.IncompleteReadError)):
                raise TsunConnectionError(
                    "Unable to communicate with TSUN device"
                ) from err
            raise
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def _read_1511(self) -> Telemetry:
        started = time.monotonic()
        registers: dict[int, int] = {}
        required = (
            (0xA1, 0x01, 0x0BB8, 0x0BD0),
            (0xA3, 0x03, 0x0E10, 0x0E2D),
            (0xA4, 0x04, 0x0ED8, 0x0EF5),
        )
        for address, function, start, end in required:
            response = await self._read(
                build_1511_request(address, function, start, end),
                protocol=PROTOCOL_1511,
                function=function,
                start=start,
                end=end,
                address=address,
            )
            registers.update(
                parse_1511_response(response, address, function, start, end)
            )
        blocks_ok = len(required)
        optional = (0xA2, 0x02, 0x0CE4, 0x0CE7)
        try:
            address, function, start, end = optional
            response = await self._read(
                build_1511_request(address, function, start, end),
                protocol=PROTOCOL_1511,
                function=function,
                start=start,
                end=end,
                address=address,
            )
            registers.update(
                parse_1511_response(response, address, function, start, end)
            )
        except TsunError:
            pass
        else:
            blocks_ok += 1
        self._protocol = PROTOCOL_1511
        # The validated TITAN map always defines PV1 through PV6, including
        # when the inverter is first loaded while all live values are zero.
        self._pv_count = max(6, detect_1511_pv_count(registers))
        device = self.device_info
        assert device is not None
        values = decode_1511(registers, self._pv_count)
        values.update(decode_1511_alarms(registers, self._pv_count))
        return Telemetry(
            values,
            device,
            round((time.monotonic() - started) * 1000),
            blocks_ok,
        )

    async def _read_02b0(self) -> Telemetry:
        started = time.monotonic()
        registers: dict[int, int] = {}
        required = ((0x03, 0x3009, 0x301E), (0x03, 0x301F, 0x302A))
        for function, start, end in required:
            response = await self._read(
                build_modbus_request(function, start, end),
                protocol=PROTOCOL_02B0,
                function=function,
                start=start,
                end=end,
            )
            registers.update(parse_modbus_response(response, function, start, end))
        blocks_ok = len(required)
        function, start, end = 0x03, 0x3003, 0x3006
        try:
            response = await self._read(
                build_modbus_request(function, start, end),
                protocol=PROTOCOL_02B0,
                function=function,
                start=start,
                end=end,
            )
            registers.update(parse_modbus_response(response, function, start, end))
        except TsunError:
            pass
        else:
            blocks_ok += 1
        self._protocol = PROTOCOL_02B0
        self._pv_count = max(self._pv_count, detect_02b0_pv_count(registers))
        device = self.device_info
        assert device is not None
        values = decode_02b0(registers, self._pv_count)
        values.update(decode_02b0_alarms(registers))
        return Telemetry(
            values,
            device,
            round((time.monotonic() - started) * 1000),
            blocks_ok,
        )

    async def async_read(self) -> Telemetry:
        """Read telemetry, detecting the local protocol on first use."""
        if self._protocol == PROTOCOL_1511:
            return await self._read_1511()
        if self._protocol == PROTOCOL_02B0:
            return await self._read_02b0()

        last_error: TsunError | None = None
        for reader in (self._read_1511, self._read_02b0):
            try:
                return await reader()
            except TsunConnectionError:
                # A failed TCP exchange cannot identify either protocol and a
                # second immediate attempt only delays the offline response.
                raise
            except TsunError as err:
                last_error = err
        raise TsunUnsupportedDeviceError(
            "No supported TSUN local protocol was detected"
        ) from last_error
