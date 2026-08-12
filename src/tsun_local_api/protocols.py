"""Read-only TSUN local protocol codecs."""

from __future__ import annotations

from .exceptions import TsunProtocolError

PROTOCOL_1511 = "1511"
PROTOCOL_02B0 = "02b0"

GLOBAL_1511_ALARMS = (0x0BBB, 0x0BBC, 0x0BBD, 0x0BBE)
SECONDARY_1511_ALARMS = (0x0CE4, 0x0CE5, 0x0CE6, 0x0CE7)
PV_1511_ALARMS = (0x0E16, 0x0E1D, 0x0E24, 0x0EDE, 0x0EE5, 0x0EEC)
ALARMS_02B0 = (0x3003, 0x3004, 0x3005, 0x3006)


def _crc16(data: bytes, byteorder: str) -> bytes:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc.to_bytes(2, byteorder)


def build_1511_request(address: int, function: int, start: int, end: int) -> bytes:
    """Build a TSUN 1511 register request."""
    body = (
        bytes((address, function, 0))
        + start.to_bytes(2, "big")
        + b"\x00\x02"
        + (end - start + 1).to_bytes(2, "big")
    )
    return body + _crc16(body, "big")


def parse_1511_response(
    frame: bytes, address: int, function: int, start: int, end: int
) -> dict[int, int]:
    """Parse little-endian registers from a TSUN 1511 response."""
    count = end - start + 1
    if len(frame) < 10 or frame[0] != 0x7E:
        raise TsunProtocolError("Invalid 1511 frame")
    if _crc16(frame[1:-2], "big") != frame[-2:]:
        raise TsunProtocolError("Invalid 1511 CRC")
    if frame[1] != address or frame[2] != function | 0x80 or frame[3] != 1:
        raise TsunProtocolError("Unexpected 1511 response")
    if int.from_bytes(frame[4:6], "big") != start:
        raise TsunProtocolError("Unexpected 1511 start register")
    size = int.from_bytes(frame[6:8], "big")
    if size != count * 2 or len(frame) != size + 10:
        raise TsunProtocolError("Unexpected 1511 data length")
    data = frame[8:-2]
    return {
        start + index: int.from_bytes(data[index * 2 : index * 2 + 2], "little")
        for index in range(count)
    }


def build_modbus_request(function: int, start: int, end: int) -> bytes:
    """Build a Modbus RTU register request."""
    body = (
        bytes((1, function))
        + start.to_bytes(2, "big")
        + (end - start + 1).to_bytes(2, "big")
    )
    return body + _crc16(body, "little")


def parse_modbus_response(
    frame: bytes, function: int, start: int, end: int
) -> dict[int, int]:
    """Parse big-endian registers from a Modbus RTU response."""
    count = end - start + 1
    if len(frame) < 5 or frame[0] != 1:
        raise TsunProtocolError("Invalid Modbus frame")
    if _crc16(frame[:-2], "little") != frame[-2:]:
        raise TsunProtocolError("Invalid Modbus CRC")
    if frame[1] != function:
        raise TsunProtocolError("Unexpected Modbus response")
    if frame[2] != count * 2 or len(frame) != frame[2] + 5:
        raise TsunProtocolError("Unexpected Modbus data length")
    data = frame[3:-2]
    return {
        start + index: int.from_bytes(data[index * 2 : index * 2 + 2], "big")
        for index in range(count)
    }


def _u32(registers: dict[int, int], address: int) -> int:
    return registers[address] << 16 | registers[address + 1]


def _scaled(value: int, factor: float, precision: int) -> float:
    """Scale an integer register without leaking binary float noise."""
    return round(value * factor, precision)


def detect_1511_pv_count(registers: dict[int, int]) -> int:
    """Return the highest populated PV input for the 1511 map."""
    bases = (0x0E10, 0x0E17, 0x0E1E, 0x0ED8, 0x0EDF, 0x0EE6)
    totals = (0x0E28, 0x0E2A, 0x0E2C, 0x0EF0, 0x0EF2, 0x0EF4)
    detected = 1
    for number, (base, total) in enumerate(zip(bases, totals), 1):
        if any(
            0 < registers.get(address, 0) < 0xFFFF
            for address in (base, base + 1, base + 2, base + 4, total, total + 1)
        ):
            detected = number
    return detected


def decode_1511(registers: dict[int, int], pv_count: int) -> dict[str, float]:
    """Decode telemetry from a supported 1511 micro-inverter."""
    values = {
        "ac_voltage": _scaled(registers[0x0BC4], 0.1, 1),
        "ac_current": _scaled(registers[0x0BC5], 0.01, 2),
        "ac_frequency": _scaled(registers[0x0BC7], 0.01, 2),
        "ac_power": _scaled(registers[0x0BCD], 0.1, 1),
        "ac_energy_today": _scaled(registers[0x0BCE], 0.01, 2),
        "ac_energy_total": _scaled(_u32(registers, 0x0BCF), 0.01, 2),
    }
    bases = (0x0E10, 0x0E17, 0x0E1E, 0x0ED8, 0x0EDF, 0x0EE6)
    totals = (0x0E28, 0x0E2A, 0x0E2C, 0x0EF0, 0x0EF2, 0x0EF4)
    for number, (base, total) in enumerate(
        zip(bases[:pv_count], totals[:pv_count]), 1
    ):
        values.update(
            {
                f"pv{number}_voltage": _scaled(registers[base], 0.1, 1),
                f"pv{number}_current": _scaled(registers[base + 1], 0.01, 2),
                f"pv{number}_power": _scaled(registers[base + 2], 0.1, 1),
                f"pv{number}_energy_today": _scaled(registers[base + 4], 0.01, 2),
                f"pv{number}_energy_total": _scaled(
                    _u32(registers, total), 0.01, 2
                ),
            }
        )
    values["dc_power_total"] = round(
        sum(values[f"pv{number}_power"] for number in range(1, pv_count + 1)), 1
    )
    return values


def decode_1511_alarms(
    registers: dict[int, int], pv_count: int
) -> dict[str, float | int]:
    """Expose 1511 alarm words without guessing undocumented bit meanings."""
    values: dict[str, float | int] = {}
    active: list[int] = []
    for index, address in enumerate(GLOBAL_1511_ALARMS):
        if address in registers:
            value = registers[address]
            values[f"alarm_global_{index}_raw"] = value
            active.append(value)
    for index, address in enumerate(SECONDARY_1511_ALARMS):
        if address in registers:
            value = registers[address]
            values[f"alarm_secondary_{index}_raw"] = value
            active.append(value)
    for number, address in enumerate(PV_1511_ALARMS[:pv_count], 1):
        if address in registers:
            value = registers[address]
            values[f"pv{number}_alarm_raw"] = value
            active.append(value)
    if all(address in registers for address in SECONDARY_1511_ALARMS):
        values["alarm_active"] = int(any(active))
    return values


def detect_02b0_pv_count(registers: dict[int, int]) -> int:
    """Return the populated PV input count for the 02B0 map."""
    detected = 1
    for number in range(1, 5):
        base = 0x3010 + (number - 1) * 3
        energy = 0x301F + (number - 1) * 3
        if any(
            registers.get(address, 0) not in (0, 0xFFFF)
            for address in (base, base + 1, base + 2, energy, energy + 1, energy + 2)
        ):
            detected = number
    return detected


def decode_02b0(registers: dict[int, int], pv_count: int) -> dict[str, float]:
    """Decode validated TSOL-MX500-compatible telemetry."""
    values = {
        "ac_voltage": _scaled(registers[0x3009], 0.1, 1),
        "ac_current": _scaled(registers[0x300A], 0.01, 2),
        "ac_frequency": _scaled(registers[0x300B], 0.01, 2),
        "ac_power": _scaled(registers[0x300F], 0.1, 1),
        "ac_energy_today": _scaled(registers[0x301C], 0.01, 2),
        "ac_energy_total": _scaled(_u32(registers, 0x301D), 0.01, 2),
    }
    for number in range(1, pv_count + 1):
        base = 0x3010 + (number - 1) * 3
        energy = 0x301F + (number - 1) * 3
        values.update(
            {
                f"pv{number}_voltage": _scaled(registers[base], 0.1, 1),
                f"pv{number}_current": _scaled(registers[base + 1], 0.01, 2),
                f"pv{number}_power": _scaled(registers[base + 2], 0.1, 1),
                f"pv{number}_energy_today": _scaled(registers[energy], 0.01, 2),
                f"pv{number}_energy_total": _scaled(
                    _u32(registers, energy + 1), 0.01, 2
                ),
            }
        )
    values["dc_power_total"] = round(
        sum(values[f"pv{number}_power"] for number in range(1, pv_count + 1)), 1
    )
    return values


def decode_02b0_alarms(registers: dict[int, int]) -> dict[str, float | int]:
    """Expose 02B0 ERR1-ERR4 values without assuming a fault-code table."""
    if not all(address in registers for address in ALARMS_02B0):
        return {}
    values: dict[str, float | int] = {
        f"alarm_code_{index}_raw": registers[address]
        for index, address in enumerate(ALARMS_02B0, 1)
    }
    values["alarm_active"] = int(any(registers[address] for address in ALARMS_02B0))
    return values
