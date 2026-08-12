"""Tests for TSUN local protocol codecs."""

from tsun_local_api.ap import build_frame, checksum
from tsun_local_api.protocols import (
    build_1511_request,
    build_modbus_request,
    decode_02b0,
    decode_02b0_alarms,
    decode_1511,
    decode_1511_alarms,
    detect_02b0_pv_count,
    detect_1511_pv_count,
)


def test_ap_frame_contains_logger_sn() -> None:
    """The AP envelope stores the numeric logger SN little-endian."""
    frame = build_frame(2_071_244_293, b"\x01\x03")
    assert frame[0] == 0xA5
    assert int.from_bytes(frame[7:11], "little") == 2_071_244_293
    assert frame[-2] == checksum(frame[1:-2])
    assert frame[-1] == 0x15


def test_request_builders() -> None:
    """Both read-only request encodings contain the requested register span."""
    assert build_1511_request(0xA1, 0x01, 0x0BB8, 0x0BD0)[:9] == bytes.fromhex(
        "A1 01 00 0B B8 00 02 00 19"
    )
    assert build_modbus_request(0x03, 0x3009, 0x301E)[:6] == bytes.fromhex(
        "01 03 30 09 00 16"
    )


def test_decode_1511_measurements() -> None:
    """1511 register scaling and 32-bit counters are decoded consistently."""
    registers = {
        0x0BC4: 2305,
        0x0BC5: 274,
        0x0BC7: 5000,
        0x0BCD: 5311,
        0x0BCE: 375,
        0x0BCF: 0,
        0x0BD0: 41468,
    }
    for base, total in zip(
        (0x0E10, 0x0E17, 0x0E1E, 0x0ED8, 0x0EDF, 0x0EE6),
        (0x0E28, 0x0E2A, 0x0E2C, 0x0EF0, 0x0EF2, 0x0EF4),
    ):
        registers.update(
            {
                base: 323,
                base + 1: 200,
                base + 2: 646,
                base + 4: 12,
                total: 0,
                total + 1: 100,
            }
        )
    assert detect_1511_pv_count(registers) == 6
    values = decode_1511(registers, 6)
    assert values["ac_voltage"] == 230.5
    assert values["ac_energy_total"] == 414.68
    assert values["pv6_power"] == 64.6
    assert values["dc_power_total"] == 387.6


def test_decode_02b0_measurements() -> None:
    """02B0 PV count and telemetry are derived from populated inputs."""
    registers = {
        0x3009: 2256,
        0x300A: 100,
        0x300B: 5002,
        0x300F: 1234,
        0x301C: 50,
        0x301D: 0,
        0x301E: 1000,
        0x3010: 340,
        0x3011: 320,
        0x3012: 1088,
        0x301F: 20,
        0x3020: 0,
        0x3021: 400,
    }
    assert detect_02b0_pv_count(registers) == 1
    values = decode_02b0(registers, 1)
    assert values["ac_power"] == 123.4
    assert values["pv1_voltage"] == 34
    assert values["dc_power_total"] == 108.8


def test_decode_raw_alarms() -> None:
    """Alarm words remain raw and expose only a combined active state."""
    registers_1511 = {
        0x0BBB: 1,
        0x0BBC: 0,
        0x0BBD: 0,
        0x0BBE: 0,
        0x0CE4: 0,
        0x0CE5: 0,
        0x0CE6: 0,
        0x0CE7: 0,
        0x0E16: 0,
    }
    values = decode_1511_alarms(registers_1511, 1)
    assert values["alarm_global_0_raw"] == 1
    assert values["alarm_active"] == 1

    values = decode_02b0_alarms(
        {0x3003: 0, 0x3004: 0, 0x3005: 7, 0x3006: 0}
    )
    assert values["alarm_code_3_raw"] == 7
    assert values["alarm_active"] == 1
