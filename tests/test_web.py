"""Tests for local logger metadata parsing."""

from tsun_local_api import parse_logger_metadata


def test_parse_metadata_without_confusing_both_serial_numbers() -> None:
    """The numeric logger SN and alphanumeric inverter SN remain distinct."""
    metadata = parse_logger_metadata(
        """
        <div>Device information</div>
        <div>Device serial number 1234567890</div>
        <div>Firmware version TEST_1.0</div>
        <div>MAC address 00-11-22-33-44-55</div>
        <script>webdata_sn = "Y000000000000000";</script>
        """
    )
    assert metadata.logger_sn == 1_234_567_890
    assert metadata.inverter_serial_number == "Y000000000000000"
    assert metadata.firmware_version == "TEST_1.0"
    assert metadata.mac_address == "00:11:22:33:44:55"
