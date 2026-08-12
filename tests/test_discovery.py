"""Tests for local TSUN discovery parsing."""

import pytest

from tsun_local_api.discovery import (
    parse_discovery_network,
    parse_udp_discovery_reply,
)


def test_parse_udp_reply() -> None:
    """Only private candidates in known response formats are accepted."""
    assert (
        parse_udp_discovery_reply(b"192.168.1.20,AA:BB,123", "192.168.1.20")
        == "192.168.1.20"
    )
    assert (
        parse_udp_discovery_reply(b"HF-DEVICE", "192.168.1.21")
        == "192.168.1.21"
    )
    assert parse_udp_discovery_reply(b"unrelated", "192.168.1.22") is None


def test_network_is_bounded() -> None:
    """User scans cannot exceed one private /24."""
    assert str(parse_discovery_network("192.168.1.20/24")) == "192.168.1.0/24"
    with pytest.raises(ValueError):
        parse_discovery_network("192.168.0.0/16")
    with pytest.raises(ValueError):
        parse_discovery_network("198.51.100.0/24")
