"""User-initiated discovery for local TSUN loggers."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, ip_network

DISCOVERY_CONCURRENCY = 128
DISCOVERY_TIMEOUT = 1.0
UDP_PORT = 48899
UDP_TIMEOUT = 1.5
UDP_MESSAGES = (
    b"WIFIKIT-214028-READ",
    b"HF-A11ASSISTHREAD",
    b"devicelinkfind",
)
MIN_PREFIX = 24
_PRIVATE_NETWORKS = tuple(
    ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_private_lan(address: IPv4Address) -> bool:
    """Return whether an address belongs to an RFC 1918 private LAN."""
    return any(address in network for network in _PRIVATE_NETWORKS)


def bounded_ipv4_network(address: str, prefix: int) -> IPv4Network | None:
    """Return a private scan network containing no more than 254 hosts."""
    ip = IPv4Address(address)
    if (
        not _is_private_lan(ip)
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return None
    network = ip_network(f"{ip}/{max(prefix, MIN_PREFIX)}", strict=False)
    return network if isinstance(network, IPv4Network) else None


def parse_discovery_network(value: str) -> IPv4Network:
    """Parse a private IPv4 /24-or-smaller user scan target."""
    network = ip_network(value.strip(), strict=False)
    if not isinstance(network, IPv4Network) or not all(
        _is_private_lan(address)
        for address in (network.network_address, network.broadcast_address)
    ):
        raise ValueError("A private IPv4 network is required")
    if network.prefixlen < MIN_PREFIX:
        raise ValueError("The discovery network must be /24 or smaller")
    return network


def parse_udp_discovery_reply(payload: bytes, source: str) -> str | None:
    """Return a candidate IP from a known logger reply."""
    message = payload.decode("utf-8", errors="ignore").strip("\x00\r\n ")
    if not message or payload in UDP_MESSAGES:
        return None
    candidate = ""
    if message.startswith("{"):
        try:
            candidate = str(json.loads(message).get("ip", ""))
        except (TypeError, ValueError):
            return None
    elif "," in message:
        candidate = message.split(",", 1)[0].strip()
    elif message.startswith("HF-"):
        candidate = source
    else:
        return None
    try:
        address = IPv4Address(candidate)
    except ValueError:
        return None
    if (
        not _is_private_lan(address)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        return None
    return str(address)


class _UdpDiscovery(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.hosts: set[str] = set()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if host := parse_udp_discovery_reply(data, addr[0]):
            self.hosts.add(host)


async def async_discover_udp(targets: Iterable[str]) -> list[str]:
    """Send the logger's read-only UDP discovery messages."""
    loop = asyncio.get_running_loop()
    protocol = _UdpDiscovery()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=("0.0.0.0", UDP_PORT),
            allow_broadcast=True,
        )
    except OSError:
        return []
    try:
        for target in set(targets):
            for message in UDP_MESSAGES:
                transport.sendto(message, (target, UDP_PORT))
        await asyncio.sleep(UDP_TIMEOUT)
    finally:
        transport.close()
    return sorted(protocol.hosts, key=IPv4Address)


async def _async_port_is_open(
    host: IPv4Address, port: int, semaphore: asyncio.Semaphore
) -> str | None:
    writer: asyncio.StreamWriter | None = None
    try:
        async with semaphore, asyncio.timeout(DISCOVERY_TIMEOUT):
            _, writer = await asyncio.open_connection(str(host), port)
        return str(host)
    except (OSError, TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def async_scan_hosts(hosts: Iterable[IPv4Address], port: int) -> list[str]:
    """Find hosts accepting the selected TCP port without sending data."""
    semaphore = asyncio.Semaphore(DISCOVERY_CONCURRENCY)
    results = await asyncio.gather(
        *(_async_port_is_open(host, port, semaphore) for host in hosts)
    )
    return sorted((host for host in results if host is not None), key=IPv4Address)


async def async_discover_devices(
    networks: Iterable[IPv4Network], port: int
) -> list[str]:
    """Combine read-only UDP discovery with bounded TCP validation."""
    selected = tuple(networks)
    hosts = {host for network in selected for host in network.hosts()}
    udp_targets = {
        "255.255.255.255",
        *(str(network.broadcast_address) for network in selected),
    }
    tcp_task = asyncio.create_task(async_scan_hosts(hosts, port))
    udp_hosts = await async_discover_udp(udp_targets)
    tcp_hosts = set(await tcp_task)
    unvalidated = [IPv4Address(host) for host in udp_hosts if host not in tcp_hosts]
    if unvalidated:
        tcp_hosts.update(await async_scan_hosts(unvalidated, port))
    return sorted(tcp_hosts, key=IPv4Address)
