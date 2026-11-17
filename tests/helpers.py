"""Packet builders shared by the unit tests."""

from datetime import datetime

from netsentinel.models import NetworkPacket, Protocol


def make_packet(
    src_ip="203.0.113.10",
    dst_ip="198.51.100.20",
    src_port=40000,
    dst_port=80,
    protocol=Protocol.TCP,
    packet_size=60,
    **overrides,
):
    """Build a NetworkPacket. Keyword overrides replace any default field."""
    fields = {
        "timestamp": datetime(2025, 6, 1, 12, 0, 0),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_size": packet_size,
    }
    fields.update(overrides)
    return NetworkPacket(**fields)
