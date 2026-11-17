"""Parser tests. Crafted Scapy packets and PyShark-shaped fixtures; no capture."""

from datetime import datetime

import pytest

from netsentinel.config import Config
from netsentinel.models import AlertType, Protocol
from netsentinel.services import PacketCapture, ThreatDetector

pytest.importorskip("scapy")

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402

SRC_MAC = "aa:bb:cc:dd:ee:ff"
DST_MAC = "11:22:33:44:55:66"


@pytest.fixture
def capture():
    """Parser instance. Construction does not open an interface."""
    return PacketCapture(Config(), interface="eth0")


def _captured(payload):
    """Serialize and re-dissect so header lengths match a packet off the wire."""
    return Ether(bytes(Ether(src=SRC_MAC, dst=DST_MAC) / payload))


def test_parse_tcp_syn_packet(capture):
    raw = _captured(
        IP(src="203.0.113.10", dst="198.51.100.5", ttl=64)
        / TCP(sport=44444, dport=22, flags="S")
    )
    packet = capture._parse_scapy_packet(raw)

    assert packet is not None
    assert packet.interface == "eth0"
    assert packet.packet_id
    assert packet.src_mac == SRC_MAC
    assert packet.dst_mac == DST_MAC
    assert packet.ethernet_type == 2048
    assert packet.src_ip == "203.0.113.10"
    assert packet.dst_ip == "198.51.100.5"
    assert packet.ip_version == 4
    assert packet.ttl == 64
    assert packet.packet_size == raw[IP].len
    assert packet.fragmented is False
    assert packet.protocol == Protocol.TCP
    assert packet.src_port == 44444
    assert packet.dst_port == 22
    assert packet.tcp_flags == {
        "SYN": True,
        "ACK": False,
        "FIN": False,
        "RST": False,
        "PSH": False,
        "URG": False,
    }
    assert packet.is_tcp
    assert packet.is_syn
    assert isinstance(packet.payload, bytes)
    assert packet.payload


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (
            "SA",
            {
                "SYN": True,
                "ACK": True,
                "FIN": False,
                "RST": False,
                "PSH": False,
                "URG": False,
            },
        ),
        (
            "F",
            {
                "SYN": False,
                "ACK": False,
                "FIN": True,
                "RST": False,
                "PSH": False,
                "URG": False,
            },
        ),
        (
            "R",
            {
                "SYN": False,
                "ACK": False,
                "FIN": False,
                "RST": True,
                "PSH": False,
                "URG": False,
            },
        ),
        (
            "P",
            {
                "SYN": False,
                "ACK": False,
                "FIN": False,
                "RST": False,
                "PSH": True,
                "URG": False,
            },
        ),
        (
            "U",
            {
                "SYN": False,
                "ACK": False,
                "FIN": False,
                "RST": False,
                "PSH": False,
                "URG": True,
            },
        ),
    ],
)
def test_parse_tcp_flag_bits(capture, flags, expected):
    raw = _captured(
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags=flags)
    )
    packet = capture._parse_scapy_packet(raw)

    assert packet.tcp_flags == expected


def test_parse_udp_packet(capture):
    raw = _captured(
        IP(src="10.1.2.3", dst="10.1.2.4", ttl=32) / UDP(sport=53000, dport=53)
    )
    packet = capture._parse_scapy_packet(raw)

    assert packet.protocol == Protocol.UDP
    assert packet.is_udp
    assert packet.src_port == 53000
    assert packet.dst_port == 53
    assert packet.ttl == 32
    assert packet.tcp_flags == {}
    assert packet.fragmented is False


def test_parse_icmp_packet(capture):
    raw = _captured(IP(src="1.1.1.1", dst="8.8.8.8", ttl=57) / ICMP())
    packet = capture._parse_scapy_packet(raw)

    assert packet.protocol == Protocol.ICMP
    assert packet.src_ip == "1.1.1.1"
    assert packet.dst_ip == "8.8.8.8"
    assert packet.ttl == 57
    assert packet.src_port is None
    assert packet.dst_port is None


def test_parse_arp_packet(capture):
    raw = _captured(
        ARP(
            psrc="192.168.0.2",
            pdst="192.168.0.1",
            hwsrc=SRC_MAC,
            hwdst="00:00:00:00:00:00",
        )
    )
    packet = capture._parse_scapy_packet(raw)

    assert packet.protocol == Protocol.ARP
    assert packet.src_mac == SRC_MAC
    assert packet.dst_mac == DST_MAC
    assert packet.ethernet_type == 2054
    assert packet.src_ip is None
    assert packet.dst_ip is None


def test_parse_fragmented_ip_packet(capture):
    raw = _captured(
        IP(src="10.0.0.8", dst="10.0.0.9", flags="MF") / UDP(sport=9, dport=53) / b"abc"
    )
    packet = capture._parse_scapy_packet(raw)

    assert packet.fragmented is True
    assert packet.protocol == Protocol.UDP
    assert packet.dst_port == 53


def test_parse_scapy_error_returns_none(capture):
    class Unreadable:
        def haslayer(self, layer):
            raise RuntimeError("malformed packet")

    assert capture._parse_scapy_packet(Unreadable()) is None


def test_parse_pyshark_tcp_packet(capture):
    raw = _PysharkPacket(
        sniff_timestamp="1700000000.5",
        length="120",
        eth=_Layer(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02"),
        ip=_Layer(src="192.0.2.10", dst="192.0.2.20", version="4", ttl="64"),
        tcp=_Layer(srcport="443", dstport="51515", flags="0x00000002,0x00000010"),
    )
    packet = capture._parse_pyshark_packet(raw)

    assert packet.timestamp == datetime.fromtimestamp(1700000000.5)
    assert packet.src_mac == "aa:bb:cc:dd:ee:01"
    assert packet.dst_mac == "aa:bb:cc:dd:ee:02"
    assert packet.src_ip == "192.0.2.10"
    assert packet.dst_ip == "192.0.2.20"
    assert packet.ip_version == 4
    assert packet.ttl == 64
    assert packet.packet_size == 120
    assert packet.protocol == Protocol.TCP
    assert packet.src_port == 443
    assert packet.dst_port == 51515
    assert packet.tcp_flags == {
        "SYN": True,
        "ACK": True,
        "FIN": False,
        "RST": False,
        "PSH": False,
        "URG": False,
    }


def test_parse_pyshark_udp_packet(capture):
    raw = _PysharkPacket(
        sniff_timestamp="1700000001",
        length="80",
        ip=_Layer(src="198.51.100.4", dst="198.51.100.5", version="4", ttl="16"),
        udp=_Layer(srcport="12345", dstport="53"),
    )
    packet = capture._parse_pyshark_packet(raw)

    assert packet.protocol == Protocol.UDP
    assert packet.src_port == 12345
    assert packet.dst_port == 53
    assert packet.src_mac is None
    assert packet.tcp_flags == {}


def test_parse_pyshark_invalid_timestamp_returns_none(capture):
    raw = _PysharkPacket(sniff_timestamp="not-a-timestamp")

    assert capture._parse_pyshark_packet(raw) is None


def test_parsed_packets_trigger_port_scan_detection(capture):
    """Fields produced by the Scapy parser are sufficient for scan detection."""
    config = Config()
    config.detection.port_scan_threshold = 3
    config.detection.suspicious_ports = []
    detector = ThreatDetector(config)

    alerts = []
    for port in (1000, 1001, 1002, 1003):
        raw = _captured(
            IP(src="203.0.113.10", dst="198.51.100.20")
            / TCP(sport=44444, dport=port, flags="S")
        )
        parsed = capture._parse_scapy_packet(raw)
        assert parsed.src_ip == "203.0.113.10"
        assert parsed.dst_port == port
        alerts.append(detector.analyze_packet(parsed))

    assert alerts[:3] == [None, None, None]
    assert alerts[3].alert_type == AlertType.PORT_SCAN
    assert alerts[3].indicators["port_count"] == 4


class _Layer:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


class _PysharkPacket:
    """Minimal stand-in for a pyshark packet. FileCapture is not required."""

    def __init__(self, **attrs):
        self.__dict__.update(attrs)
