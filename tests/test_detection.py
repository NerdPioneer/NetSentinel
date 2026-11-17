"""Detection tests using crafted NetworkPacket objects. No live capture."""

from netsentinel.config import Config
from netsentinel.models import AlertType, Protocol, ThreatLevel
from netsentinel.services import ThreatDetector

from tests.helpers import make_packet


def _analyze_ports(detector, ports, src_ip="203.0.113.10", dst_ip="198.51.100.20"):
    alerts = []
    for index, port in enumerate(ports):
        packet = make_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000 + index,
            dst_port=port,
        )
        alerts.append(detector.analyze_packet(packet))
    return alerts


def test_port_scan_alerts_only_after_threshold(detector):
    """Threshold is a strict greater-than check on unique destination ports."""
    alerts = _analyze_ports(detector, [1000, 1001, 1002, 1003])

    assert alerts[:3] == [None, None, None]
    alert = alerts[3]
    assert alert.alert_type == AlertType.PORT_SCAN
    assert alert.threat_level == ThreatLevel.MEDIUM
    assert alert.source_ip == "203.0.113.10"
    assert alert.destination_ip == "198.51.100.20"
    assert alert.title == "Port Scan Detected from 203.0.113.10"
    assert alert.description == "Source IP 203.0.113.10 has scanned 4 ports"
    assert alert.indicators["port_count"] == 4
    assert set(alert.indicators["scanned_ports"]) == {1000, 1001, 1002, 1003}
    assert alert.confidence_score == 0.8
    assert alert.recommendations

    follow_up = detector.analyze_packet(make_packet(src_port=51000, dst_port=1004))
    assert follow_up.alert_type == AlertType.PORT_SCAN
    assert follow_up.indicators["port_count"] == 5
    assert detector.get_statistics()["alerts_generated"] == 2


def test_repeated_destination_port_does_not_advance_the_scan(detector):
    alerts = _analyze_ports(detector, [80, 80, 80, 80])

    assert alerts == [None, None, None, None]
    assert detector.port_scan_tracker["203.0.113.10"] == {80}
    assert detector.get_statistics()["alerts_generated"] == 0


def test_port_scans_are_tracked_per_source(detector):
    assert _analyze_ports(detector, [1, 2, 3], src_ip="203.0.113.10") == [
        None,
        None,
        None,
    ]
    assert _analyze_ports(detector, [1, 2, 3], src_ip="203.0.113.11") == [
        None,
        None,
        None,
    ]

    scanned = detector.analyze_packet(
        make_packet(src_ip="203.0.113.10", src_port=60000, dst_port=4)
    )
    # Port 1 is already in this source's set, so the count stays at the threshold.
    still_quiet = detector.analyze_packet(
        make_packet(src_ip="203.0.113.11", src_port=60001, dst_port=1)
    )

    assert scanned.alert_type == AlertType.PORT_SCAN
    assert scanned.source_ip == "203.0.113.10"
    assert still_quiet is None


def test_incomplete_packets_are_not_counted_as_scans(detector):
    """A scan needs both a source address and a destination port."""
    missing_source = make_packet(src_ip=None, dst_port=80)
    missing_port = make_packet(dst_port=None)

    assert detector.analyze_packet(missing_source) is None
    assert detector.analyze_packet(missing_port) is None
    assert detector.port_scan_tracker == {}

    stats = detector.get_statistics()
    assert stats["packets_analyzed"] == 2
    assert stats["alerts_generated"] == 0
    # Connection tracking keys off the IP pair, so a missing port still records a flow.
    assert stats["connections_tracked"] == 1
    assert "203.0.113.10:40000-198.51.100.20:None" in detector.connections


def test_suspicious_port_alerts_when_source_address_is_absent(detector):
    alert = detector.analyze_packet(make_packet(src_ip=None, dst_port=23))

    assert alert.alert_type == AlertType.SUSPICIOUS_IP
    assert alert.source_ip is None
    assert alert.destination_port == 23
    assert detector.port_scan_tracker == {}


def test_udp_ports_count_toward_a_scan(detector):
    alerts = []
    for index, port in enumerate((10, 11, 12, 13)):
        packet = make_packet(
            src_port=2000 + index,
            dst_port=port,
            protocol=Protocol.UDP,
        )
        alerts.append(detector.analyze_packet(packet))

    assert alerts[:3] == [None, None, None]
    assert alerts[3].alert_type == AlertType.PORT_SCAN


def test_suspicious_port_alert(detector):
    packet = make_packet(
        src_ip="203.0.113.50",
        dst_ip="198.51.100.8",
        src_port=41000,
        dst_port=23,
    )
    alert = detector.analyze_packet(packet)

    assert alert.alert_type == AlertType.SUSPICIOUS_IP
    assert alert.threat_level == ThreatLevel.LOW
    assert alert.title == "Suspicious Port Access: 23"
    assert alert.description == "Connection attempt to suspicious port 23"
    assert alert.source_ip == "203.0.113.50"
    assert alert.destination_ip == "198.51.100.8"
    assert alert.destination_port == 23
    assert alert.indicators == {"suspicious_port": 23, "protocol": "TCP"}
    assert alert.confidence_score == 0.6
    assert alert.timestamp == packet.timestamp
    assert detector.get_statistics()["alerts_generated"] == 1


def test_port_scan_takes_priority_over_a_suspicious_port(detector):
    """A packet that both finishes a scan and hits a watched port is a scan."""
    alerts = _analyze_ports(detector, [1, 2, 3, 3389])

    assert alerts[:3] == [None, None, None]
    assert alerts[3].alert_type == AlertType.PORT_SCAN
    assert 3389 in alerts[3].indicators["scanned_ports"]


def test_connection_tracking_and_statistics(detector):
    first = make_packet(packet_size=100)
    second = make_packet(packet_size=40)

    assert detector.analyze_packet(first) is None
    assert detector.analyze_packet(second) is None

    stats = detector.get_statistics()
    assert stats == {
        "packets_analyzed": 2,
        "alerts_generated": 0,
        "connections_tracked": 1,
    }

    connection = detector.connections["203.0.113.10:40000-198.51.100.20:80"]
    assert connection.packet_count == 2
    assert connection.bytes_sent == 140
    assert connection.protocol == Protocol.TCP
    assert connection.first_seen == first.timestamp
    assert connection.last_seen == second.timestamp


def test_statistics_return_a_copy_and_recent_alerts_are_limited(config):
    detector = ThreatDetector(config)
    assert detector.get_recent_alerts() == []

    for index in range(3):
        detector.analyze_packet(
            make_packet(
                src_ip=f"203.0.113.{index + 1}",
                src_port=1000 + index,
                dst_port=3389,
            )
        )

    recent = detector.get_recent_alerts(limit=2)
    assert [alert.source_ip for alert in recent] == [
        "203.0.113.2",
        "203.0.113.3",
    ]
    assert len(detector.get_recent_alerts(limit=10)) == 3

    snapshot = detector.get_statistics()
    snapshot["packets_analyzed"] = 0
    assert detector.get_statistics()["packets_analyzed"] == 3


def test_yaml_configuration_drives_detection(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "detection:",
                "  port_scan_threshold: 1",
                "  suspicious_ports: []",
                "",
            ]
        )
    )
    detector = ThreatDetector(Config(str(config_file)))

    first = detector.analyze_packet(make_packet(dst_port=80))
    second = detector.analyze_packet(make_packet(src_port=40001, dst_port=81))

    assert first is None
    assert second.alert_type == AlertType.PORT_SCAN
    assert second.indicators["port_count"] == 2
