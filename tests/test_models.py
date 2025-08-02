"""
Unit tests for NetSentinel models.
"""

import unittest
from datetime import datetime

from netsentinel.models import (
    NetworkPacket, ThreatAlert, ConnectionState, Protocol,
    AlertType, ThreatLevel
)


class TestNetworkPacket(unittest.TestCase):
    """Test cases for NetworkPacket class."""
    
    def test_packet_creation(self):
        """Test creating a network packet."""
        timestamp = datetime.now()
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP
        )
        
        self.assertEqual(packet.timestamp, timestamp)
        self.assertEqual(packet.src_ip, "192.168.1.100")
        self.assertEqual(packet.dst_ip, "10.0.0.1")
        self.assertEqual(packet.protocol, Protocol.TCP)
        self.assertTrue(packet.is_tcp)
        self.assertFalse(packet.is_udp)
    
    def test_tcp_flags(self):
        """Test TCP flag handling."""
        packet = NetworkPacket(
            timestamp=datetime.now(),
            protocol=Protocol.TCP,
            tcp_flags={'SYN': True, 'ACK': False}
        )
        
        self.assertTrue(packet.is_syn)
        self.assertFalse(packet.tcp_flags.get('ACK', False))
    
    def test_connection_tuple(self):
        """Test connection tuple generation."""
        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP
        )
        
        expected_tuple = ("192.168.1.100", 12345, "10.0.0.1", 80, "TCP")
        self.assertEqual(packet.connection_tuple, expected_tuple)
    
    def test_packet_to_dict(self):
        """Test converting packet to dictionary."""
        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            protocol=Protocol.UDP
        )
        
        packet_dict = packet.to_dict()
        
        self.assertIn('timestamp', packet_dict)
        self.assertIn('src_ip', packet_dict)
        self.assertIn('dst_ip', packet_dict)
        self.assertEqual(packet_dict['protocol'], 'UDP')


class TestThreatAlert(unittest.TestCase):
    """Test cases for ThreatAlert class."""
    
    def test_alert_creation(self):
        """Test creating a threat alert."""
        timestamp = datetime.now()
        alert = ThreatAlert(
            alert_id="test-001",
            timestamp=timestamp,
            alert_type=AlertType.PORT_SCAN,
            threat_level=ThreatLevel.MEDIUM,
            title="Test Port Scan",
            description="Test port scan detected"
        )
        
        self.assertEqual(alert.alert_id, "test-001")
        self.assertEqual(alert.alert_type, AlertType.PORT_SCAN)
        self.assertEqual(alert.threat_level, ThreatLevel.MEDIUM)
        self.assertEqual(len(alert.related_packets), 0)
    
    def test_alert_to_dict(self):
        """Test converting alert to dictionary."""
        alert = ThreatAlert(
            alert_id="test-001",
            timestamp=datetime.now(),
            alert_type=AlertType.SUSPICIOUS_IP,
            threat_level=ThreatLevel.HIGH,
            title="Suspicious IP",
            description="Suspicious IP detected"
        )
        
        alert_dict = alert.to_dict()
        
        self.assertIn('alert_id', alert_dict)
        self.assertIn('alert_type', alert_dict)
        self.assertIn('threat_level', alert_dict)
        self.assertEqual(alert_dict['alert_type'], 'SUSPICIOUS_IP')
        self.assertEqual(alert_dict['threat_level'], 'HIGH')


class TestConnectionState(unittest.TestCase):
    """Test cases for ConnectionState class."""
    
    def test_connection_creation(self):
        """Test creating a connection state."""
        timestamp = datetime.now()
        connection = ConnectionState(
            connection_id="test-conn-001",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
            first_seen=timestamp,
            last_seen=timestamp
        )
        
        self.assertEqual(connection.connection_id, "test-conn-001")
        self.assertEqual(connection.src_ip, "192.168.1.100")
        self.assertEqual(connection.protocol, Protocol.TCP)
        self.assertEqual(connection.packet_count, 0)
    
    def test_connection_stats_update(self):
        """Test updating connection statistics."""
        timestamp = datetime.now()
        connection = ConnectionState(
            connection_id="test-conn-001",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
            first_seen=timestamp,
            last_seen=timestamp
        )
        
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            packet_size=1500
        )
        
        connection.update_stats(packet)
        
        self.assertEqual(connection.packet_count, 1)
        self.assertEqual(connection.bytes_sent, 1500)


class TestEnums(unittest.TestCase):
    """Test cases for enum classes."""
    
    def test_protocol_enum(self):
        """Test Protocol enum values."""
        self.assertEqual(Protocol.TCP.value, "TCP")
        self.assertEqual(Protocol.UDP.value, "UDP")
        self.assertEqual(Protocol.HTTP.value, "HTTP")
    
    def test_alert_type_enum(self):
        """Test AlertType enum values."""
        self.assertEqual(AlertType.PORT_SCAN.value, "PORT_SCAN")
        self.assertEqual(AlertType.SUSPICIOUS_IP.value, "SUSPICIOUS_IP")
    
    def test_threat_level_enum(self):
        """Test ThreatLevel enum values."""
        self.assertEqual(ThreatLevel.LOW.value, "LOW")
        self.assertEqual(ThreatLevel.CRITICAL.value, "CRITICAL")


if __name__ == '__main__':
    unittest.main()
