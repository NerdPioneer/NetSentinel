"""
Data Models for NetSentinel

This module defines the data structures used throughout the NetSentinel
application for representing network packets, threats, and alerts.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum


class Protocol(Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    OTHER = "OTHER"


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    """Types of security alerts."""
    PORT_SCAN = "PORT_SCAN"
    SUSPICIOUS_IP = "SUSPICIOUS_IP"
    MALICIOUS_DOMAIN = "MALICIOUS_DOMAIN"
    UNUSUAL_TRAFFIC = "UNUSUAL_TRAFFIC"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    BRUTE_FORCE = "BRUTE_FORCE"
    DGA_DOMAIN = "DGA_DOMAIN"
    BEACON_TRAFFIC = "BEACON_TRAFFIC"


@dataclass
class NetworkPacket:
    """Represents a captured network packet."""
    
    # Timestamp
    timestamp: datetime
    
    # Layer 2 (Data Link) information
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ethernet_type: Optional[str] = None
    
    # Layer 3 (Network) information
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    ttl: Optional[int] = None
    packet_size: Optional[int] = None
    fragmented: bool = False
    
    # Layer 4 (Transport) information
    protocol: Protocol = Protocol.OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    
    # Application layer information
    payload: Optional[bytes] = None
    application_protocol: Optional[str] = None
    
    # Metadata
    interface: Optional[str] = None
    packet_id: Optional[str] = None
    raw_packet: Optional[Any] = None  # Store original packet object
    
    def __post_init__(self):
        """Post-initialization processing."""
        if self.tcp_flags is None:
            self.tcp_flags = {}
    
    @property
    def is_tcp(self) -> bool:
        """Check if packet uses TCP protocol."""
        return self.protocol == Protocol.TCP
    
    @property
    def is_udp(self) -> bool:
        """Check if packet uses UDP protocol."""
        return self.protocol == Protocol.UDP
    
    @property
    def is_syn(self) -> bool:
        """Check if TCP packet has SYN flag set."""
        return self.tcp_flags.get('SYN', False) if self.tcp_flags else False
    
    @property
    def is_fin(self) -> bool:
        """Check if TCP packet has FIN flag set."""
        return self.tcp_flags.get('FIN', False) if self.tcp_flags else False
    
    @property
    def connection_tuple(self) -> tuple:
        """Get unique connection identifier."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol.value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol.value,
            'packet_size': self.packet_size,
            'tcp_flags': self.tcp_flags,
            'interface': self.interface
        }


@dataclass
class ThreatAlert:
    """Represents a security threat alert."""
    
    # Alert identification
    alert_id: str
    timestamp: datetime
    alert_type: AlertType
    threat_level: ThreatLevel
    
    # Alert details
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    
    # Associated data
    related_packets: List[NetworkPacket] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary representation."""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type.value,
            'threat_level': self.threat_level.value,
            'title': self.title,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'confidence_score': self.confidence_score,
            'false_positive_probability': self.false_positive_probability,
            'indicators': self.indicators,
            'recommendations': self.recommendations,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'packet_count': len(self.related_packets)
        }


@dataclass
class ConnectionState:
    """Represents the state of a network connection."""
    
    connection_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    
    # Connection tracking
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # TCP-specific state
    tcp_state: Optional[str] = None
    handshake_complete: bool = False
    
    # Behavioral analysis
    is_suspicious: bool = False
    anomaly_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    
    def update_stats(self, packet: NetworkPacket) -> None:
        """Update connection statistics with new packet."""
        self.last_seen = packet.timestamp
        self.packet_count += 1
        
        if packet.packet_size:
            if packet.src_ip == self.src_ip:
                self.bytes_sent += packet.packet_size
            else:
                self.bytes_received += packet.packet_size


@dataclass
class DetectionRule:
    """Represents a threat detection rule."""
    
    rule_id: str
    name: str
    description: str
    alert_type: AlertType
    threat_level: ThreatLevel
    
    # Rule logic
    conditions: Dict[str, Any]
    threshold: Optional[int] = None
    time_window: Optional[int] = None  # seconds
    
    # Metadata
    enabled: bool = True
    author: Optional[str] = None
    created_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    
    def matches_packet(self, packet: NetworkPacket) -> bool:
        """Check if packet matches this rule's conditions."""
        # This would contain the actual rule matching logic
        # For now, return False as placeholder
        return False
