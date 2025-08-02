"""
Core Services for NetSentinel

This module contains the main business logic for packet capture,
analysis, and threat detection.
"""

import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, List, Set
from collections import defaultdict, deque

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
except ImportError:
    print("Warning: Scapy not installed. Live packet capture will not work.")
    scapy = None

try:
    import pyshark
except ImportError:
    print("Warning: PyShark not installed. PCAP file analysis will not work.")
    pyshark = None

from .models import (
    NetworkPacket, ThreatAlert, ConnectionState, Protocol,
    AlertType, ThreatLevel
)
from .config import Config


class PacketCapture:
    """Handles network packet capture from live interfaces or files."""
    
    def __init__(self, config: Config, interface: Optional[str] = None, 
                 offline_file: Optional[str] = None):
        """Initialize packet capture."""
        self.config = config
        self.interface = interface or config.network.default_interface
        self.offline_file = offline_file
        self.logger = logging.getLogger(__name__)
        
        # Validate dependencies
        if not offline_file and not scapy:
            raise ImportError("Scapy is required for live packet capture")
        if offline_file and not pyshark:
            raise ImportError("PyShark is required for offline PCAP analysis")
    
    def start_capture(self, packet_handler: Callable[[NetworkPacket], None]) -> None:
        """Start packet capture and call handler for each packet."""
        if self.offline_file:
            self._capture_from_file(packet_handler)
        else:
            self._capture_live(packet_handler)
    
    def _capture_live(self, packet_handler: Callable[[NetworkPacket], None]) -> None:
        """Capture packets from live network interface."""
        self.logger.info(f"Starting live capture on interface {self.interface}")
        
        def scapy_handler(raw_packet):
            try:
                packet = self._parse_scapy_packet(raw_packet)
                if packet:
                    packet_handler(packet)
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        
        # Start packet capture
        scapy.sniff(
            iface=self.interface,
            prn=scapy_handler,
            timeout=self.config.network.packet_timeout,
            store=False
        )
    
    def _capture_from_file(self, packet_handler: Callable[[NetworkPacket], None]) -> None:
        """Capture packets from PCAP file."""
        self.logger.info(f"Starting offline analysis of {self.offline_file}")
        
        try:
            capture = pyshark.FileCapture(self.offline_file)
            
            for raw_packet in capture:
                try:
                    packet = self._parse_pyshark_packet(raw_packet)
                    if packet:
                        packet_handler(packet)
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")
            
            capture.close()
            
        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}")
            raise
    
    def _parse_scapy_packet(self, raw_packet) -> Optional[NetworkPacket]:
        """Parse a Scapy packet into NetworkPacket model."""
        try:
            packet = NetworkPacket(
                timestamp=datetime.now(),
                interface=self.interface,
                packet_id=str(uuid.uuid4()),
                raw_packet=raw_packet
            )
            
            # Layer 2 (Ethernet)
            if raw_packet.haslayer(Ether):
                ether = raw_packet[Ether]
                packet.src_mac = ether.src
                packet.dst_mac = ether.dst
                packet.ethernet_type = ether.type
            
            # Layer 3 (IP)
            if raw_packet.haslayer(IP):
                ip = raw_packet[IP]
                packet.src_ip = ip.src
                packet.dst_ip = ip.dst
                packet.ip_version = ip.version
                packet.ttl = ip.ttl
                packet.packet_size = ip.len
                packet.fragmented = bool(ip.flags & 0x1)  # More fragments flag
            
            # Layer 4 (Transport)
            if raw_packet.haslayer(TCP):
                tcp = raw_packet[TCP]
                packet.protocol = Protocol.TCP
                packet.src_port = tcp.sport
                packet.dst_port = tcp.dport
                packet.tcp_flags = {
                    'SYN': bool(tcp.flags & 0x02),
                    'ACK': bool(tcp.flags & 0x10),
                    'FIN': bool(tcp.flags & 0x01),
                    'RST': bool(tcp.flags & 0x04),
                    'PSH': bool(tcp.flags & 0x08),
                    'URG': bool(tcp.flags & 0x20)
                }
            elif raw_packet.haslayer(UDP):
                udp = raw_packet[UDP]
                packet.protocol = Protocol.UDP
                packet.src_port = udp.sport
                packet.dst_port = udp.dport
            elif raw_packet.haslayer(ICMP):
                packet.protocol = Protocol.ICMP
            elif raw_packet.haslayer(ARP):
                packet.protocol = Protocol.ARP
            
            # Extract payload
            if hasattr(raw_packet, 'payload') and raw_packet.payload:
                packet.payload = bytes(raw_packet.payload)
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error parsing Scapy packet: {e}")
            return None
    
    def _parse_pyshark_packet(self, raw_packet) -> Optional[NetworkPacket]:
        """Parse a PyShark packet into NetworkPacket model."""
        try:
            packet = NetworkPacket(
                timestamp=datetime.fromtimestamp(float(raw_packet.sniff_timestamp)),
                packet_id=str(uuid.uuid4()),
                raw_packet=raw_packet
            )
            
            # Layer 2
            if hasattr(raw_packet, 'eth'):
                packet.src_mac = raw_packet.eth.src
                packet.dst_mac = raw_packet.eth.dst
            
            # Layer 3
            if hasattr(raw_packet, 'ip'):
                packet.src_ip = raw_packet.ip.src
                packet.dst_ip = raw_packet.ip.dst
                packet.ip_version = int(raw_packet.ip.version)
                packet.ttl = int(raw_packet.ip.ttl)
                packet.packet_size = int(raw_packet.length)
            
            # Layer 4
            if hasattr(raw_packet, 'tcp'):
                packet.protocol = Protocol.TCP
                packet.src_port = int(raw_packet.tcp.srcport)
                packet.dst_port = int(raw_packet.tcp.dstport)
                
                # Parse TCP flags
                flags = raw_packet.tcp.flags
                packet.tcp_flags = {
                    'SYN': '0x00000002' in flags,
                    'ACK': '0x00000010' in flags,
                    'FIN': '0x00000001' in flags,
                    'RST': '0x00000004' in flags,
                    'PSH': '0x00000008' in flags,
                    'URG': '0x00000020' in flags
                }
            elif hasattr(raw_packet, 'udp'):
                packet.protocol = Protocol.UDP
                packet.src_port = int(raw_packet.udp.srcport)
                packet.dst_port = int(raw_packet.udp.dstport)
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error parsing PyShark packet: {e}")
            return None


class ThreatDetector:
    """Analyzes network packets for suspicious activity and threats."""
    
    def __init__(self, config: Config):
        """Initialize threat detector."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Connection tracking
        self.connections: Dict[str, ConnectionState] = {}
        self.port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self.packet_window: deque = deque(maxlen=1000)  # Last 1000 packets
        
        # Alert storage
        self.alerts: List[ThreatAlert] = []
        
        # Detection statistics
        self.stats = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'connections_tracked': 0
        }
    
    def analyze_packet(self, packet: NetworkPacket) -> Optional[ThreatAlert]:
        """Analyze a single packet for threats."""
        self.stats['packets_analyzed'] += 1
        self.packet_window.append(packet)
        
        # Update connection tracking
        self._update_connection_state(packet)
        
        # Run detection rules
        alert = None
        
        # Port scan detection
        if self._detect_port_scan(packet):
            alert = self._create_port_scan_alert(packet)
        
        # Suspicious port detection
        elif self._detect_suspicious_port(packet):
            alert = self._create_suspicious_port_alert(packet)
        
        # TODO: Add more detection methods
        
        if alert:
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            self.logger.warning(f"ALERT: {alert.title}")
        
        return alert
    
    def _update_connection_state(self, packet: NetworkPacket) -> None:
        """Update connection state tracking."""
        if not packet.src_ip or not packet.dst_ip:
            return
        
        conn_id = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
        
        if conn_id not in self.connections:
            self.connections[conn_id] = ConnectionState(
                connection_id=conn_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port or 0,
                dst_port=packet.dst_port or 0,
                protocol=packet.protocol,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp
            )
            self.stats['connections_tracked'] += 1
        
        self.connections[conn_id].update_stats(packet)
    
    def _detect_port_scan(self, packet: NetworkPacket) -> bool:
        """Detect potential port scanning activity."""
        if not packet.src_ip or not packet.dst_port:
            return False
        
        # Track unique destination ports per source IP
        self.port_scan_tracker[packet.src_ip].add(packet.dst_port)
        
        # Check if threshold exceeded
        return len(self.port_scan_tracker[packet.src_ip]) > self.config.detection.port_scan_threshold
    
    def _detect_suspicious_port(self, packet: NetworkPacket) -> bool:
        """Detect connections to suspicious ports."""
        if not packet.dst_port:
            return False
        
        return packet.dst_port in self.config.detection.suspicious_ports
    
    def _create_port_scan_alert(self, packet: NetworkPacket) -> ThreatAlert:
        """Create alert for port scan detection."""
        scanned_ports = list(self.port_scan_tracker[packet.src_ip])
        
        return ThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=packet.timestamp,
            alert_type=AlertType.PORT_SCAN,
            threat_level=ThreatLevel.MEDIUM,
            title=f"Port Scan Detected from {packet.src_ip}",
            description=f"Source IP {packet.src_ip} has scanned {len(scanned_ports)} ports",
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            indicators={
                'scanned_ports': scanned_ports,
                'port_count': len(scanned_ports)
            },
            recommendations=[
                "Investigate source IP for malicious activity",
                "Consider blocking source IP if confirmed malicious",
                "Review firewall rules for port access"
            ],
            confidence_score=0.8
        )
    
    def _create_suspicious_port_alert(self, packet: NetworkPacket) -> ThreatAlert:
        """Create alert for suspicious port access."""
        return ThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=packet.timestamp,
            alert_type=AlertType.SUSPICIOUS_IP,
            threat_level=ThreatLevel.LOW,
            title=f"Suspicious Port Access: {packet.dst_port}",
            description=f"Connection attempt to suspicious port {packet.dst_port}",
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
            destination_port=packet.dst_port,
            indicators={
                'suspicious_port': packet.dst_port,
                'protocol': packet.protocol.value
            },
            recommendations=[
                "Monitor connection for additional suspicious activity",
                "Verify if connection is legitimate"
            ],
            confidence_score=0.6
        )
    
    def get_statistics(self) -> Dict[str, int]:
        """Get detection statistics."""
        return self.stats.copy()
    
    def get_recent_alerts(self, limit: int = 10) -> List[ThreatAlert]:
        """Get most recent alerts."""
        return self.alerts[-limit:] if self.alerts else []
