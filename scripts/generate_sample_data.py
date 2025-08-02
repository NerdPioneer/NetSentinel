#!/usr/bin/env python3
"""
Sample data generator for NetSentinel testing.

This script generates sample network traffic data for testing
the NetSentinel analysis capabilities.
"""

import random
import time
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent))

from netsentinel.models import NetworkPacket, Protocol


def generate_normal_traffic(count: int = 100) -> list:
    """Generate normal network traffic patterns."""
    packets = []
    base_time = datetime.now()
    
    # Common ports for normal traffic
    common_ports = [80, 443, 53, 22, 25, 993, 995]
    
    for i in range(count):
        timestamp = base_time + timedelta(seconds=i * random.uniform(0.1, 2.0))
        
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip=f"192.168.1.{random.randint(100, 200)}",
            dst_ip=f"10.0.0.{random.randint(1, 50)}",
            src_port=random.randint(32768, 65535),
            dst_port=random.choice(common_ports),
            protocol=random.choice([Protocol.TCP, Protocol.UDP]),
            packet_size=random.randint(64, 1500)
        )
        
        packets.append(packet)
    
    return packets


def generate_port_scan_traffic(target_ip: str = "192.168.1.1", 
                             scanner_ip: str = "10.0.0.100") -> list:
    """Generate port scanning traffic patterns."""
    packets = []
    base_time = datetime.now()
    
    # Scan common ports
    ports_to_scan = list(range(1, 1024))
    random.shuffle(ports_to_scan)
    
    for i, port in enumerate(ports_to_scan[:50]):  # Scan 50 ports
        timestamp = base_time + timedelta(seconds=i * 0.1)  # Fast scanning
        
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip=scanner_ip,
            dst_ip=target_ip,
            src_port=random.randint(32768, 65535),
            dst_port=port,
            protocol=Protocol.TCP,
            packet_size=64,
            tcp_flags={'SYN': True, 'ACK': False}
        )
        
        packets.append(packet)
    
    return packets


def generate_suspicious_traffic() -> list:
    """Generate various types of suspicious traffic."""
    packets = []
    base_time = datetime.now()
    
    # Suspicious ports
    suspicious_ports = [23, 135, 139, 445, 1433, 3389, 5900]
    
    for i, port in enumerate(suspicious_ports):
        timestamp = base_time + timedelta(seconds=i * 5)
        
        packet = NetworkPacket(
            timestamp=timestamp,
            src_ip="203.0.113.100",  # External IP
            dst_ip="192.168.1.50",
            src_port=random.randint(32768, 65535),
            dst_port=port,
            protocol=Protocol.TCP,
            packet_size=random.randint(64, 200)
        )
        
        packets.append(packet)
    
    return packets


def save_sample_data(filename: str = "sample_traffic.json"):
    """Generate and save sample traffic data."""
    import json
    
    all_packets = []
    
    # Generate different types of traffic
    all_packets.extend(generate_normal_traffic(200))
    all_packets.extend(generate_port_scan_traffic())
    all_packets.extend(generate_suspicious_traffic())
    
    # Sort by timestamp
    all_packets.sort(key=lambda p: p.timestamp)
    
    # Convert to dict format for JSON serialization
    packet_data = [packet.to_dict() for packet in all_packets]
    
    # Save to file
    output_path = Path(__file__).parent / filename
    with open(output_path, 'w') as f:
        json.dump(packet_data, f, indent=2, default=str)
    
    print(f"Generated {len(all_packets)} sample packets")
    print(f"Saved to: {output_path}")
    
    return all_packets


if __name__ == "__main__":
    packets = save_sample_data()
    
    # Print some statistics
    protocols = {}
    for packet in packets:
        proto = packet.protocol.value
        protocols[proto] = protocols.get(proto, 0) + 1
    
    print("\nProtocol distribution:")
    for proto, count in protocols.items():
        print(f"  {proto}: {count}")
    
    print(f"\nTime span: {packets[0].timestamp} to {packets[-1].timestamp}")
