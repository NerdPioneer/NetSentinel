#!/usr/bin/env python3
"""
Quick test script for NetSentinel functionality.

This script performs basic functionality tests to ensure
the core components are working correctly.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from netsentinel.config import Config
    from netsentinel.models import NetworkPacket, Protocol, AlertType, ThreatLevel
    from netsentinel.services import ThreatDetector
    from netsentinel.utils import setup_logging, is_valid_ip, is_private_ip
    
    print("✓ All imports successful")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


def test_config():
    """Test configuration loading."""
    print("\n--- Testing Configuration ---")
    
    try:
        config = Config()
        print(f"✓ Default interface: {config.network.default_interface}")
        print(f"✓ Port scan threshold: {config.detection.port_scan_threshold}")
        print(f"✓ Suspicious ports: {len(config.detection.suspicious_ports)}")
        return True
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        return False


def test_packet_creation():
    """Test packet model creation."""
    print("\n--- Testing Packet Creation ---")
    
    try:
        packet = NetworkPacket(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
            packet_size=1500
        )
        
        print(f"✓ Packet created: {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
        print(f"✓ Protocol: {packet.protocol.value}")
        print(f"✓ Connection tuple: {packet.connection_tuple}")
        return True
    except Exception as e:
        print(f"✗ Packet creation failed: {e}")
        return False


def test_threat_detection():
    """Test threat detection logic."""
    print("\n--- Testing Threat Detection ---")
    
    try:
        config = Config()
        detector = ThreatDetector(config)
        
        # Create packets that should trigger port scan detection
        for port in range(80, 95):  # 15 ports, above default threshold of 10
            packet = NetworkPacket(
                timestamp=datetime.now(),
                src_ip="10.0.0.100",
                dst_ip="192.168.1.1",
                src_port=12345,
                dst_port=port,
                protocol=Protocol.TCP
            )
            
            alert = detector.analyze_packet(packet)
            if alert:
                print(f"✓ Alert generated: {alert.title}")
                break
        
        stats = detector.get_statistics()
        print(f"✓ Packets analyzed: {stats['packets_analyzed']}")
        print(f"✓ Alerts generated: {stats['alerts_generated']}")
        
        return True
    except Exception as e:
        print(f"✗ Threat detection test failed: {e}")
        return False


def test_utilities():
    """Test utility functions."""
    print("\n--- Testing Utilities ---")
    
    try:
        # Test IP validation
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("invalid_ip") == False
        print("✓ IP validation working")
        
        # Test private IP detection
        assert is_private_ip("192.168.1.1") == True
        assert is_private_ip("8.8.8.8") == False
        print("✓ Private IP detection working")
        
        # Test logging setup
        setup_logging(verbose=True)
        print("✓ Logging setup successful")
        
        return True
    except Exception as e:
        print(f"✗ Utilities test failed: {e}")
        return False


def run_all_tests():
    """Run all basic functionality tests."""
    print("NetSentinel Quick Test Suite")
    print("=" * 40)
    
    tests = [
        test_config,
        test_packet_creation,
        test_threat_detection,
        test_utilities
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 40)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print(f"Success rate: {passed / (passed + failed) * 100:.1f}%")
    
    if failed == 0:
        print("\n🎉 All tests passed! NetSentinel core functionality is working.")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Check the output above for details.")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
