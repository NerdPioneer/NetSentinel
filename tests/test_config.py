"""
Unit tests for NetSentinel configuration module.
"""

import unittest
import tempfile
import json
from pathlib import Path

from netsentinel.config import Config, NetworkConfig, DetectionConfig


class TestConfig(unittest.TestCase):
    """Test cases for Config class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        # Test network defaults
        self.assertEqual(config.network.default_interface, "eth0")
        self.assertTrue(config.network.promiscuous_mode)
        self.assertEqual(config.network.packet_timeout, 30)
        
        # Test detection defaults
        self.assertEqual(config.detection.port_scan_threshold, 10)
        self.assertIn(80, config.detection.suspicious_ports)
        self.assertIn(443, config.detection.suspicious_ports)
    
    def test_config_from_dict(self):
        """Test loading configuration from dictionary."""
        config_data = {
            'network': {
                'default_interface': 'wlan0',
                'packet_timeout': 60
            },
            'detection': {
                'port_scan_threshold': 20
            }
        }
        
        config = Config()
        config._update_from_dict(config_data)
        
        self.assertEqual(config.network.default_interface, 'wlan0')
        self.assertEqual(config.network.packet_timeout, 60)
        self.assertEqual(config.detection.port_scan_threshold, 20)
    
    def test_config_to_dict(self):
        """Test converting configuration to dictionary."""
        config = Config()
        config_dict = config.to_dict()
        
        self.assertIn('network', config_dict)
        self.assertIn('detection', config_dict)
        self.assertIn('logging', config_dict)
        self.assertIn('output', config_dict)
    
    def test_config_save_load_json(self):
        """Test saving and loading configuration from JSON file."""
        config = Config()
        config.network.default_interface = 'test_interface'
        config.detection.port_scan_threshold = 15
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name
        
        try:
            config.save_to_file(config_file)
            
            # Load config from file
            loaded_config = Config(config_file)
            
            self.assertEqual(loaded_config.network.default_interface, 'test_interface')
            self.assertEqual(loaded_config.detection.port_scan_threshold, 15)
        
        finally:
            Path(config_file).unlink()


class TestNetworkConfig(unittest.TestCase):
    """Test cases for NetworkConfig class."""
    
    def test_network_config_defaults(self):
        """Test NetworkConfig default values."""
        config = NetworkConfig()
        
        self.assertEqual(config.default_interface, "eth0")
        self.assertTrue(config.promiscuous_mode)
        self.assertEqual(config.packet_timeout, 30)
        self.assertEqual(config.max_packet_size, 65535)


class TestDetectionConfig(unittest.TestCase):
    """Test cases for DetectionConfig class."""
    
    def test_detection_config_defaults(self):
        """Test DetectionConfig default values."""
        config = DetectionConfig()
        
        self.assertEqual(config.port_scan_threshold, 10)
        self.assertIsInstance(config.suspicious_ports, list)
        self.assertGreater(len(config.suspicious_ports), 0)
        self.assertFalse(config.enable_geolocation)


if __name__ == '__main__':
    unittest.main()
