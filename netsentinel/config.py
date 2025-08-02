"""
Configuration Management for NetSentinel

This module handles loading and managing configuration settings
for the NetSentinel application.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class NetworkConfig:
    """Network-related configuration settings."""
    default_interface: str = "eth0"
    promiscuous_mode: bool = True
    packet_timeout: int = 30
    max_packet_size: int = 65535


@dataclass
class DetectionConfig:
    """Threat detection configuration settings."""
    port_scan_threshold: int = 10
    suspicious_ports: list = field(default_factory=lambda: [22, 23, 80, 443, 3389])
    dns_blacklist: list = field(default_factory=list)
    ip_whitelist: list = field(default_factory=list)
    enable_geolocation: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


@dataclass
class OutputConfig:
    """Output and alerting configuration."""
    alert_file: str = "alerts.json"
    enable_console_output: bool = True
    enable_file_output: bool = True
    alert_format: str = "json"  # json or csv


class Config:
    """Main configuration class for NetSentinel."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration from file or defaults."""
        self.network = NetworkConfig()
        self.detection = DetectionConfig()
        self.logging = LoggingConfig()
        self.output = OutputConfig()
        
        if config_file and Path(config_file).exists():
            self.load_from_file(config_file)
        else:
            self.load_from_env()
    
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from YAML or JSON file."""
        config_path = Path(config_file)
        
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() == '.yaml' or config_path.suffix.lower() == '.yml':
                    config_data = yaml.safe_load(f)
                elif config_path.suffix.lower() == '.json':
                    config_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {config_path.suffix}")
            
            self._update_from_dict(config_data)
            
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
            print("Using default configuration...")
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Network settings
        if os.getenv('NETSENTINEL_INTERFACE'):
            self.network.default_interface = os.getenv('NETSENTINEL_INTERFACE')
        
        # Detection settings
        if os.getenv('NETSENTINEL_PORT_SCAN_THRESHOLD'):
            self.detection.port_scan_threshold = int(os.getenv('NETSENTINEL_PORT_SCAN_THRESHOLD'))
        
        # Logging settings
        if os.getenv('NETSENTINEL_LOG_LEVEL'):
            self.logging.level = os.getenv('NETSENTINEL_LOG_LEVEL')
        
        if os.getenv('NETSENTINEL_LOG_FILE'):
            self.logging.log_file = os.getenv('NETSENTINEL_LOG_FILE')
    
    def _update_from_dict(self, config_data: Dict[str, Any]) -> None:
        """Update configuration from dictionary."""
        if 'network' in config_data:
            for key, value in config_data['network'].items():
                if hasattr(self.network, key):
                    setattr(self.network, key, value)
        
        if 'detection' in config_data:
            for key, value in config_data['detection'].items():
                if hasattr(self.detection, key):
                    setattr(self.detection, key, value)
        
        if 'logging' in config_data:
            for key, value in config_data['logging'].items():
                if hasattr(self.logging, key):
                    setattr(self.logging, key, value)
        
        if 'output' in config_data:
            for key, value in config_data['output'].items():
                if hasattr(self.output, key):
                    setattr(self.output, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'network': self.network.__dict__,
            'detection': self.detection.__dict__,
            'logging': self.logging.__dict__,
            'output': self.output.__dict__
        }
    
    def save_to_file(self, config_file: str) -> None:
        """Save current configuration to file."""
        config_path = Path(config_file)
        config_data = self.to_dict()
        
        with open(config_path, 'w') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config_data, f, default_flow_style=False)
            elif config_path.suffix.lower() == '.json':
                json.dump(config_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported config file format: {config_path.suffix}")
    
    @property
    def default_interface(self) -> str:
        """Get default network interface."""
        return self.network.default_interface
