"""
Utility Functions for NetSentinel

This module contains helper functions and utilities used throughout
the NetSentinel application.
"""

import logging
import logging.handlers
import os
import hashlib
import json
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_network_interfaces() -> List[str]:
    """Get list of available network interfaces."""
    interfaces = []
    
    try:
        import psutil
        for interface_name, interface_addresses in psutil.net_if_addrs().items():
            interfaces.append(interface_name)
    except ImportError:
        # Fallback method without psutil
        try:
            import socket
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state' in line.lower():
                    interface = line.split(':')[1].strip().split('@')[0]
                    interfaces.append(interface)
        except (subprocess.SubprocessError, FileNotFoundError):
            # Last resort - common interface names
            interfaces = ['eth0', 'wlan0', 'en0', 'lo']
    
    return interfaces


def is_private_ip(ip_address: str) -> bool:
    """Check if IP address is in private range."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False


def is_valid_ip(ip_address: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def calculate_hash(data: bytes) -> str:
    """Calculate MD5 hash of data."""
    return hashlib.md5(data).hexdigest()


def save_json_data(data: Any, file_path: str) -> None:
    """Save data to JSON file."""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json_data(file_path: str) -> Any:
    """Load data from JSON file."""
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r') as f:
        return json.load(f)


def ensure_directory(directory: str) -> None:
    """Ensure directory exists, create if it doesn't."""
    Path(directory).mkdir(parents=True, exist_ok=True)


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def timestamp_to_string(timestamp: datetime) -> str:
    """Convert timestamp to ISO format string."""
    return timestamp.isoformat()


def string_to_timestamp(timestamp_str: str) -> datetime:
    """Convert ISO format string to timestamp."""
    return datetime.fromisoformat(timestamp_str)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    import re
    # Remove or replace unsafe characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    return sanitized


def get_geolocation(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get geolocation information for IP address."""
    # This would integrate with a geolocation service
    # For now, return placeholder
    if is_private_ip(ip_address):
        return {
            'country': 'Private',
            'city': 'Private Network',
            'latitude': 0.0,
            'longitude': 0.0
        }
    
    # TODO: Integrate with actual geolocation service (MaxMind, etc.)
    return None


def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string into list of ports."""
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports


def is_suspicious_domain(domain: str) -> bool:
    """Check if domain appears suspicious (basic heuristics)."""
    suspicious_indicators = [
        # Very long domains
        len(domain) > 50,
        # Domains with many subdomains
        domain.count('.') > 5,
        # Domains with suspicious patterns
        any(char in domain for char in ['0x', 'bit.ly', 'tinyurl']),
        # Domains with many numbers
        sum(c.isdigit() for c in domain) > len(domain) * 0.3
    ]
    
    return any(suspicious_indicators)


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


class RateLimiter:
    """Simple rate limiter for API calls or operations."""
    
    def __init__(self, max_calls: int, time_window: int):
        """Initialize rate limiter."""
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    def can_proceed(self) -> bool:
        """Check if operation can proceed based on rate limit."""
        now = datetime.now()
        
        # Remove old calls outside time window
        self.calls = [call_time for call_time in self.calls 
                     if (now - call_time).seconds < self.time_window]
        
        # Check if we can make another call
        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True
        
        return False


class PacketCache:
    """Simple LRU cache for packet data."""
    
    def __init__(self, max_size: int = 1000):
        """Initialize packet cache."""
        self.max_size = max_size
        self.cache = {}
        self.access_order = []
    
    def get(self, key: str) -> Any:
        """Get item from cache."""
        if key in self.cache:
            # Move to end (most recently used)
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        return None
    
    def put(self, key: str, value: Any) -> None:
        """Put item in cache."""
        if key in self.cache:
            # Update existing
            self.access_order.remove(key)
        elif len(self.cache) >= self.max_size:
            # Remove least recently used
            lru_key = self.access_order.pop(0)
            del self.cache[lru_key]
        
        self.cache[key] = value
        self.access_order.append(key)
