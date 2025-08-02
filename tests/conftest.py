"""
Test configuration for NetSentinel package.
"""

import pytest
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_config():
    """Provide sample configuration for tests."""
    from netsentinel.config import Config
    return Config()


@pytest.fixture
def sample_packet_data():
    """Provide sample packet data for tests."""
    from datetime import datetime
    from netsentinel.models import NetworkPacket, Protocol
    
    return NetworkPacket(
        timestamp=datetime.now(),
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        packet_size=1500
    )
