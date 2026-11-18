"""Shared fixtures for NetSentinel parsing and detection tests."""

import pytest

from netsentinel.config import Config
from netsentinel.services import ThreatDetector


@pytest.fixture
def config():
    """Config with a small scan threshold and an explicit suspicious-port list."""
    cfg = Config()
    cfg.detection.port_scan_threshold = 3
    cfg.detection.suspicious_ports = [23, 3389]
    return cfg


@pytest.fixture
def detector(config):
    """Threat detector bound to the test configuration."""
    return ThreatDetector(config)
