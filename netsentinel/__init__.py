"""
NetSentinel - Network Traffic Analysis and Threat Detection

A modular Python project for capturing, parsing, and analyzing network traffic
to detect suspicious activity using custom security logic.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

# Core modules - import with error handling
try:
    from .config import Config
    from .models import NetworkPacket, ThreatAlert
    from .services import PacketCapture, ThreatDetector
    
    __all__ = [
        "Config",
        "NetworkPacket", 
        "ThreatAlert",
        "PacketCapture",
        "ThreatDetector"
    ]
except ImportError as e:
    # Handle missing dependencies gracefully
    print(f"Warning: Some NetSentinel modules could not be imported: {e}")
    print("This is normal if dependencies are not yet installed.")
    print("Run: pip install -r requirements.txt")
    
    __all__ = []
