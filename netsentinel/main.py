#!/usr/bin/env python3
"""
NetSentinel Main Entry Point

This is the main entry point for the NetSentinel application.
It handles command-line arguments and orchestrates the packet capture
and analysis workflow.
"""

import argparse
import sys
import logging
from pathlib import Path

# Import core NetSentinel modules
from netsentinel.config import Config
from netsentinel.services import PacketCapture, ThreatDetector
from netsentinel.utils import setup_logging


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="NetSentinel - Network Traffic Analysis and Threat Detection"
    )
    
    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Network interface to capture packets from (e.g., eth0, wlan0)"
    )
    
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Path to pcap file for offline analysis"
    )
    
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--live",
        action="store_true",
        help="Enable live packet capture mode"
    )
    
    return parser.parse_args()


def main():
    """Main application entry point."""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = Config(args.config)
        logger.info("NetSentinel starting up...")
        
        # Initialize components
        threat_detector = ThreatDetector(config)
        
        if args.file:
            # Offline analysis mode
            logger.info(f"Starting offline analysis of {args.file}")
            packet_capture = PacketCapture(config, offline_file=args.file)
        elif args.interface or args.live:
            # Live capture mode
            interface = args.interface or config.default_interface
            logger.info(f"Starting live capture on interface {interface}")
            packet_capture = PacketCapture(config, interface=interface)
        else:
            logger.error("Must specify either --file for offline analysis or --interface/--live for live capture")
            sys.exit(1)
        
        # Start analysis
        logger.info("Beginning packet analysis...")
        packet_capture.start_capture(threat_detector.analyze_packet)
        
    except KeyboardInterrupt:
        logger.info("Shutting down NetSentinel...")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
