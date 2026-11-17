# NetSentinel Documentation

This directory is the documentation index for NetSentinel.

## Start here

- [Project README](../README.md) — summary, features, installation, and usage
- [Docker](../DOCKER.md) — container setup for development and live capture
- [Example configuration](../config_example.yaml) — scan threshold, suspicious ports, and logging

## Current behavior

NetSentinel captures live traffic or reads a pcap file, parses Ethernet, IP, and transport-layer fields, and raises alerts for port scans and connections to configured suspicious ports.

## License

NetSentinel is released under the MIT License. See [LICENSE](../LICENSE).
