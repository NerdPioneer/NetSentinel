# NetSentinel

NetSentinel is a Python packet analyzer that captures live traffic or reads pcap files, parses OSI Layers 2–4, and flags port scans and other suspicious activity.

**Author:** [Ezekiel Obeisun Jr](https://github.com/NerdPioneer)  
**Repository:** [github.com/NerdPioneer/NetSentinel](https://github.com/NerdPioneer/NetSentinel)

## Features

- Live capture on a network interface (Scapy), or offline analysis of a pcap file (PyShark)
- Parsing of Ethernet, IPv4, TCP, UDP, ICMP, and ARP fields, including TCP flags
- Port-scan detection when one source address touches more unique destination ports than a configurable threshold
- Alerts when a packet targets a destination port listed as suspicious
- Per-flow connection tracking (packet counts and byte totals)
- YAML or JSON configuration, with environment-variable overrides for interface, scan threshold, and logging
- A command-line entry point, `netsentinel`

## Requirements

- Python 3.8 or newer
- Live capture: libpcap (Linux/macOS) or Npcap (Windows), plus permission to open the interface (root or `CAP_NET_RAW`)
- Pcap analysis: [tshark](https://www.wireshark.org/), which PyShark uses to read capture files

## Installation

```bash
git clone https://github.com/NerdPioneer/NetSentinel.git
cd NetSentinel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp config_example.yaml config.yaml
```

`pip install -e .` installs the package without the test tools. `requirements.txt` lists the same runtime dependencies.

Container setup, including the privileged mode live capture needs, is documented in [DOCKER.md](DOCKER.md).

## Usage

Analyze a capture file:

```bash
python -m netsentinel.main --file capture.pcap --config config.yaml --verbose
```

Capture live traffic on an interface:

```bash
sudo python -m netsentinel.main --interface eth0 --config config.yaml
```

`--live` captures on `--interface` when one is given, otherwise on `network.default_interface` from the config file (`eth0` by default).

```bash
python -m netsentinel.main --help
```

| Flag | Purpose |
| --- | --- |
| `-i`, `--interface` | Network interface for live capture |
| `--live` | Live capture mode |
| `-f`, `--file` | Pcap file for offline analysis |
| `-c`, `--config` | YAML or JSON configuration file (default: `config.yaml`) |
| `-v`, `--verbose` | Debug logging |

Provide `--file`, or one of `--interface` and `--live`. When a file and a live-capture flag are both present, NetSentinel analyzes the file. Alerts are written to the log as they are detected.

### Detection

Thresholds live under `detection` in the configuration file. See [config_example.yaml](config_example.yaml).

- **Port scan.** NetSentinel records the set of destination ports each source IP contacts. It raises a medium-severity alert when that set grows larger than `port_scan_threshold` (default: 10). The comparison is strict, so the packet that crosses the threshold is the first alert. Further packets from that source continue to alert.
- **Suspicious port.** A packet whose destination port is in `suspicious_ports` raises a low-severity alert. When the same packet also completes a port scan, the port-scan alert is the one reported. Built-in defaults watch ports 22, 23, 80, 443, and 3389. The sample configuration extends that list; edit it for the network under observation.

Each alert includes a title, description, indicators (ports contacted, or the suspicious port), a confidence score, and follow-up recommendations.

### Tests

The pytest suite covers parsing and detection with crafted packets. It runs without root and without a live interface.

```bash
pytest
```

`python scripts/quick_test.py` is a separate manual smoke check of imports, models, and detection.

## Layout

```
netsentinel/           Core package: CLI, models, capture, detection, configuration
tests/                 Pytest suite for parsing and detection
scripts/               Sample-data generator and a manual smoke check
config_example.yaml    Example configuration
```

## License

Released under the [MIT License](LICENSE). Copyright 2025 Ezekiel Obeisun Jr.
