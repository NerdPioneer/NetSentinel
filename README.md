# NetSentinel

NetSentinel is a Python packet analyzer that captures live traffic or reads pcap files, parses OSI Layers 2–4, and flags port scans and other suspicious activity.

**Author:** [Ezekiel Obeisun Jr](https://github.com/NerdPioneer)  
**Repository:** [github.com/NerdPioneer/NetSentinel](https://github.com/NerdPioneer/NetSentinel)

## Features

- Live capture on a network interface (Scapy), or offline analysis of a pcap file (PyShark)
- Parsing of Ethernet, IPv4, TCP, UDP, ICMP, and ARP fields, including TCP flags
- Port-scan detection when one source address contacts more unique destination ports than a configurable threshold
- Alerts when a packet uses a destination port listed as suspicious
- Per-flow connection tracking (packet counts and byte totals)
- YAML or JSON configuration, with environment-variable overrides for interface, scan threshold, and logging
- Console script: `netsentinel`

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

- **Port scan.** Unique destination ports are counted per source IP. A medium-severity alert fires when that count is greater than `port_scan_threshold` (default 10). The packet that crosses the threshold is the first alert, and later packets from that source alert as well.
- **Suspicious port.** A destination port in `suspicious_ports` raises a low-severity alert. If that same packet also crosses the scan threshold, the alert is a port scan. The built-in list is 22, 23, 80, 443, and 3389. `config_example.yaml` also includes 135, 139, 445, 1433, and 5900.

Each alert has a title, description, indicators, a confidence score, and recommendations.

### Tests

The pytest suite runs parsing and detection on crafted packets. No interface is opened.

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
