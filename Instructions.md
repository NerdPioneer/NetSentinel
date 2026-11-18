# Development notes

NetSentinel captures live traffic or reads pcap files, parses packet fields, and flags port scans and connections to suspicious ports.

## Layout

### `netsentinel/`

- `__init__.py` — package imports; warns if a dependency is missing
- `main.py` — argparse CLI
- `config.py` — YAML or JSON, with environment overrides
- `models.py` — packet, alert, and connection dataclasses
- `services.py` — `PacketCapture` and `ThreatDetector`
- `utils.py` — logging and helpers

### `tests/`

pytest. Fixtures are in `conftest.py`. Modules are named `test_*.py`.

### Tooling

`Makefile`, `docker.sh`, `scripts/`, `requirements.txt`, `pyproject.toml`.

## Containers

- Base image `python:3.11-slim`
- System packages include `libpcap-dev`, `tcpdump`, and `tshark`
- User `netsentinel` (live capture still needs a privileged container)
- Host networking for interface access

```bash
./docker.sh build
./docker.sh dev
./docker.sh test
./docker.sh shell
```

## Code

- Missing `scapy` or `pyshark` imports raise or print an explicit error
- `NETSENTINEL_INTERFACE`, `NETSENTINEL_PORT_SCAN_THRESHOLD`, and `NETSENTINEL_LOG_LEVEL` override the config file
- Errors are logged
- Public classes and functions have docstrings
- PEP 8

## Git

Commit messages say what changed. No emojis. One change per commit. `main` is the stable branch.

## Commands

```bash
python -m pytest tests/ -v
python scripts/quick_test.py
python -m netsentinel.main --help
python scripts/generate_sample_data.py
make docker-dev
make docker-test
./docker.sh shell
```

Unit tests use crafted packets. `make docker-test` runs pytest in the container.

## Security

- The image process is user `netsentinel`
- No secrets in the tree
- Config and packet fields are read from the operator-supplied file, environment, or capture
