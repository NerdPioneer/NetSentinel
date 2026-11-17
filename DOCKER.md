# Docker

The image installs the Python dependencies plus libpcap, tcpdump, and tshark. Live capture sets `network_mode: host` and `privileged: true` so the container can open the interface. The process runs as user `netsentinel`.

## Requirements

- Docker
- Docker Compose

## Commands

```bash
./docker.sh build
./docker.sh dev            # dev container, source tree mounted
./docker.sh shell
./docker.sh test           # pytest
./docker.sh sample         # scripts/generate_sample_data.py (JSON, not a pcap)
docker-compose up netsentinel
```

`make docker-build`, `make docker-dev`, and `make docker-test` call the same script.

Inside the dev container:

```bash
python scripts/quick_test.py
python scripts/generate_sample_data.py
python -m netsentinel.main --help
python -m pytest tests/ -v
```

List interfaces from the capture container:

```bash
docker exec -it netsentinel ip link show
```

Logs, stop, and remove containers and images:

```bash
./docker.sh logs
./docker.sh stop
./docker.sh clean
```

## Configuration

```bash
cp config_example.yaml config.yaml
```

Compose mounts `./config.yaml` at `/app/config.yaml`. `NETSENTINEL_INTERFACE` and `NETSENTINEL_LOG_LEVEL` override the interface and log level.

```bash
docker run -e NETSENTINEL_INTERFACE=eth0 -e NETSENTINEL_LOG_LEVEL=DEBUG netsentinel
```

## Volumes

- `./data` — capture data
- `./logs` — logs
- `./output` — alert output
- `./samples` — pcaps, read-only

## Troubleshooting

Bind-mount ownership:

```bash
sudo chown -R "$USER:$USER" data logs output
```

Host networking is available on Linux. Elsewhere, set `NETSENTINEL_INTERFACE` to an interface that exists in the container. `docker0` is a common name.

If `netsentinel` exits on start:

```bash
docker-compose logs netsentinel
docker run -it --entrypoint /bin/bash netsentinel
```
