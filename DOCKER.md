# NetSentinel Docker Quick Start

This guide will get you up and running with NetSentinel using Docker, eliminating the need to install dependencies locally.

## Prerequisites

- Docker and Docker Compose installed
- Basic understanding of Docker commands

## Quick Start Commands

### 1. Build the Docker Images
```bash
# Using the convenience script
./docker.sh build

# Or using Make
make docker-build

# Or directly with Docker Compose
docker-compose build
```

### 2. Start Development Environment
```bash
# Start interactive development container
./docker.sh dev

# This creates a container with all dependencies installed
# Access the container with:
docker exec -it netsentinel-dev bash
```

### 3. Run Tests
```bash
# Run the test suite in Docker
./docker.sh test

# Or using Make
make docker-test
```

### 4. Generate and Test Sample Data
```bash
# Generate sample network traffic data
./docker.sh sample

# This creates sample data you can analyze
```

## Development Workflow

### Starting Development
```bash
# 1. Build images (first time only)
./docker.sh build

# 2. Start development container
./docker.sh dev

# 3. Get shell access
./docker.sh shell
```

### Inside the Container
Once inside the development container, you can:

```bash
# Run quick tests
python scripts/quick_test.py

# Generate sample data
python scripts/generate_sample_data.py

# Run NetSentinel with help
python -m netsentinel.main --help

# Run unit tests
python -m pytest tests/ -v

# Start interactive Python shell
python -c "import netsentinel; print('NetSentinel loaded successfully!')"
```

### Network Interface Access
For live packet capture, the container needs privileged access:

```bash
# Run with network interface access
docker-compose up netsentinel

# Check available interfaces inside container
docker exec -it netsentinel ip link show
```

## Configuration

### Using Custom Configuration
1. Copy the example config: `cp config_example.yaml config.yaml`
2. Edit `config.yaml` for your needs
3. The Docker Compose setup will automatically mount this file

### Environment Variables
You can also configure NetSentinel using environment variables:

```bash
# Set in docker-compose.yml or pass directly
docker run -e NETSENTINEL_INTERFACE=eth0 -e NETSENTINEL_LOG_LEVEL=DEBUG netsentinel
```

## Data Persistence

Docker volumes are configured for:
- `./data` - Captured network data
- `./logs` - Application logs  
- `./output` - Analysis results and alerts
- `./samples` - Sample PCAP files (read-only)

## Useful Docker Commands

```bash
# View container logs
./docker.sh logs

# Stop all containers
./docker.sh stop

# Clean up everything (containers, images, volumes)
./docker.sh clean

# Start with web dashboard (future feature)
./docker.sh dashboard
```

## Phase 1 Development Tasks

With Docker set up, you can now work on Phase 1 objectives:

1. **Packet Capture Testing**:
   ```bash
   # Inside container
   python -c "
   from netsentinel.services import PacketCapture
   from netsentinel.config import Config
   config = Config()
   print('Packet capture module loaded successfully')
   "
   ```

2. **Threat Detection Testing**:
   ```bash
   # Inside container  
   python -c "
   from netsentinel.services import ThreatDetector
   from netsentinel.config import Config
   detector = ThreatDetector(Config())
   print('Threat detector initialized')
   "
   ```

3. **Model Validation**:
   ```bash
   # Inside container
   python scripts/quick_test.py
   ```

## Troubleshooting

### Permission Issues
If you encounter permission issues:
```bash
# Fix directory permissions
sudo chown -R $USER:$USER data logs output
```

### Network Interface Issues
For packet capture on macOS/Windows:
```bash
# Use host networking (Linux only)
docker run --network host --privileged netsentinel

# Or specify interface
docker run -e NETSENTINEL_INTERFACE=docker0 netsentinel
```

### Container Won't Start
```bash
# Check container logs
docker-compose logs netsentinel

# Debug with interactive shell
docker run -it --entrypoint /bin/bash netsentinel
```

## Next Steps

Once Docker is working:
1. Test the core functionality with `./docker.sh test`
2. Generate sample data with `./docker.sh sample`  
3. Start developing Phase 1 features inside the container
4. Use `./docker.sh shell` for interactive development

The containerized environment gives you a consistent, reproducible setup for NetSentinel development without local dependency conflicts!
