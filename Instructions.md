# NetSentinel Development Instructions

## Project Context
NetSentinel is a modular Python project for network traffic analysis and threat detection. It's designed to simulate real-world SOC responsibilities and demonstrate technical proficiency in packet-level traffic analysis.

## Development Philosophy
- Clean, modular architecture following Python best practices
- Docker-first development to eliminate dependency issues
- Comprehensive testing with pytest
- Professional documentation and code quality
- Security-focused design patterns

## Project Structure Standards

### Core Package (`netsentinel/`)
- `__init__.py` - Package initialization with graceful import handling
- `main.py` - CLI entry point with argparse
- `config.py` - Configuration management (YAML/JSON + environment variables)
- `models.py` - Data models using dataclasses and enums
- `services.py` - Business logic (PacketCapture, ThreatDetector)
- `utils.py` - Helper functions and utilities

### Testing (`tests/`)
- Use pytest framework
- `conftest.py` for shared test configuration
- Test files named `test_*.py`
- Maintain high test coverage

### Development Tools
- `Makefile` for common development tasks
- `docker.sh` for Docker convenience commands
- `scripts/` for utility scripts
- `requirements.txt` for dependencies
- `pyproject.toml` for modern Python packaging

## Docker Standards

### Container Setup
- Use Python 3.11-slim base image
- Install system dependencies (libpcap-dev, tcpdump, etc.)
- Create non-root user for security
- Privileged mode required for packet capture
- Host networking for live interface access

### Development Workflow
```bash
./docker.sh build    # Build images
./docker.sh dev      # Start development container
./docker.sh test     # Run tests
./docker.sh shell    # Access container shell
```

## Code Standards

### Import Handling
- Use try/except for optional dependencies (scapy, pyshark)
- Graceful degradation when dependencies missing
- Clear error messages for missing packages

### Configuration
- Support YAML and JSON config files
- Environment variable overrides
- Sensible defaults for all settings
- Example configuration provided

### Error Handling
- Comprehensive logging throughout
- Graceful error handling
- User-friendly error messages
- No silent failures

### Documentation
- Docstrings for all classes and functions
- Type hints where appropriate
- README files for major components
- Examples and usage instructions

## Phase Development Approach

### Phase 1: Foundation
- Basic packet capture and parsing
- Simple threat detection (port scans)
- CLI interface
- Docker environment
- Testing framework

### Future Phases
- Enhanced detection algorithms
- Web dashboard
- Database integration
- Machine learning capabilities
- Real-time alerting

## Git Workflow

### Commit Standards
- Clear, concise commit messages
- No emojis in commit messages
- Descriptive but brief
- One logical change per commit

### Branch Strategy
- `main` branch for stable releases
- Feature branches for development
- No direct commits to main in production

## Development Environment

### Required Tools
- Docker and Docker Compose
- Git
- Text editor/IDE with Python support

### Optional Tools
- Make (for convenience commands)
- Python locally (for IDE support)

## Testing Strategy

### Unit Tests
- Test all core functionality
- Mock external dependencies
- Fast execution
- High coverage

### Integration Tests
- Test Docker environment
- End-to-end workflows
- Real packet processing

### Performance Tests
- Packet processing throughput
- Memory usage monitoring
- Resource efficiency

## Security Considerations

### Container Security
- Non-root user execution
- Minimal attack surface
- Regular base image updates
- Secure defaults

### Code Security
- Input validation
- No hardcoded secrets
- Secure configuration handling
- Principle of least privilege

## Maintenance Guidelines

### Dependencies
- Keep dependencies minimal
- Regular security updates
- Pin versions for reproducibility
- Document dependency rationale

### Documentation
- Keep documentation current
- Update examples when code changes
- Maintain architecture decisions
- Document breaking changes

## Common Commands Reference

```bash
# Development
make docker-dev          # Start development environment
make docker-test         # Run tests
./docker.sh shell        # Access container

# Testing
python scripts/quick_test.py    # Quick functionality test
python -m pytest tests/ -v     # Full test suite

# Analysis
python -m netsentinel.main --help              # CLI help
python scripts/generate_sample_data.py         # Create test data
```

## Key Design Decisions

1. **Docker-first**: Eliminates local dependency conflicts
2. **Modular architecture**: Easy to extend and maintain
3. **Configuration-driven**: Flexible without code changes
4. **Comprehensive testing**: Ensures reliability
5. **Professional structure**: Production-ready from start

## Important Notes

- Always test in Docker environment
- Maintain backward compatibility
- Document architectural decisions
- Follow Python PEP 8 style guide
- Keep security considerations in mind
- Write tests before implementing features

This document should be updated as the project evolves and new patterns emerge.
