# NetSentinel Phase 1 Status Report
Phase 1 focuses on building a minimal but functional version of NetSentinel. The goal is to capture network traffic, extract relevant metadata, apply basic detection rules, and log results for analysis. This lays the foundation for all future functionality.

---

## Objective

- Build a CLI-based packet analyzer using Python
- Capture live packets (or read from a `.pcap`)
- Extract fields such as IP addresses, ports, protocols, and DNS queries
- Apply 1–2 simple detection rules (e.g., port scan, DNS anomaly)
- Output results to console and save logs to file

---

## Why This Phase Matters

## Learn OSI Layers 2–4 in Context
- Layer 2: Ethernet, MAC addresses (optional at this stage)
- Layer 3: IP routing, addressing, and fragmentation
- Layer 4: TCP/UDP ports and session behavior
This builds the core understanding needed to detect real threats.

## Develop Real-World Packet Analysis Skills
- Learn how to parse traffic programmatically
- Understand how tools like Wireshark, Suricata, and Zeek function under the hood

## Directory Structure

NetSentinel/
├── netsentinel/                    # Core package
│   ├── __init__.py                # Package initialization
│   ├── main.py                    # CLI entry point
│   ├── config.py                  # Configuration management
│   ├── models.py                  # Data models (Packet, Alert, etc.)
│   ├── services.py                # Core business logic
│   └── utils.py                   # Helper functions
├── tests/                         # Unit tests
│   ├── conftest.py               # Test configuration
│   ├── test_config.py            # Config tests
│   └── test_models.py            # Model tests
├── scripts/                       # Utility scripts
│   ├── generate_sample_data.py   # Sample data generator
│   └── quick_test.py             # Functionality tester
├── docs/                          # Documentation
│   └── README.md                 # Documentation index
├── Docker files                   # Container setup
│   ├── Dockerfile                # Production container
│   ├── Dockerfile.dev            # Development container
│   ├── docker-compose.yml        # Service orchestration
│   ├── .dockerignore             # Docker ignore rules
│   └── docker.sh                 # Docker utilities
├── Configuration files
│   ├── requirements.txt          # Python dependencies
│   ├── pyproject.toml            # Modern Python packaging
│   ├── setup.py                  # Package setup
│   ├── config_example.yaml       # Sample configuration
│   └── .gitignore               # Git ignore rules
├── Development tools
│   ├── Makefile                  # Development commands
│   └── DOCKER.md                # Docker quick start
└── README.md                     # Project documentation
```
