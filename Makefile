# NetSentinel Makefile
# Common development and deployment tasks

.PHONY: help install install-dev test lint format clean run-sample setup check docker-build docker-dev docker-test docker-clean

# Default target
help:
	@echo "NetSentinel Development Commands"
	@echo "================================"
	@echo ""
	@echo "Setup Commands:"
	@echo "  setup          - Initial project setup (install dependencies)"
	@echo "  install        - Install the package"
	@echo "  install-dev    - Install with development dependencies"
	@echo ""
	@echo "Development Commands:"
	@echo "  test           - Run unit tests"
	@echo "  lint           - Run code linting"
	@echo "  format         - Format code with black"
	@echo "  check          - Run quick functionality test"
	@echo ""
	@echo "Docker Commands:"
	@echo "  docker-build   - Build Docker images"
	@echo "  docker-dev     - Start development container"
	@echo "  docker-test    - Run tests in Docker"
	@echo "  docker-clean   - Clean up Docker resources"
	@echo ""
	@echo "Utility Commands:"
	@echo "  clean          - Clean up temporary files"
	@echo "  run-sample     - Generate and run sample data"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make docker-dev    # Start Docker development environment"
	@echo "  make docker-test   # Run tests in Docker"
	@echo "  make setup         # Local setup (if not using Docker)"

# Setup and installation
setup: install-dev
	@echo "✓ NetSentinel setup complete!"
	@echo "Run 'make check' to verify installation"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pip install -r requirements.txt

# Testing and quality
test:
	python -m pytest tests/ -v

lint:
	flake8 netsentinel/ tests/ scripts/
	mypy netsentinel/

format:
	black netsentinel/ tests/ scripts/

check:
	python scripts/quick_test.py

# Utility commands
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -f alerts.json alerts.csv *.log
	rm -rf build/ dist/

run-sample:
	python scripts/generate_sample_data.py
	@echo ""
	@echo "Sample data generated. You can now test with:"
	@echo "python -m netsentinel.main --help"

# Development server (if Flask dashboard is implemented)
serve:
	@echo "Starting NetSentinel dashboard..."
	# python -m netsentinel.dashboard

# Package building
build:
	python -m build

# Quick development cycle
dev: format lint test
	@echo "✓ Development checks passed!"

# Git hooks setup
hooks:
	@echo "Setting up git hooks..."
	@echo "#!/bin/sh" > .git/hooks/pre-commit
	@echo "make format lint" >> .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Git pre-commit hook installed"

# Docker commands
docker-build:
	@echo "Building Docker images..."
	./docker.sh build

docker-dev:
	@echo "Starting Docker development environment..."
	./docker.sh dev

docker-test:
	@echo "Running tests in Docker..."
	./docker.sh test

docker-clean:
	@echo "Cleaning Docker resources..."
	./docker.sh clean

# Quick Docker setup for new users
docker-setup: docker-build
	@echo "✓ Docker setup complete!"
	@echo "Start development with: make docker-dev"
	@echo "Run tests with: make docker-test"
