#!/bin/bash
# NetSentinel Docker Utilities
# Convenient scripts for Docker operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_usage() {
    echo "NetSentinel Docker Utilities"
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build      - Build Docker images"
    echo "  run        - Run NetSentinel in container"
    echo "  dev        - Start development container"
    echo "  test       - Run tests in container"
    echo "  shell      - Get shell access to running container"
    echo "  logs       - Show container logs"
    echo "  stop       - Stop all containers"
    echo "  clean      - Clean up containers and images"
    echo "  sample     - Run with sample data"
    echo "  dashboard  - Start with web dashboard"
    echo ""
    echo "Examples:"
    echo "  $0 build       # Build images"
    echo "  $0 dev         # Start development environment"
    echo "  $0 test        # Run test suite"
    echo "  $0 sample      # Analyze sample data"
}

build_images() {
    echo -e "${BLUE}Building NetSentinel Docker images...${NC}"
    docker-compose build
    echo -e "${GREEN}✓ Build complete${NC}"
}

run_netsentinel() {
    echo -e "${BLUE}Starting NetSentinel...${NC}"
    docker-compose up netsentinel
}

start_dev() {
    echo -e "${BLUE}Starting development environment...${NC}"
    docker-compose --profile dev up -d netsentinel-dev
    echo -e "${GREEN}✓ Development container started${NC}"
    echo -e "${YELLOW}Access with: docker exec -it netsentinel-dev bash${NC}"
}

run_tests() {
    echo -e "${BLUE}Running tests in container...${NC}"
    docker-compose run --rm netsentinel python -m pytest tests/ -v
}

get_shell() {
    echo -e "${BLUE}Getting shell access...${NC}"
    if docker ps | grep -q netsentinel-dev; then
        docker exec -it netsentinel-dev bash
    elif docker ps | grep -q netsentinel; then
        docker exec -it netsentinel bash
    else
        echo -e "${RED}No running NetSentinel containers found${NC}"
        echo "Start with: $0 dev"
        exit 1
    fi
}

show_logs() {
    echo -e "${BLUE}Showing container logs...${NC}"
    docker-compose logs -f
}

stop_containers() {
    echo -e "${BLUE}Stopping all containers...${NC}"
    docker-compose down
    echo -e "${GREEN}✓ All containers stopped${NC}"
}

clean_up() {
    echo -e "${BLUE}Cleaning up containers and images...${NC}"
    docker-compose down --rmi all --volumes --remove-orphans
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

run_sample() {
    echo -e "${BLUE}Running NetSentinel with sample data...${NC}"
    
    # First generate sample data
    docker-compose run --rm netsentinel python scripts/generate_sample_data.py
    
    # Then analyze it (placeholder - would need actual sample pcap)
    echo -e "${YELLOW}Sample data generated in container${NC}"
    echo -e "${YELLOW}To analyze: docker exec -it netsentinel python -m netsentinel.main --help${NC}"
}

start_dashboard() {
    echo -e "${BLUE}Starting NetSentinel with dashboard...${NC}"
    docker-compose --profile dashboard up -d
    echo -e "${GREEN}✓ Dashboard available at http://localhost:5000${NC}"
}

# Create required directories
setup_dirs() {
    mkdir -p data logs output samples
    echo -e "${GREEN}✓ Created required directories${NC}"
}

# Main script logic
case "$1" in
    build)
        setup_dirs
        build_images
        ;;
    run)
        setup_dirs
        run_netsentinel
        ;;
    dev)
        setup_dirs
        build_images
        start_dev
        ;;
    test)
        run_tests
        ;;
    shell)
        get_shell
        ;;
    logs)
        show_logs
        ;;
    stop)
        stop_containers
        ;;
    clean)
        clean_up
        ;;
    sample)
        setup_dirs
        run_sample
        ;;
    dashboard)
        setup_dirs
        build_images
        start_dashboard
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
