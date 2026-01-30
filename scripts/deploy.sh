#!/bin/bash
# Sentinel-V Deployment Script

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    if [[ $(echo "$PYTHON_VERSION 3.8" | awk '{print ($1 < $2)}') -eq 1 ]]; then
        log_error "Python 3.8 or higher required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    log_info "Python version: $PYTHON_VERSION"
    
    # Check for virtual environment
    if [[ -z "$VIRTUAL_ENV" ]]; then
        log_warn "Not running in a virtual environment. Consider using one."
    fi
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        python3 -m pip install -r requirements.txt
    else
        log_error "requirements.txt not found"
        exit 1
    fi
    
    # Install in development mode
    python3 -m pip install -e .
    
    log_info "Dependencies installed successfully"
}

configure_system() {
    log_info "Configuring Sentinel-V system..."
    
    # Create necessary directories
    mkdir -p config logs data
    
    # Copy default configuration if it doesn't exist
    if [[ ! -f "config/sentinel.yaml" ]]; then
        if [[ -f "config/sentinel.default.yaml" ]]; then
            cp config/sentinel.default.yaml config/sentinel.yaml
            log_info "Created config/sentinel.yaml from default"
        else
            log_warn "No configuration file found. Using defaults."
        fi
    fi
    
    # Set permissions
    chmod 600 config/*.yaml 2>/dev/null || true
    chmod 755 logs data
    
    log_info "Configuration complete"
}

run_tests() {
    log_info "Running tests..."
    
    if command -v pytest &> /dev/null; then
        if pytest tests/ -v --tb=short; then
            log_info "Tests passed"
        else
            log_error "Tests failed"
            exit 1
        fi
    else
        log_warn "pytest not found. Skipping tests."
    fi
}

start_system() {
    log_info "Starting Sentinel-V system..."
    
    # Check if system is already running
    if pgrep -f "sentinel-v start" > /dev/null; then
        log_warn "Sentinel-V appears to be already running"
        read -p "Do you want to stop it and restart? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            stop_system
        else
            log_info "Exiting without changes"
            exit 0
        fi
    fi
    
    # Start in background
    nohup sentinel-v start --config config/sentinel.yaml > logs/sentinel.log 2>&1 &
    SENTINEL_PID=$!
    
    log_info "Sentinel-V started with PID: $SENTINEL_PID"
    log_info "Logs: logs/sentinel.log"
    
    # Wait a bit and check status
    sleep 3
    if ps -p $SENTINEL_PID > /dev/null; then
        log_info "✅ Sentinel-V is running"
        
        # Show status
        sentinel-v status
    else
        log_error "Failed to start Sentinel-V"
        tail -20 logs/sentinel.log
        exit 1
    fi
}

stop_system() {
    log_info "Stopping Sentinel-V system..."
    
    # Find and kill process
    SENTINEL_PIDS=$(pgrep -f "sentinel-v start" || true)
    
    if [[ -z "$SENTINEL_PIDS" ]]; then
        log_warn "No Sentinel-V processes found"
    else
        for PID in $SENTINEL_PIDS; do
            log_info "Stopping process $PID"
            kill -TERM $PID 2>/dev/null || true
        done
        
        # Wait for processes to terminate
        sleep 2
        
        # Force kill if still running
        SENTINEL_PIDS=$(pgrep -f "sentinel-v start" || true)
        for PID in $SENTINEL_PIDS; do
            log_warn "Force killing process $PID"
            kill -9 $PID 2>/dev/null || true
        done
        
        log_info "Sentinel-V stopped"
    fi
}

show_help() {
    cat << EOF
Sentinel-V Deployment Script

Usage: $0 [command]

Commands:
  install     Install and configure Sentinel-V
  start       Start the Sentinel-V system
  stop        Stop the Sentinel-V system
  restart     Restart the Sentinel-V system
  status      Show system status
  test        Run tests
  help        Show this help message

Examples:
  $0 install   # Install and configure
  $0 start     # Start the system
  $0 status    # Check status
EOF
}

case "$1" in
    install)
        check_prerequisites
        install_dependencies
        configure_system
        run_tests
        ;;
    start)
        start_system
        ;;
    stop)
        stop_system
        ;;
    restart)
        stop_system
        sleep 2
        start_system
        ;;
    status)
        if command -v sentinel-v &> /dev/null; then
            sentinel-v status
        else
            log_error "sentinel-v command not found"
        fi
        ;;
    test)
        run_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
