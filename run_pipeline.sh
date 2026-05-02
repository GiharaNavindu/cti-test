#!/bin/bash

################################################################################
# STIXX-CTI Pipeline - Full Run Script
# 
# Complete workflow: Fetch MITRE ATTACK -> Fetch FiGHT -> Convert -> Visualize -> Prune
# 
# Usage: ./run_full_pipeline.sh [OPTIONS]
# Options:
#   -h, --help              Show this help message
#   -c, --config CONFIG     Use custom config file (default: pipeline_config.json)
#   -s, --skip-fetch        Skip data fetching, use existing data
#   -n, --no-visualize      Skip visualization step
#   -p, --no-prune          Skip pruning step
#   -v, --verbose           Enable verbose output
#   --cleanup               Delete processed data and start fresh
#
# Examples:
#   ./run_full_pipeline.sh                      # Run complete pipeline
#   ./run_full_pipeline.sh --skip-fetch         # Use existing data only
#   ./run_full_pipeline.sh --cleanup --verbose  # Fresh run with verbose logging
#
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - use quotes to handle paths with spaces
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="${SCRIPT_DIR}"
PROJECT_ROOT="${PIPELINE_DIR}/.."
RAW_DATA_DIR="${PIPELINE_DIR}/raw_data"
PROCESSED_DATA_DIR="${PIPELINE_DIR}/processed_data"
VIZ_DIR="${PROCESSED_DATA_DIR}/visualizations"
LOG_FILE="${PIPELINE_DIR}/pipeline_execution.log"
PYTHON_VERSION_REQUIRED="3.8"

# Default flags
SKIP_FETCH=false
NO_VISUALIZE=false
NO_PRUNE=false
VERBOSE=false
CLEANUP=false
CONFIG_FILE="${PIPELINE_DIR}/pipeline_config.json"

################################################################################
# FUNCTIONS
################################################################################

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Log to file
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "${LOG_FILE}"
}

# Print header
print_header() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Print help
show_help() {
    head -33 "$0" | tail -25
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python() {
    if ! command_exists python3; then
        print_error "Python 3 is not installed. Please install Python 3.8 or higher."
        log "ERROR: Python 3 not found"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    print_info "Found Python: $PYTHON_VERSION"
    log "Python version: $PYTHON_VERSION"
}

# Setup virtual environment
setup_venv() {
    print_info "Setting up virtual environment..."
    
    if [ -d "${PIPELINE_DIR}/venv" ]; then
        print_info "Virtual environment already exists"
        if [ -f "${PIPELINE_DIR}/venv/bin/activate" ]; then
            source "${PIPELINE_DIR}/venv/bin/activate"
            print_info "Virtual environment activated"
        else
            print_warning "Virtual environment activate script not found - may be incomplete"
        fi
    else
        print_info "Creating new virtual environment..."
        if python3 -m venv "${PIPELINE_DIR}/venv"; then
            source "${PIPELINE_DIR}/venv/bin/activate"
            print_success "Virtual environment created and activated"
            log "Virtual environment created at ${PIPELINE_DIR}/venv"
        else
            print_error "Failed to create virtual environment"
            log "ERROR: Failed to create virtual environment"
            exit 1
        fi
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."
    
    local requirements_file="${PIPELINE_DIR}/requirements.txt"
    
    if [ ! -f "$requirements_file" ]; then
        print_error "requirements.txt not found at $requirements_file"
        log "ERROR: requirements.txt not found"
        print_warning "Cannot install dependencies - continuing with existing packages"
        return 0  # Don't exit, allow continuation with existing packages
    fi
    
    print_info "Upgrading pip, setuptools, and wheel..."
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1 || true
    
    print_info "Installing packages from requirements.txt..."
    if pip install -r "$requirements_file" 2>&1 | grep -q "Successfully installed\|already satisfied"; then
        print_success "All dependencies installed successfully"
        log "Dependencies installed from ${requirements_file}"
    else
        print_warning "Some dependencies may have failed - continuing anyway"
        log "WARNING: Some dependencies failed during installation"
    fi
}

# Setup directories
setup_directories() {
    print_info "Setting up directory structure..."
    
    mkdir -p "${RAW_DATA_DIR}"
    mkdir -p "${PROCESSED_DATA_DIR}"
    mkdir -p "${VIZ_DIR}"
    mkdir -p "${PIPELINE_DIR}/mcp"
    
    print_success "Directories created/verified"
    log "Directories setup complete"
}

# Cleanup function
cleanup_data() {
    print_warning "Removing processed data and visualizations..."
    
    rm -rf "${PROCESSED_DATA_DIR}"/*
    rm -f "${LOG_FILE}"
    
    print_success "Cleanup complete"
    log "Cleanup executed - processed data removed"
}

# Create default config if it doesn't exist
create_default_config() {
    if [ ! -f "${CONFIG_FILE}" ]; then
        print_info "Creating default pipeline configuration..."
        
        cat > "${CONFIG_FILE}" << 'EOF'
{
    "base_dir": ".",
    "raw_data_dir": "raw_data",
    "processed_data_dir": "processed_data",
    "fetch_attack": true,
    "fetch_fight": true,
    "convert_fight": true,
    "visualize": true,
    "prune": true,
    "log_file": "pipeline.log",
    "taxii_server": "https://attack-taxii.mitre.org/taxii2/",
    "fallback_to_github": true,
    "semantic_similarity_threshold": 25,
    "prune_output_format": "compressed"
}
EOF
        
        print_success "Default configuration created at ${CONFIG_FILE}"
        log "Default configuration created"
    fi
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -s|--skip-fetch)
                SKIP_FETCH=true
                shift
                ;;
            -n|--no-visualize)
                NO_VISUALIZE=true
                shift
                ;;
            -p|--no-prune)
                NO_PRUNE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --cleanup)
                CLEANUP=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Run Step 1: Fetch ATT&CK data
step_1_fetch_attack() {
    print_header "STEP 1: Fetching ATTACK Data from MITRE TAXII Server"
    
    if [ "$SKIP_FETCH" = true ]; then
        print_info "Skipping ATTACK fetch (--skip-fetch enabled)"
        log "Skipped ATTACK fetch"
        
        if [ ! -f "${RAW_DATA_DIR}/attack_bundle.json" ]; then
            print_warning "ATTACK bundle not found. Please run without --skip-fetch flag first"
            return 1
        fi
        return 0
    fi
    
    if [ -f "${RAW_DATA_DIR}/attack_bundle.json" ]; then
        print_info "✓ ATTACK bundle already exists"
        print_info "  Using existing data from: ${RAW_DATA_DIR}/attack_bundle.json"
        log "ATTACK bundle already exists, skipping fetch"
        return 0
    fi
    
    print_info "Connecting to MITRE ATTACK TAXII server..."
    print_info "This may take several minutes (rate limited to 10 requests per 10 minutes)..."
    
    if python3 "${PIPELINE_DIR}/fetch_attack.py"; then
        print_success "✓ Successfully fetched ATTACK data"
        print_success "✓ Saved to: ${RAW_DATA_DIR}/attack_bundle.json"
        log "ATTACK data fetch completed successfully"
        return 0
    else
        print_error "✗ Failed to fetch ATTACK data"
        log "ERROR: ATTACK data fetch failed"
        return 1
    fi
}

# Run Step 2: Fetch FiGHT data
step_2_fetch_fight() {
    print_header "STEP 2: Fetching FiGHT Framework Data"
    
    if [ "$SKIP_FETCH" = true ]; then
        print_info "Skipping FiGHT fetch (--skip-fetch enabled)"
        log "Skipped FiGHT fetch"
        
        if [ ! -f "${RAW_DATA_DIR}/fight_data.yaml" ]; then
            print_warning "FiGHT data not found. Please run without --skip-fetch flag first"
            return 1
        fi
        return 0
    fi
    
    if [ -f "${RAW_DATA_DIR}/fight_data.yaml" ]; then
        print_info "✓ FiGHT data already exists"
        print_info "  Using existing data from: ${RAW_DATA_DIR}/fight_data.yaml"
        log "FiGHT data already exists, skipping fetch"
        return 0
    fi
    
    print_info "Fetching FiGHT framework data..."
    
    if python3 "${PIPELINE_DIR}/fetch_fight.py"; then
        print_success "✓ Successfully fetched FiGHT data"
        print_success "✓ Saved to: ${RAW_DATA_DIR}/fight_data.yaml"
        log "FiGHT data fetch completed successfully"
        return 0
    else
        print_error "✗ Failed to fetch FiGHT data"
        log "ERROR: FiGHT data fetch failed"
        return 1
    fi
}

# Run Step 3: Convert FiGHT YAML to STIX
step_3_convert_fight_to_stix() {
    print_header "STEP 3: Converting FiGHT YAML to STIX Format"
    
    local fight_yaml="${RAW_DATA_DIR}/fight_data.yaml"
    local fight_stix="${RAW_DATA_DIR}/fight_stix_bundle.json"
    
    if [ ! -f "$fight_yaml" ]; then
        print_error "✗ FiGHT YAML not found at: $fight_yaml"
        print_error "  Please run Step 2 first (fetch FiGHT data)"
        log "ERROR: FiGHT YAML not found - cannot proceed with conversion"
        return 1
    fi
    
    if [ -f "$fight_stix" ]; then
        print_info "✓ FiGHT STIX bundle already exists"
        print_info "  Using existing data from: $fight_stix"
        log "FiGHT STIX bundle already exists, skipping conversion"
        return 0
    fi
    
    print_info "Converting FiGHT YAML to STIX objects..."
    
    if python3 "${PIPELINE_DIR}/convert_fight_to_stix.py"; then
        print_success "✓ Successfully converted FiGHT to STIX"
        print_success "✓ Saved to: $fight_stix"
        log "FiGHT to STIX conversion completed successfully"
        return 0
    else
        print_error "✗ Failed to convert FiGHT to STIX"
        log "ERROR: FiGHT to STIX conversion failed"
        return 1
    fi
}

# Run Step 4: Visualize threat data
step_4_visualize_threat_data() {
    print_header "STEP 4: Visualizing Threat Data"
    
    if [ "$NO_VISUALIZE" = true ]; then
        print_info "Skipping visualization (--no-visualize enabled)"
        log "Visualization skipped"
        return 0
    fi
    
    local attack_bundle="${RAW_DATA_DIR}/attck_bundle.json"
    local fight_bundle="${RAW_DATA_DIR}/fight_stix_bundle.json"
    
    if [ ! -f "$attack_bundle" ]; then
        print_error "✗ ATTACK bundle not found at: $attack_bundle"
        log "ERROR: ATTACK bundle not found for visualization"
        return 1
    fi
    
    if [ ! -f "$fight_bundle" ]; then
        print_error "✗ FiGHT STIX bundle not found at: $fight_bundle"
        log "ERROR: FiGHT STIX bundle not found for visualization"
        return 1
    fi
    
    print_info "Generating threat data visualizations..."
    print_info "  - Creating interactive network graphs"
    print_info "  - Generating statistics dashboards"
    print_info "  - Building relationship heatmaps"
    
    if python3 "${PIPELINE_DIR}/visualize_stix.py" 2>&1; then
        print_success "✓ Successfully generated visualizations"
        print_success "✓ Visualizations saved to: ${VIZ_DIR}/"
        print_info "Generated files:"
        print_info "  - attack_threat_network.html"
        print_info "  - fight_threat_network.html"
        print_info "  - statistics_dashboard.html"
        print_info "  - attack_heatmap.html"
        log "Threat data visualization completed successfully"
        return 0
    else
        print_error "✗ Failed to generate visualizations"
        log "ERROR: Threat data visualization failed"
        return 1
    fi
}

# Run Step 5: Prune STIX data
step_5_prune_stix_data() {
    print_header "STEP 5: Pruning STIX Data Using Semantic Similarity"
    
    if [ "$NO_PRUNE" = true ]; then
        print_info "Skipping pruning (--no-prune enabled)"
        log "Pruning skipped"
        return 0
    fi
    
    local attack_bundle="${RAW_DATA_DIR}/attck_bundle.json"
    local ontology_file="${PIPELINE_DIR}/oran_ontology.json"
    
    if [ ! -f "$attack_bundle" ]; then
        print_error "✗ ATTACK bundle not found at: $attack_bundle"
        log "ERROR: ATTACK bundle not found for pruning"
        return 1
    fi
    
    if [ ! -f "$ontology_file" ]; then
        print_error "✗ ORAN ontology not found at: $ontology_file"
        log "ERROR: ORAN ontology not found"
        return 1
    fi
    
    print_info "Pruning using ORAN ontology semantic similarity..."
    print_info "  - Max-Sim strategy for ontology matching"
    print_info "  - 25% minimum relevance threshold"
    print_info "  - O-DU related object tagging"
    
    if python3 "${PIPELINE_DIR}/prune_stix.py" 2>&1; then
        print_success "✓ Successfully pruned STIX data"
        print_success "✓ Pruned bundle saved to: ${PROCESSED_DATA_DIR}/"
        print_info "Generated files:"
        print_info "  - lite_bundle.json.gz (compressed pruned bundle)"
        print_info "  - oran_pruned_nodes.json (O-RAN relevant objects)"
        print_info "  - oran_pruned_edges.json (relevant relationships)"
        log "STIX data pruning completed successfully"
        return 0
    else
        print_error "✗ Failed to prune STIX data"
        log "ERROR: STIX data pruning failed"
        return 1
    fi
}

# Print execution summary
print_summary() {
    local start_time=$1
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    local minutes=$((elapsed / 60))
    local seconds=$((elapsed % 60))
    
    print_header "PIPELINE EXECUTION SUMMARY"
    
    echo "Status: $2"
    echo ""
    echo "Output Locations:"
    echo "  Raw Data:      ${RAW_DATA_DIR}/"
    echo "  Processed:     ${PROCESSED_DATA_DIR}/"
    echo "  Visualizations: ${VIZ_DIR}/"
    echo ""
    echo "Execution Time: ${minutes}m ${seconds}s"
    echo "Log File:       ${LOG_FILE}"
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Initialize log file
    > "${LOG_FILE}"
    
    # Print banner
    print_header "STIXX-CTI PIPELINE - COMPLETE THREAT INTELLIGENCE WORKFLOW"
    echo "Started: $(date +'%Y-%m-%d %H:%M:%S')"
    log "Pipeline execution started"
    
    local start_time=$(date +%s)
    
    # Parse arguments
    parse_arguments "$@"
    
    # Cleanup if requested
    if [ "$CLEANUP" = true ]; then
        cleanup_data
    fi
    
    # Pre-flight checks
    print_header "PRE-FLIGHT CHECKS"
    check_python
    setup_directories
    create_default_config
    setup_venv
    install_dependencies
    
    print_success "Pre-flight checks completed"
    echo ""
    
    # Pipeline execution with error handling
    local all_success=true
    
    step_1_fetch_attack || all_success=false
    [ "$all_success" = false ] && print_warning "Continuing with existing data..." || true
    
    step_2_fetch_fight || all_success=false
    [ "$all_success" = false ] && print_warning "Continuing with existing data..." || true
    
    step_3_convert_fight_to_stix || all_success=false
    [ "$all_success" = false ] && print_warning "Continuing with existing data..." || true
    
    step_4_visualize_threat_data || all_success=false
    
    step_5_prune_stix_data || all_success=false
    
    # Print summary
    if [ "$all_success" = true ]; then
        print_summary "$start_time" "${GREEN}✓ PIPELINE COMPLETED SUCCESSFULLY${NC}"
        log "Pipeline execution completed successfully"
        exit 0
    else
        print_summary "$start_time" "${YELLOW}⚠ PIPELINE COMPLETED WITH WARNINGS${NC}"
        log "Pipeline execution completed with warnings"
        exit 0
    fi
}

# Run main function
main "$@"
