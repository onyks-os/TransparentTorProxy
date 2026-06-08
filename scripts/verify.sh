#!/bin/bash
# TTP - Pre-release Verification Suite

# Configuration
TOTAL_EST_TIME=480 # 8 minutes in seconds
VERBOSE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse arguments
for arg in "$@"; do
  case $arg in
    -v|--verbose) VERBOSE=true ;;
  esac
done

# Start time tracking
START_TIME=$SECONDS

# Helpers

print_progress() {
    local elapsed=$(( SECONDS - START_TIME ))
    local percent=$(( elapsed * 100 / TOTAL_EST_TIME ))
    if [ $percent -gt 99 ]; then percent=99; fi
    
    local m=$(( elapsed / 60 ))
    local s=$(( elapsed % 60 ))
    local em=$(( TOTAL_EST_TIME / 60 ))
    local es=$(( TOTAL_EST_TIME % 60 ))

    printf "\r${CYAN} [%02d:%02d/%02d:%02d] [%-15s] %d%% ${NC}" \
        "$m" "$s" "$em" "$es" \
        "$(printf '#%.0s' $(seq 1 $((percent / 7))))" \
        "$percent"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr="|/-\\"
    while ps a | awk '{print $1}' | grep -q "$pid"; do
        local temp=${spinstr#?}
        printf " [%c] " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b"
        print_progress
    done
    printf "    \b\b\b\b"
}

run_step() {
    local name="$1"
    local cmd="$2"
    
    printf " %-35s" "$name"
    
    if [ "$VERBOSE" = true ]; then
        echo -e "\n${CYAN}--- Output for $name ---${NC}"
        eval "$cmd"
        local status=$?
        echo -e "${CYAN}--------------------------${NC}"
    else
        eval "$cmd" > /tmp/ttp_verify.log 2>&1 &
        local pid=$!
        spinner $pid
        wait $pid
        local status=$?
    fi

    if [ $status -eq 0 ]; then
        printf "\r ${GREEN}[PASS] %-35s${NC}\n" "$name"
    else
        printf "\r ${RED}[FAIL] %-35s${NC}\n" "$name"
        if [ "$VERBOSE" = false ]; then
            echo -e "\n${RED}Error in $name. Details:${NC}"
            cat /tmp/ttp_verify.log
        fi
        exit 1
    fi
}

# Pipeline steps

echo -e "\n${YELLOW}TTP Pre-release Verification Pipeline${NC}\n"

run_step "Formatting Check (Ruff Format)" "ruff format --check ttp/ tests/"
run_step "Linting (Ruff)" "ruff check ttp/ tests/"
run_step "Unit Tests (Pytest)" "pytest tests/ -q"
run_step "Integration (Debian)" "make integration-debian"
run_step "Integration (Fedora)" "make integration-fedora"
run_step "Integration (Arch)" "make integration-arch"
run_step "Build Artifacts (.deb, .rpm)" "make build"

ELAPSED=$(( SECONDS - START_TIME ))
M=$(( ELAPSED / 60 ))
S=$(( ELAPSED % 60 ))

echo -e "\n${GREEN}All checks passed in ${M}m ${S}s! Ready for release.${NC}\n"
