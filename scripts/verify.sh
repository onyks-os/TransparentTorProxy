#!/bin/bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

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

# Lint and test go through the Makefile so this script cannot drift from what
# CI enforces: `make lint` is ruff + mypy + shellcheck + secret scan.
run_step "Lint & Type Check (make lint)" "make lint"
run_step "Unit Tests (make test)" "make test"
run_step "Fuzzing (Hypothesis)" "pytest fuzzing/fuzz_target.py -q"
run_step "Dependency Audit (pip-audit)" "pip-audit ."
# The suite behind the README's zero-leak claim. It is listed here because a
# release that has not run it is a release shipping an unverified claim; it needs
# root and the `nse` extra, so it is skipped rather than failed when either is
# missing. A skip is announced, not silent.
if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then
    if python3 -c "import nse" 2>/dev/null; then
        run_step "Zero-leak Ruleset (make test-nse)" "make test-nse"
    else
        printf " ${YELLOW}[SKIP] %-35s${NC} (network-sandbox-engine not installed: pip install -e '.[nse]')\n" "Zero-leak Ruleset"
    fi
else
    printf " ${YELLOW}[SKIP] %-35s${NC} (needs root; run with passwordless sudo or as root)\n" "Zero-leak Ruleset"
fi

run_step "Integration (Debian)" "make integration-debian"
run_step "Integration (Fedora)" "make integration-fedora"
run_step "Integration (Arch)" "make integration-arch"
# `make build` only produces the Python sdist/wheel; `make packages` is what
# builds the native .deb and .rpm this step claims to verify.
run_step "Build Artifacts (.deb, .rpm)" "make packages"

ELAPSED=$(( SECONDS - START_TIME ))
M=$(( ELAPSED / 60 ))
S=$(( ELAPSED % 60 ))

echo -e "\n${GREEN}All checks passed in ${M}m ${S}s! Ready for release.${NC}\n"
