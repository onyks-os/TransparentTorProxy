#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# TTP — Docker Integration Test Runner
# ══════════════════════════════════════════════════════════════════════
#
# Runs the full integration test suite (tests/test_integration.py)
# inside a privileged Docker container with systemd. This is the
# closest we can get to a real system without using a full VM.
#
# Why Docker + systemd?
#   - TTP needs root, nftables, and a running Tor daemon.
#   - Unit tests mock all of this, but integration tests verify the
#     REAL end-to-end flow: start → verify Tor routing → refresh → stop.
#   - The container runs systemd as PID 1, allowing `systemctl start tor`
#     to work just like on a real machine.
#
# Supported distros: debian, fedora, arch
# Each has a corresponding Dockerfile (Dockerfile.<distro>.test).
#
# Usage:
#   ./run_integration_tests.sh [debian|fedora|arch]
#
# Note: Requires Docker with --privileged support. Podman works too.
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

# Ensure we are in the project root directory before building
cd "$(dirname "$0")/.."

DISTRO="${1:-debian}"

if [ "$DISTRO" == "debian" ]; then
    DOCKERFILE="vm-helpers/Dockerfile.debian.test"
elif [ "$DISTRO" == "fedora" ]; then
    DOCKERFILE="vm-helpers/Dockerfile.fedora.test"
elif [ "$DISTRO" == "arch" ]; then
    DOCKERFILE="vm-helpers/Dockerfile.arch.test"
else
    echo "Unknown distro: $DISTRO"
    exit 1
fi

echo "==> Building Docker image for $DISTRO..."
docker build -t ttp-integration-$DISTRO -f "$DOCKERFILE" .

echo "==> Starting systemd container ($DISTRO)..."
# Required flags for systemd and nftables to work inside Docker
CID=$(docker run -d \
    --privileged \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --cgroupns=host \
    --tmpfs /tmp --tmpfs /run --tmpfs /run/lock \
    ttp-integration-$DISTRO)

# Wait for systemd to initialize
echo "==> Waiting for systemd to boot..."
sleep 5

echo "==> Running integration tests inside container..."
set +e
docker exec -it $CID /venv/bin/pytest /app/tests/test_integration.py -v -s
TEST_EXIT=$?
set -e

echo "==> Cleaning up container..."
docker stop $CID
docker rm $CID

if [ $TEST_EXIT -eq 0 ]; then
    echo "==> ALL INTEGRATION TESTS PASSED ($DISTRO)! ✅"
else
    echo "==> INTEGRATION TESTS FAILED ($DISTRO)! ❌"
    exit $TEST_EXIT
fi
