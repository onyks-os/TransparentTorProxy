#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Run only disposable containers; never invoke the integration fixture on host.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${TTP_SESSION_IMAGE:-localhost/ttp-notifications-check:latest}
name="ttp-session-check-$$"
cleanup() {
    result=$?
    if [ "$result" -ne 0 ]; then
        podman logs "$name" >&2 || true
        podman inspect "$name" --format '{{json .State}}' >&2 || true
        podman exec "$name" journalctl -b --no-pager -n 100 >&2 || true
    fi
    podman rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
podman run -d --name "$name" --network none --systemd=always --ulimit core=-1:-1 \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt label=disable \
    --tmpfs /tmp -v "$repo:/src:ro" "$image" /usr/lib/systemd/systemd >/dev/null
# Early exec processes can be killed by systemd during boot. Wait for the
# manager to finish starting before launching the destructive fixture.
ready=false
for _ in {1..60}; do
    boot_state=$(podman exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$boot_state" in
        running|degraded) ready=true; break ;;
    esac
    if [ "$(podman inspect "$name" --format '{{.State.Running}}')" != true ]; then
        echo "Container exited before systemd became ready" >&2
        exit 1
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo "Container systemd did not finish booting within 60 seconds" >&2
    exit 1
fi
podman exec "$name" sh -c '
    set -eu
    install_dir=$(/opt/v/bin/python -c "import sysconfig; print(sysconfig.get_path(\"purelib\"))")
    cp -R /src/ttp "$install_dir/"
    chmod -R a+rX "$install_dir/ttp"
    mkdir -p /tmp/ttp-fixtures
    cp /src/tests/fixtures/*.py /tmp/ttp-fixtures/
    chmod -R a+rX /tmp/ttp-fixtures
    TTP_SESSION_INTEGRATION=1 /opt/v/bin/python /tmp/ttp-fixtures/session_services.py
    runuser -u nobody -- dbus-run-session -- /opt/v/bin/python /tmp/ttp-fixtures/notification_probe.py /tmp/ttp-protocol-accept.json accept
    runuser -u nobody -- dbus-run-session -- /opt/v/bin/python /tmp/ttp-fixtures/notification_probe.py /tmp/ttp-protocol-timeout.json timeout
'
