#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Destructive tests stay in an offline disposable container, never on the host.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
name="ttp-vpn-check-$$"
image=${TTP_VPN_IMAGE:-localhost/ttp-vpn-check:latest}
cleanup() {
    result=$?
    if [ "$result" -ne 0 ]; then
        podman exec "$name" cat /tmp/vpn-proof/capture.log >&2 || true
        podman logs "$name" >&2 || true
        podman exec "$name" journalctl -b -u NetworkManager --no-pager -n 50 >&2 || true
    fi
    podman rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
security_args=(--security-opt label=disable)
if [ -r /sys/module/apparmor/parameters/enabled ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ]; then
    security_args+=(--security-opt apparmor=unconfined)
fi
podman run -dt --name "$name" --network none --systemd=always --ulimit core=-1:-1 \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN "${security_args[@]}" \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    -e TTP_VPN_DUALSTACK="${TTP_VPN_DUALSTACK:-0}" \
    --tmpfs /tmp -v "$repo:/src:ro" "$image" /usr/lib/systemd/systemd >/dev/null
ready=false
for _ in {1..60}; do
    boot_state=$(podman exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$boot_state" in running|degraded) ready=true; break ;; esac
    sleep 1
done
[ "$ready" = true ] || { echo "VPN fixture did not boot" >&2; exit 1; }
podman exec "$name" sh -c '
    set -eu
    install_dir=$(/opt/v/bin/python -c "import sysconfig; print(sysconfig.get_path(\"purelib\"))")
    cp -R /src/ttp "$install_dir/"
    chmod -R a+rX "$install_dir/ttp"
    systemctl start NetworkManager
    cp /src/tests/fixtures/vpn_path.py /tmp/vpn_path.py
    TTP_VPN_INTEGRATION=1 /opt/v/bin/python /tmp/vpn_path.py
'
