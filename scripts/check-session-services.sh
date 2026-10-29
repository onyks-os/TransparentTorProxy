#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Run only disposable containers; never invoke the integration fixture on host.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${TTP_SESSION_IMAGE:-localhost/ttp-notifications-check:latest}
name="ttp-session-check-$$"
cleanup() { podman rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
podman run -d --name "$name" --network none --systemd=always \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt label=disable \
    --tmpfs /tmp -v "$repo:/src:ro" "$image" /usr/lib/systemd/systemd >/dev/null
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
