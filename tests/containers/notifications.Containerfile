# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Protocol fixtures only; these desktop bindings are not TTP dependencies.
FROM localhost/ttp-dnssec-debian13:latest
RUN apt-get update && apt-get install -y --no-install-recommends python3-dbus python3-gi dbus-daemon nftables && rm -rf /var/lib/apt/lists/*
