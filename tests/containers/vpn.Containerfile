# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Local, disposable WireGuard peer. No provider or Internet access at test time.
FROM localhost/ttp-dnssec-debian13:latest
RUN apt-get update && apt-get install -y --no-install-recommends network-manager wireguard-tools nftables tcpdump && rm -rf /var/lib/apt/lists/*
