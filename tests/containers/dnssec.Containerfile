# Disposable resolver-policy tests. Build needs network; test runs use --network none.
ARG BASE_IMAGE=docker.io/library/debian:13-slim
FROM ${BASE_IMAGE}
RUN if command -v dnf >/dev/null; then \
      dnf install -y python3 python3-pip dbus-daemon iproute systemd systemd-resolved systemd-networkd && dnf clean all; \
    else \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-venv dbus iproute2 systemd systemd-resolved; \
    fi
RUN test -x /usr/lib/systemd/systemd-networkd && python3 -m venv /opt/v
COPY pyproject.toml README.md /build/
COPY ttp /build/ttp
COPY assets /build/assets
RUN /opt/v/bin/pip install /build pytest
WORKDIR /src
