#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
# Sign the Fedora 45 RPM with a new, release-scoped OpenPGP key. The private key
# lives only in the container; the exported public key is a release asset.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
fi
export SOURCE_DATE_EPOCH

version="$(grep -m1 '^version = ' pyproject.toml | cut -d '"' -f2)"
rpm="packaging/transparent-tor-proxy-${version}-1.fc45.noarch.rpm"
key="packaging/transparent-tor-proxy-${version}-fc45-rpm-key.asc"
[ -f "$rpm" ] || { echo "Missing Fedora 45 RPM: $rpm" >&2; exit 1; }
engine="$(command -v podman || command -v docker || true)"
[ -n "$engine" ] || { echo "podman or docker is required to sign the Fedora 45 RPM" >&2; exit 2; }
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$rpm" "$stage/package.rpm"

# Use the same digest-pinned Fedora image as the build. No secret is mounted,
# uploaded, or written to the host: only the signed RPM and public key cross
# the container boundary.
image="registry.fedoraproject.org/fedora:45@sha256:f5afe36c8ddb2aa5333597e900f53c5ed0267d9ebb27be765dc8ec2633aa1648"
# shellcheck disable=SC2016 # expanded by the container shell, not by this shell
"$engine" run --rm -v "$stage:/stage:z" -e TTP_VERSION="$version" "$image" sh -c '
    set -eu
    dnf install -y -q rpm-sign gnupg2 > /tmp/sign-deps.log 2>&1 || { tail -40 /tmp/sign-deps.log; exit 1; }
    export GNUPGHOME="$(mktemp -d)"
    chmod 700 "$GNUPGHOME"
    trap '\''rm -rf "$GNUPGHOME"'\'' EXIT
    gpg --batch --pinentry-mode loopback --passphrase "" --quick-generate-key \
        "TTP Fedora 45 RPM $TTP_VERSION <rpm@transparent-tor-proxy.invalid>" rsa3072 sign 0
    fingerprint="$(gpg --batch --with-colons --list-secret-keys | awk -F: '\''$1 == "fpr" { print $10; exit }'\'')"
    [ -n "$fingerprint" ] || exit 1
    gpg --batch --armor --export "$fingerprint" > /stage/rpm-key.asc
    rpmsign --addsign --key-id "$fingerprint" /stage/package.rpm
    rpmkeys --import /stage/rpm-key.asc
    rpmkeys --checksig /stage/package.rpm
    chown "$(stat -c %u:%g /stage)" /stage/package.rpm /stage/rpm-key.asc
'
mv "$stage/package.rpm" "$rpm"
mv "$stage/rpm-key.asc" "$key"

# The SBOM and checksums must describe the final signed bytes. The optional
# maintainer signature for checksums, if present, is now stale and is renewed.
python3 packaging/make_sbom.py "$rpm"
chmod 644 "$rpm.cdx.json"
(
    cd packaging
    sha256sum ./*.deb ./*.rpm ./*.tar.gz ./*.whl "$(basename "$key")" > SHA256SUMS.txt
    rm -f SHA256SUMS.txt.asc
    gpg_key_id="${GPG_KEY_ID:-34774E0CEC668426}"
    if command -v gpg >/dev/null 2>&1 && gpg --list-secret-keys "$gpg_key_id" >/dev/null 2>&1; then
        gpg --detach-sign --armor --yes --local-user "$gpg_key_id" SHA256SUMS.txt
    fi
    sha256sum --strict -c SHA256SUMS.txt
)
echo "Signed $rpm; public key: $key"
