#!/usr/bin/env bash
# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT
#
# Verify a published release the way a user would, from what is actually
# published - not from the files the release job had on disk.
#
#   scripts/verify-release.sh v0.4.9 [download-dir]
#
# Checks, and fails on the first thing that does not hold:
#   1. every asset has a Sigstore bundle, and every bundle has an asset;
#   2. every asset verifies against its bundle, and the signing certificate names
#      this repository's release workflow *at this tag* - a valid signature
#      made by any other workflow or ref is rejected;
#   3. SHA256SUMS.txt matches the packages it lists;
#   4. PyPI serves, for this version, exactly the wheel and sdist attached to
#      the release (same SHA-256), so what pip installs is what was signed.
#
# Needs: gh (authenticated, or GH_TOKEN), the `sigstore` CLI (pip install
# sigstore), curl, python3, sha256sum.

set -euo pipefail

tag="${1:?usage: $0 <tag, e.g. v0.4.9> [download-dir]}"
repo="${GITHUB_REPOSITORY:-onyks-os/TransparentTorProxy}"
dir="${2:-$(mktemp -d)}"
identity="https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}"
issuer="https://token.actions.githubusercontent.com"
version="${tag#v}"

command -v sigstore >/dev/null || { echo "the sigstore CLI is required: pip install sigstore" >&2; exit 2; }

echo "==> Downloading the assets of $repo $tag into $dir"
mkdir -p "$dir"
gh release download "$tag" -R "$repo" -D "$dir" --clobber
cd "$dir"

shopt -s nullglob
assets=()
for f in *; do
    case "$f" in *.sigstore.json) ;; *) assets+=("$f") ;; esac
done
[ "${#assets[@]}" -gt 0 ] || { echo "FAIL: the release has no assets" >&2; exit 1; }

echo "==> 1. Every asset has a bundle, every bundle an asset"
for f in "${assets[@]}"; do
    [ -f "$f.sigstore.json" ] || { echo "FAIL: $f has no Sigstore bundle" >&2; exit 1; }
done
for b in *.sigstore.json; do
    [ -f "${b%.sigstore.json}" ] || { echo "FAIL: bundle $b signs nothing in the release" >&2; exit 1; }
done
echo "    ${#assets[@]} assets, each with a bundle"

echo "==> 2. Signatures, bound to $identity"
for f in "${assets[@]}"; do
    if ! out="$(sigstore verify identity --cert-identity "$identity" --cert-oidc-issuer "$issuer" \
                --bundle "$f.sigstore.json" "$f" 2>&1)"; then
        echo "FAIL: $f does not verify as signed by $identity" >&2
        echo "$out" >&2
        exit 1
    fi
    echo "    OK  $f"
done

echo "==> 3. SHA256SUMS.txt"
sha256sum --strict -c SHA256SUMS.txt | sed 's/^/    /'

echo "==> 4. PyPI serves the signed Python distributions"
pypi_json="$(curl -fsSL "https://pypi.org/pypi/transparent-tor-proxy/${version}/json")"
checked=0
while IFS=$'\t' read -r name digest; do
    [ -f "$name" ] || { echo "FAIL: PyPI has $name, the release does not" >&2; exit 1; }
    local_digest="$(sha256sum "$name" | cut -d' ' -f1)"
    if [ "$local_digest" != "$digest" ]; then
        echo "FAIL: PyPI's $name ($digest) is not the signed release asset ($local_digest)" >&2
        exit 1
    fi
    echo "    OK  $name"
    checked=$((checked + 1))
done < <(printf '%s' "$pypi_json" | python3 -c '
import json, sys
for f in json.load(sys.stdin)["urls"]:
    print(f["filename"], f["digests"]["sha256"], sep="\t")')
[ "$checked" -gt 0 ] || { echo "FAIL: PyPI lists no files for $version" >&2; exit 1; }

echo "==> $repo $tag: verified"
