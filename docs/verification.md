# Release Verification

Release assets published by the automated pipeline are signed with **Sigstore**
(keyless signing through GitHub Actions OIDC). Sigstore is the canonical
verification path: it is what `.github/workflows/release.yml` produces on every
tag, and it binds the artifact to the workflow that built it rather than to a
private key held on a maintainer's laptop.

## The short way

From a checkout of the repository, with [`gh`](https://cli.github.com/) and the
Sigstore client (`pip install sigstore`):

```bash
scripts/verify-release.sh v0.4.9
```

It downloads every asset of the release and fails unless each one verifies
against its bundle *and* the signing certificate names this repository's release
workflow at that tag, `SHA256SUMS.txt` matches, and PyPI serves exactly the signed
wheel and sdist. The same script runs in CI after every release and weekly
(`.github/workflows/verify-release.yml`), together with an install of the
published `.deb` and `.rpm` in clean containers.

The sections below do the same by hand, one artifact at a time.

## 1. Verify the Sigstore signature

Every published artifact ships with a matching `.sigstore.json` bundle. With the
Sigstore Python client (`pip install sigstore`), for the release tag you downloaded
(`v0.4.9` in the example):

```bash
sigstore verify identity \
  --bundle transparent-tor-proxy_0.4.9_all.deb.sigstore.json \
  --cert-identity "https://github.com/onyks-os/TransparentTorProxy/.github/workflows/release.yml@refs/tags/v0.4.9" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  transparent-tor-proxy_0.4.9_all.deb
```

Or with [cosign](https://docs.sigstore.dev/cosign/installation/):

```bash
cosign verify-blob \
  --bundle transparent-tor-proxy_0.4.9_all.deb.sigstore.json \
  --certificate-identity "https://github.com/onyks-os/TransparentTorProxy/.github/workflows/release.yml@refs/tags/v0.4.9" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  transparent-tor-proxy_0.4.9_all.deb
```

The certificate identity **must** name the tag you are verifying. A bundle that
verifies against a different ref is not a bundle for this release.

You can verify each artifact directly, or verify `SHA256SUMS.txt` once and then
check the artifacts against it:

```bash
sha256sum -c SHA256SUMS.txt
```

## 2. What each artifact contains: the SBOMs

Every package has its own CycloneDX SBOM beside it, named after it
(`transparent-tor-proxy_0.4.10_all.deb.cdx.json`, and so on), signed like the
package. It is read from the package itself by `packaging/make_sbom.py`, so it
declares:

- the package, by version and SHA-256;
- what it **contains** besides TTP - for the `.rpm`, the copy of `transitions` it
  bundles, by version and by the digest of the wheel it was unpacked from;
- what it **requires**, as the package declares it, with the version floor and who
  is expected to provide it (`pip`, or the distribution).

Releases up to 0.4.9 published a single `sbom.json` instead, which described the
build machine's Python environment rather than any package.

## 3. Optional: GPG signature

Releases built locally by a maintainer may additionally carry a detached GPG
signature `SHA256SUMS.txt.asc`. **The automated pipeline does not produce one** -
CI holds no private key, by design - so treat its absence as normal and use the
Sigstore bundle above.

When a `.asc` is present:

```bash
gpg --keyserver keys.openpgp.org --recv-keys 34774E0CEC668426
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
```

The release signing key fingerprint is:

`6AB8 C37F 2182 75FD E595  58D7 3477 4E0C EC66 8426`

You can also look the key up on [keys.openpgp.org](https://keys.openpgp.org).
`packaging/release.sh` signs with this key explicitly, so a signature made by any
other key should be treated as untrusted.

## What a failed verification means

A verification failure means the artifact is not the one this project published.
Do not install it, and please report it through the process in
[SECURITY.md](../SECURITY.md).
