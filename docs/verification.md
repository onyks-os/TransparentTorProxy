# Release Verification

Release assets published by the automated pipeline are signed with **Sigstore**
(keyless signing through GitHub Actions OIDC). Sigstore is the canonical
verification path: it is what `.github/workflows/release.yml` produces on every
tag, and it binds the artifact to the workflow that built it rather than to a
private key held on a maintainer's laptop.

## 1. Verify the Sigstore signature

Every published artifact ships with a matching `.sigstore.json` bundle. Install
[cosign](https://docs.sigstore.dev/cosign/installation/), then, for the release tag
you downloaded (`v0.4.7` in the example):

```bash
cosign verify-blob \
  --bundle transparent-tor-proxy_0.4.7_all.deb.sigstore.json \
  --certificate-identity "https://github.com/onyks-os/TransparentTorProxy/.github/workflows/release.yml@refs/tags/v0.4.7" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  transparent-tor-proxy_0.4.7_all.deb
```

The certificate identity **must** name the tag you are verifying. A bundle that
verifies against a different ref is not a bundle for this release.

You can verify each artifact directly, or verify `SHA256SUMS.txt` once and then
check the artifacts against it:

```bash
sha256sum -c SHA256SUMS.txt
```

## 2. Optional: GPG signature

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
