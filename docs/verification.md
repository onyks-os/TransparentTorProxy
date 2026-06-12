# Release Verification

To verify that the downloaded release assets are intact and authentic, follow these steps:

1. Download the `SHA256SUMS.txt` and `SHA256SUMS.txt.asc` files from the [Releases page](https://github.com/onyks-os/TransparentTorProxy/releases).

2. Import the author's public GPG key:
   ```bash
   gpg --keyserver keys.openpgp.org --recv-keys 34774E0CEC668426
   ```

3. Verify the GPG signature:
   ```bash
   gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
   ```

4. Verify the SHA256 checksums of the downloaded files:
   ```bash
   sha256sum -c SHA256SUMS.txt 2>&1 | grep OK
   ```

## Verifying Signer Identity

The release assets are signed using a GPG private key. The public key fingerprint is:

`6AB8 C37F 2182 75FD E595  58D7 3477 4E0C EC66 8426`

You can also search and verify the key on [keys.openpgp.org](https://keys.openpgp.org).
