# Secrets Management Policy

TTP does not require secrets to operate. During development:

1. **No secrets are hardcoded** in the source code.
2. Any tokens or service keys (e.g., GPG signing, PyPI) are stored exclusively as **GitHub Secrets** or local environment variables.
3. For signing releases, the GPG key is stored only on the development machine and is never committed.
4. If a secret is accidentally committed, it will be revoked immediately and the history rewritten.
