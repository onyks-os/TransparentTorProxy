# TTP – Alternative Installation Methods (Fallback)

This document describes fallback installation methods for Transparent Tor Proxy (TTP) using Python-specific tools like `pipx` or `pip`.

> [!WARNING]
> **Important Note on Linux Distributions (PEP 668)**  
> Recent versions of Ubuntu, Debian, and other major distributions prevent global `pip install` to protect system stability. Using Python package managers directly bypasses TTP's kernel-level optimizations (such as SELinux module compilation on Fedora/RHEL) and will not install or manage system dependencies (`tor`, `nftables`, `conntrack`) automatically.
> 
> Therefore, these methods are **not recommended** for general use and should only be used as a fallback if native packages or source script installation are not possible.

---

## 1. pipx (Recommended Fallback)

`pipx` installs TTP in an isolated, dedicated virtual environment but exposes the `ttp` command globally.

```bash
pipx install transparent-tor-proxy
```

---

## 2. Standard pip with venv

If you prefer standard `pip`, install TTP inside a dedicated virtual environment to avoid the `externally-managed-environment` error.

```bash
# 1. Create the virtual environment
python3 -m venv ~/.local/share/ttp-venv

# 2. Install the package
~/.local/share/ttp-venv/bin/pip install transparent-tor-proxy

# 3. Create a symbolic link to make 'ttp' available system-wide
sudo ln -s ~/.local/share/ttp-venv/bin/ttp /usr/local/bin/ttp
```

---

## Uninstallation Warning

Running `pipx uninstall` or deleting the virtual environment directory **only removes the Python code**. If TTP is active, your firewall rules and DNS overlay will remain hijacked. 

**Always run `sudo ttp stop` before uninstalling** via `pip`/`pipx` to restore your network to its default state.
