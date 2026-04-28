"""Custom exception hierarchy for TTP.

This allows the CLI and other modules to distinguish between different
types of system failures and decide on the appropriate recovery strategy
(e.g., fatal error vs. warning).
"""


class TTPError(Exception):
    """Base class for all Transparent Tor Proxy exceptions."""

    pass


class FirewallError(TTPError):
    """Raised when nftables operations (backup, apply, restore) fail."""

    pass


class DNSError(TTPError):
    """Raised when DNS configuration (resolvectl, resolv.conf) fails."""

    pass


class StateError(TTPError):
    """Raised when session lock or state management fails."""

    pass


class TorError(TTPError):
    """Raised when Tor detection, installation, or control fails."""

    pass
