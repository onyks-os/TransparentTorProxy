# Copyright (c) 2026 onyks-os
# SPDX-License-Identifier: MIT

"""Fetch one verification endpoint and print only what TTP reads from it.

Run by :func:`ttp.tor_control._fetch_endpoint` as ``python -I -m ttp.netprobe
<url>`` in a child that runs as ``nobody`` when TTP itself runs as root. The
TLS handshake, the HTTP response and the JSON body all come from a third party;
parsing them here keeps that out of the root process. What goes back is one
JSON line holding at most four fields, each already reduced to its type and a
bounded length - or ``null`` for no usable answer. The parent validates it again
and trusts none of it beyond that.

Standard library only, and nothing from the rest of ``ttp`` - importing the
package would pull in modules a network probe has no business running.
"""

from __future__ import annotations

import json
import math
import socket
import ssl
import sys
import urllib.error
import urllib.request

#: The only URLs this probe fetches. Mirrors ttp.tor_control.VERIFY_ENDPOINTS;
#: tests/test_netprobe.py keeps them equal.
ENDPOINTS = (
    "https://check.torproject.org/api/ip",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
)

#: Longest string field handed back: an IPv6 address with a zone fits in 45.
_MAX_FIELD = 64
#: Largest body read from an endpoint; the real ones are a few hundred bytes.
_MAX_BODY = 64 * 1024


def fetch(url: str) -> object | None:
    """The parsed JSON body of *url*, or ``None`` on any failure."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "ttp"})
        with urllib.request.urlopen(request, timeout=15) as response:
            payload: object = json.loads(response.read(_MAX_BODY).decode())
        return payload
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def reduce(payload: object) -> dict[str, object] | None:
    """Keep the fields TTP reads, with the right types and bounded lengths."""
    if not isinstance(payload, dict):
        return None
    out: dict[str, object] = {}
    for key in ("IP", "ip", "ip_addr"):
        value = payload.get(key)
        if isinstance(value, str) and len(value) <= _MAX_FIELD:
            out[key] = value
    if isinstance(payload.get("IsTor"), bool):
        out["IsTor"] = payload["IsTor"]
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_report(url: str, timeout: float) -> dict[str, object]:
    """Detailed, bounded reply for the session verifier; no proxy or redirect.

    A proxy inherited from the caller's environment is not the path this probe
    is intended to measure. Redirects cannot delegate the authority's verdict
    to another origin. Error descriptions are fixed identifiers, not raw server
    text interpolated into a privileged terminal.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "ttp"})
        with opener.open(request, timeout=timeout) as response:
            body = response.read(_MAX_BODY + 1)
        if len(body) > _MAX_BODY:
            return {"error": "response_too_large"}
        data = reduce(json.loads(body.decode("utf-8")))
        return {"data": data} if data is not None else {"error": "response_shape"}
    except urllib.error.HTTPError as exc:
        return {"error": "http_redirect" if 300 <= exc.code < 400 else "http_error", "http_status": exc.code}
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, socket.gaierror):
            return {"error": "dns_error"}
        if isinstance(reason, ssl.SSLError):
            return {"error": "tls_error"}
        return {"error": "timeout" if isinstance(reason, TimeoutError) else "connection_error"}
    except TimeoutError:
        return {"error": "timeout"}
    except ssl.SSLError:
        return {"error": "tls_error"}
    except OSError:
        return {"error": "connection_error"}
    except UnicodeError:
        return {"error": "response_encoding"}
    except ValueError:
        return {"error": "response_json"}


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "--report" and argv[1] in ENDPOINTS:
        try:
            timeout = float(argv[2])
            if not math.isfinite(timeout) or not 0 < timeout <= 3600:
                raise ValueError("invalid timeout")
        except ValueError:
            print("probe timeout must be positive and at most 3600 seconds", file=sys.stderr)
            return 2
        print(json.dumps(fetch_report(argv[1], timeout)))
        return 0
    if len(argv) != 1 or argv[0] not in ENDPOINTS:
        print("usage: python -m ttp.netprobe <one of TTP's verification endpoints>", file=sys.stderr)
        return 2
    print(json.dumps(reduce(fetch(argv[0]))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
