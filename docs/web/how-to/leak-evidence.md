# DNS and UDP containment evidence

The 0.5.0 development tests distinguish packet containment, application
availability and socket observations. A DNS timeout or error reply does not
identify the network path. The same is true of a global redirect counter:
another process may have incremented it while the tested query escaped.

## Measurements and verdicts

| Evidence | Verdict |
| --- | --- |
| Exact probe payload observed outside the protected network namespace | Leak in the protected measurement window, even if no reply arrived |
| No matching egress, complete capture, attempted stimulus, successful pre/post controls | Contained for this actor, destination, protocol and window |
| Timeout, socket error, DNS reply shape or aggregate counter alone | Inconclusive |
| Missing measurement, failed control, capture drops, unknown packet layout or unfinished report | Inconclusive / harness failure; no green containment result |

The independent public Tor HTTP check still verifies a working permitted path.
A DNS/UDP containment result alone cannot establish Tor connectivity or browser
anonymity. A remote resolver can return SERVFAIL, NOTIMP or REFUSED just as a
local proxy can; receiving TXT answers alone does not establish a direct route.

## Controlled integration fixture

Run the [disposable integration VM](vm-testing.md) rather than the fixture on
your normal host. `scripts/vm/leak_boundary.py` requires the explicit disposable
VM marker set by the controller and configures test addresses on its private
Docker bridge and container veth. It never uses public DNS or STUN services as
the containment oracle.

The observer and controlled receivers run outside the protected container's
network namespace. They exercise both IPv4 and IPv6, five DNS cases (silent
receiver, SERVFAIL, NOTIMP, REFUSED and an answer), plus an arbitrary UDP port.
The stimulus runs as UID/GID 65534 with zero effective capabilities; sessions
with configured user/group bypasses or external Tor ownership are refused by
this baseline fixture.

Each case uses a unique query/flow payload. Before starting TTP, the same class
of request must cross the boundary to its receiver. During the protected
session, the host records the container-facing veth and matches the exact
destination, UDP port and payload. The receiver independently records delivery.
Any matching egress is a leak regardless of the socket's return value.

Distinct non-IP Ethernet beacons bracket each stimulus to verify the capture
window. These harness-only beacons create no IP firewall exemption. Kernel
packet-drop statistics, parsing errors and a bounded capture memory budget
determine whether absence can be evaluated. Unsupported fragmentation,
extensions or VLAN layouts invalidate this fixture's clean verdict; they are
not silently discarded as safe.

After explicit stop, unprotected positive controls must succeed again. Only
then is the report marked complete. Pytest reads these **historical protected
measurements**, not the now-stopped session, and rederives each verdict from its
evidence. Missing/stale run identifiers or a mismatched saved verdict fail.
Schema version 2 rejects older artifacts that inferred safety from sockets.

CI retains `leak-boundary.tar.gz`: phase JSON, unique payloads, complete reports
and per-window PCAPs. The export must succeed for an otherwise successful
integration job. Captures contain test-container traffic and should be treated
as diagnostic artifacts. Test cleanup removes the disposable container even
when preparation or measurement fails.

## Scope and remaining gates

This fixture measures the controlled container boundary during a running
managed session. It does not prove every Internet route, provider, browser,
resolver, transport or IP packet layout is safe. Its synthetic destinations
and bounded capture windows are explicit. It also does not observe the full
startup, fault-response or teardown interval; continuous fault observation is
covered separately by [continuous fault observations](continuous-fault-evidence.md).

The older public DNS/STUN socket helpers remain diagnostic: their socket-only
results cannot produce a contained verdict. The calibrated receiver cases
replace those optimistic assertions in the integration gate; no inconclusive
result is treated as a pass.
