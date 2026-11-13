# Continuous fault observations

The chaos VM gate records traffic **before each fault is injected** and keeps
sampling throughout the watchdog response, the existing recovery audits and a
final three-second hold. The old 18-second wait remains a recovery deadline;
it no longer removes that interval from the external observation.

## What is measured

An ordinary process with its own UID/GID, no supplementary groups and no
effective capabilities attempts TCP/80, DNS UDP/53 and arbitrary UDP/19302 in
both IPv4 and IPv6. Its controlled destinations are `198.51.100.7` and
`2001:db8:5444::7`, outside the default LAN exemptions. No public response is
needed for these egress observations. Real Tor/public-IP recovery checks remain
separate, and an unavailable public dependency still fails its own audit.

The process starts before TTP and continues across injections and session
resets. Every cycle has a sequence number; datagrams carry a unique run/channel
payload and TCP attempts record their source ports. The nominal interval is
100 ms for each channel. The report records the largest sampled gap and fails
if any channel has a gap over 500 ms in a fault interval. This is sampled
observation: a shorter unsampled opening can still be missed.

QEMU records complete Ethernet frames outside the guest firewall, before
user-network NAT. A missing/corrupt/truncated capture, unsupported required
packet layout, missing sequence/channel or lost phase beacon cannot yield a
clean result. Unlike a host AF_PACKET socket, this observer has no kernel packet
socket receive queue; a write/read failure or missing required data invalidates
the evidence. The capture is streamed during analysis.

Root emits distinct non-IP Ethernet phase beacons around injection commands,
controls and hold intervals. These create no IP bypass for the ordinary actor.
The analyser requires the same ordered beacons in the independent capture and
the guest log. It uses capture order for phases and QEMU timestamps for packet
exposure bounds; it never subtracts a guest clock from a host/QEMU clock.
Successful unprotected controls must expose all six channels before and after
the sweep. The same controls also run before each reset session.

## Containment and recovery are separate results

| Fault family | Required result |
| --- | --- |
| Tor orderly stop/SIGKILL, resolver overlay removal, link flap | No observed direct probe packet in the fault window; recovery audits also pass |
| Privileged insertion of an accept rule, deletion of the final reject rule, table flush/destruction | Record every observed escaped packet as a leak/exposure; require the final hold to contain traffic and recovery audits to pass |
| Missing calibration, stimulus, capture or planned injection | Inconclusive/harness failure |

Removing the enforcement barrier as root can expose traffic before the watchdog
repairs or isolates it. An accepted recovery experiment for that deliberate
mutation **does not mean continuous containment**. Its JSON keeps
`containment: leak`, packet/byte counts and first/last observed egress. Exposure
from an ordinary non-firewall fault fails the gate, even when it later recovers.
Any direct probe packet during the final hold fails, including after a
privileged enforcement mutation.

A positively matched packet bracketed by known fault beacons remains a leak
even if later capture data is lost. Such incomplete experiments still fail;
unprotected calibration packets alone cannot establish a fault leak.

`accepted` means that the experiment met the row's stated expectations. It is
not a blanket security verdict. No new runtime barrier or instantaneous
recovery guarantee is introduced by this test harness.

## Running and finding evidence

Use the [disposable VM runner](vm-testing.md), never your normal host:

```bash
VM_WORK=/path/to/new-private-workdir scripts/vm/lifecycle/chaos.sh
VM_WORK=/path/to/another-workdir \
  CHAOS_ARGS="--reset-between --no-bypass --duration 2400" \
  scripts/vm/lifecycle/chaos.sh
```

The lifecycle workflow covers chained, fresh-session and fresh-session/no-bypass
variants. `--injection kill_tor` selects a single fault for local reproduction.
The wrapper's exit status requires both recovery audits and external evidence
to succeed. It retains `chaos.pcap`, `chaos.log`, `chaos-boundary/events.jsonl`,
`chaos-boundary/stimulus.jsonl` and `chaos-boundary-report.json`; CI uploads them.
Captures may include unrelated guest/Tor traffic and are diagnostic artifacts.

These tests cover the stated synthetic actor, interface and packet shapes.
They do not qualify browsers, physical handover/suspend, every transport,
full startup/rollback/teardown or interfaces outside the observed NIC. See
[DNS/UDP evidence](leak-evidence.md) for the separate steady-session fixture.
