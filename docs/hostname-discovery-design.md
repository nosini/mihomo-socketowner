# Mihomo: application hostname discovery with eBPF

Design and implementation record for optional application hostname discovery.

| Item | Status |
| --- | --- |
| Prepared | 2026-10-14 |
| Project status | Milestone 1 in progress; experiment authorized and started 2026-10-16 |
| Work completed | Verified first-send prototype; authenticated bootstrap; guarded reader consumption through real REDIRECT routing |
| Work not completed | Broader send/reinjection coverage; stable reader ABI and operator/service integration; full TLS/browser workloads |
| Intended reader | An agent returning to this workspace without the original conversation |

This document preserves the user's objective and the resulting assessment. The
recommendations below are proposed design choices, not a finalized implementation.
Recheck the source and supported library versions when work resumes. Saving this
document alone does not authorize installing software, changing services or
deploying the feature. The user subsequently authorized starting implementation
on 2026-10-16.

## Implementation progress, 2026-10-16

An isolated [OpenSSL experiment](../experiments/hostname/README.md) now
reads the live hostname and socket BIO at handshake entry, resolves the current
descriptor through kernel BTF and compares its socket cookie with `SO_COOKIE`.
The opt-in VM suite passes normal IPv4/IPv6 correlation, concurrency, descriptor
and actual TLS-object address reuse, setter order, transport replacement and
several unsupported-path tests. The profile accepts only two verified library
hashes; this is not generic OpenSSL support.

The suite also reproduces an unsafe case: abandoned setup publishes a name
without sending TLS bytes, then a missed observation of a replacement TLS object
leaves that old name attached to the same live socket. Therefore these snapshots
are **not routing evidence**, and milestone 1 is not complete. Guarded descriptor
table reads also do not establish file-reference lifetime safety under concurrent
close/replacement. The experiment README records reproduction commands, evidence
and next steps. No public pins, owner ABI, Mihomo routing or service changes have
been introduced.

### Live send correlation follow-up

The [live send-hook experiment](../experiments/hostname/SEND.md) reads the active
TLS connection from known live call frames at `lsm/socket_sendmsg` and associates
it with the kernel-held socket for that write. It needs no cached handshake
observation and does not traverse the process descriptor table. Tests address
the abandoned-setup counterexample with the handshake uprobe disabled, including
two live TLS objects sharing a socket. A private packet map also resolves direct
and REDIRECT flows through forced IPv4/IPv6 source-port collisions, with original
destinations verified independently.

The [publication follow-up](../experiments/hostname/PUBLICATION.md) adds a
preallocated atomic control word independent of record-map updates. A guarded
reader rejects records while writers are active, across an intervening write,
or permanently after any failed publication or scope-storage creation. VM fault
tests retain old positive records through real kernel update errors and verify
that the reader returns unknown while networking continues.

The [send-order follow-up](../experiments/hostname/SEND_ORDER.md) reproduces
another counterexample: sequential corked writes produce a flow tagged with the
second hostname while the peer's first ClientHello contains the first. A
monotonic, non-evicting per-socket guard now permanently excludes every socket
after a second send attempt, including parallel writes and same-name retries.
Readers check it independently of retained old flow records. This deliberately
restricts coverage rather than claiming general concurrent-send attribution.

The [packet follow-up](../experiments/hostname/PACKET.md) captures the kernel's
verified first-write buffer and TCP sequence position, admitting at most 4 KiB.
Only emitted payloads matching the captured byte window receive a hostname.
Control packets stay unknown; mismatched or unsupported packets exclude the
socket. IPv4/IPv6 tests cover ACKs while a ClientHello remains corked, automatic
TCP retransmission, modified payloads and oversized writes without blocking TLS.

The [lifetime follow-up](../experiments/hostname/LIFETIME.md) registers direct
cgroup release/state callbacks and retires closed socket cookies without relying
on successful record deletion or replacement. Tests cover final close, peer
FIN/RST, target exit and exact tuple reuse with old positive entries retained.
The in-process reader also binds itself to original link/program/map identities,
revokes stopped or changed sessions, and leaves already-open sockets unknown
after restart. Cross-process observer authority and crash handling remain work
for independent service integration.

The [routing follow-up](../experiments/hostname/ROUTING.md) runs the controlled
client through Mihomo's real REDIRECT listener, rule matcher, DIRECT adapter and
relay. It demonstrates that the current route can commit before ClientHello,
then tests a bounded pre-routing lookup, late evidence/replies, stopped observer
and stalled IPC for IPv4/IPv6 with process lookup on/off. A DOMAIN rule selects
the expected outbound while preserving the original IP and port. The private
supervised test bridge introduces no production reader or service ABI.

The [authority follow-up](../experiments/hostname/AUTHORITY.md) separates the
observer and a capability-free reader. Private link pins span descriptor teardown,
frozen maps prevent userspace mutation, and a pidfd/irreversible authority gate
rejects retained records after crash or revocation. Tests cover interrupted
reads, live/dead reconnect and fresh-map restart without adopting old sockets.
This remains a trusted inherited-FD bootstrap in the VM harness.

The [bootstrap follow-up](../experiments/hostname/BOOTSTRAP.md) replaces inherited
FDs with an authenticated, versioned experimental Unix socket exchange. The
observer is the socket/cleanup owner; readers bind to its kernel peer pidfd.
A root-private journal and stable lock support revocation before owned cleanup
and recovery after partial setup or crash without trusting a reusable numeric PID.

The [metadata follow-up](../../mihomo/docs/application-hostname-metadata.md) adds
connection-bound application-name provenance to Mihomo's ordinary `RuleHost()`
path. It defines explicit/Fake-IP precedence, ordinary-name conflicts and the
separate verified-inner role. Usable evidence preserves the real IP/port through
DNS hints, hosts overrides, sniffing and dial encoding. The expanded supervised
REDIRECT matrix uses the real DOMAIN matcher rather than a rule-input clone.
There is still no production caller, reader interface or enable setting.

The [consumption follow-up](../experiments/hostname/CONSUMPTION.md) connects the
authenticated reader directly to capability-free Mihomo in the VM. It binds
tentative names to the original reader/flow/record and rechecks them after rule
matching, before committing the outbound. Failure restores ordinary metadata
and routing policy. Both IP families and process modes pass crash, revocation,
second-send, eviction, expiry, reader-close and restart cases. The final guarded
read is the commitment point; a subsequent crash leaves that route fixed.

The [native lookup follow-up](../experiments/hostname/NATIVE.md) adds independent,
disabled-by-default configuration and a bounded lookup in Mihomo's ordinary TCP
REDIRECT tunnel. An explicit experimental backend build is required. Bootstrap,
polling and confirmation share one deadline; resource capacity is bounded, and
reload/disable cancel pending reads. Readers close before dialing. Thirty-two
native cases pass alongside the earlier routing matrices, including delayed/late
data, missing/stalled observers and post-match cancellation. Parsing a proposed
configuration does not revoke active evidence.

Milestone 1 remains open for broader send coverage and reinjection. Stable
optional reader records, resident observer entry
points and service confinement remain unimplemented. These diagnostic maps must not become
a stable public routing interface without that work.

## Objective

Make application-level destination hostnames available to Mihomo's domain routing
rules even when supported applications resolve names independently through DoH,
DoT or DoQ, or use TLS Encrypted Client Hello (ECH).

Observe the hostname the application already knows, before encryption hides it
from network observers. Preserve end-to-end TLS, certificate validation and
pinning. Retain the existing separation between Mihomo and the privileged eBPF
component.

The initial engineering contract should be:

> Discover the intended hostname of a supported transport connection, verify its
> association with that connection, and make it available before Mihomo commits
> the routing decision. If that association cannot be established, use existing
> routing behavior.

**Correctness takes precedence over coverage. An unknown hostname is preferable
to a hostname attributed to the wrong connection.**

## Feasibility assessment

The approach is feasible for supported application and transport paths. TLS
configuration is a promising observation point because the application normally
provides its intended server name regardless of how it resolved the address.

The difficult parts are establishing a reliable relationship between that name
and a live socket, then publishing it before the routing decision. Capturing a
string through a uprobe alone does not demonstrate the feature.

There is no universal userspace interface for this relationship. TLS libraries,
custom transports, browser networking stacks, static linking and packaged runtime
copies require explicit support. Unsupported paths must fall back safely.

This feature can improve routing for ordinary supported applications using
encrypted DNS. It cannot establish that an application is honest about the name
it supplies, or guarantee enforcement against deliberate evasion.

## Requirements to preserve

- Mihomo receives no additional process-inspection or BPF-loading privileges.
- Privileged observation remains outside Mihomo and reuses the existing
  infrastructure where appropriate.
- Process and socket attribution, the kill-switch and ordinary networking remain
  operational when hostname observation fails or is disabled.
- Hostname discovery has an independent enable/disable setting. Its lookup must
  not depend on whether process-name matching is enabled in the routing rules.
- Fake-IP mappings and existing TLS/QUIC sniffing remain available.
- Existing IP routing applies when no usable hostname is available.
- No TLS termination, certificate replacement, additional trusted CA, handshake
  rewriting, traffic decryption or application modification is required.
- Collection is limited to hostname and correlation metadata. Do not capture TLS
  keys, general plaintext, HTTP bodies, cookies, tokens or passwords.
- Retention is bounded by routing and correlation needs. Do not persist hostname
  histories by default; logging must be minimal and configurable.
- Published metadata is accessible only to the intended service reader.
- Performance, latency and application reliability must be measured before
  claiming compatibility.

## Current implementation foundation

The original request referenced these branches:

- [nosini/mihomo: ebpf-process-tracking](https://github.com/nosini/mihomo/tree/ebpf-process-tracking)
- [nosini/hardened-proxy-service: ebpf-process-lookup](https://github.com/nosini/hardened-proxy-service/tree/ebpf-process-lookup)

At assessment time, this workspace contains three repositories:

| Directory | Observed branch | Responsibility |
| --- | --- | --- |
| `mihomo/` | `ebpf-process-tracking` | Unprivileged BPF map reader, connection handling and routing |
| `socketowner/` | `main` | Privileged BPF implementation, attachment and public map ABI |
| `hardened-proxy-service/` | `ebpf-process-lookup` | systemd integration, service generator, sandbox and SELinux policy |

The privileged loader is the separate
[socketowner](https://github.com/nosini/socketowner) project, installed as
`socketowner`.

Useful source entry points:

- [Public socketowner map contract](map-interface.md).
- [BPF socket attribution](../bpf/sockowner.c) and
  [executable/process tracking](../bpf/execpath.c).
- [Loader and attachment lifecycle](../main.go).
- [Mihomo map reader](../../mihomo/component/process/sockowner_linux.go).
- [TCP and UDP routing paths](../../mihomo/tunnel/tunnel.go).
- [Domain metadata and `RuleHost()`](../../mihomo/constant/metadata.go).
- [Sniffer metadata updates](../../mihomo/component/sniffer/dispatcher.go).
- [Privileged service unit](../../hardened-proxy-service/socketowner.service),
  [service generator](../../hardened-proxy-service/mihomo-process-generator) and
  [SELinux policy](../../hardened-proxy-service/mihomo.te).

These observations describe the inspected checkout, not runtime verification.

## Observation strategy

### Start with a supported TLS transport

Track the intended name and transport binding on the same live TLS object.
Support either setter order: the application may configure the hostname before
or after attaching a transport. Observe successful configuration, replacement,
reset and object destruction as required by that adapter.

Some concrete adapter starting points are:

| Stack | Hostname observation | Correlation work still required |
| --- | --- | --- |
| OpenSSL | `SSL_ctrl()` with the hostname-setting command on versions where the public setter is a macro; version-specific ECH configuration where applicable | Bind the live `SSL` object to its actual socket, including the supported BIO path |
| NSS | `SSL_SetURL()` | Map the layered `PRFileDesc` to the underlying native socket and its lifetime |
| BoringSSL / Chromium | Intended name supplied to TLS configuration | Follow the actual application transport adapter to the underlying socket |
| Other stacks | Stack-specific hostname configuration | A verified transport binding for that stack |

In OpenSSL 3.0, `SSL_set_tlsext_host_name()` expands to `SSL_ctrl()`; probing the
macro name as though it were an exported function would be incorrect. The
`SSL_set_fd()` API provides a straightforward socket BIO binding for applications
that use it. Custom or memory BIO paths need separate support.

Chromium demonstrates why generic TLS hooks are insufficient: its TLS socket
implementation supplies the hostname, then uses `SocketBIOAdapter` and BIO
attachment APIs rather than a simple `SSL_set_fd()` path.

Observation points are candidates until their ABI, lifecycle and transport
semantics have been verified for a supported build.

### Treat resolver observations as candidates

Observing `getaddrinfo("example.com")` establishes that the process requested a
resolution. Observing the returned addresses adds evidence, but still does not
identify the eventual socket.

A process can resolve several domains sharing an address, prefetch unused names,
ignore results or connect from another thread. Asynchronous and multiprocess
networking further weaken a time-based association.

Do not use any of these as sufficient routing evidence:

- The most recently resolved name for a PID or thread.
- A recent name whose DNS result matches the destination IP.
- A single remaining cached candidate, without a verified transport relationship.

Resolver observations may help a supported adapter establish a relationship, but
resolver-only promotion to routing metadata should remain unsupported initially.
Never turn candidates into a global IP-to-domain cache.

### Distinguish ECH inner and outer names

The intended inner hostname and the public outer hostname have different roles.
An adapter must identify which role its observation represents.

A verified application inner name differing from sniffed outer SNI is expected
under ECH. It should not automatically be treated as an unexplained conflict.
Conversely, a TLS configuration hook must not be assumed to expose the inner name
without checking that implementation's ECH behavior.

## Connection identity and correlation

Use the following conceptual chain:

```text
Application's intended hostname
            |
            v
Verified live TLS or transport object
            |
            v
Verified underlying application socket and lifetime
            |
            v
Flow identity in the networking mode seen by Mihomo
            |
            v
Hostname available before route selection
```

### The existing owner key is insufficient

The socketowner v1 owner map key contains network namespace cookie, source
address, source port and protocol. It excludes the remote destination. Entries
can outlive closed sockets and are removed by LRU eviction.

Do not attach authoritative hostnames solely to that key. Preserve the existing
ABI and introduce a separately versioned optional hostname interface.

The new design needs enough information to verify:

- Process identity across PID reuse, exec and relevant namespace boundaries.
- Transport-object identity across allocation reuse and reset.
- Socket identity across descriptor reuse, duplication and transfer.
- Local and remote endpoints in the relevant namespace.
- Socket/flow generation, observation validity and loader generation.
- The meaning and provenance of the hostname observation.

An application socket and Mihomo's accepted proxy socket are different sockets.
Their cookies cannot simply be compared. Define how the application socket maps
to the intercepted flow for each supported inbound mode. Account for NAT source
port changes and retain original destination information where required.

### Lifetime rules are part of correctness

The design must explicitly handle concurrent connections, thread changes,
process changes, connection failures, UDP reconnects, descriptor passing and
object replacement. A hostname set earlier must not survive an unrelated
transport reassignment.

Timeouts and LRU limits bound retention; they do not prove identity. A raw object
pointer, PID, descriptor number or stale tuple is insufficient by itself.

Missing an allocation, reset or destruction event can be more dangerous than
missing a hostname event: it can cause old state to appear current. Do not assume
perfect probe delivery. Require a complete, verifiable association and invalidate
partial or inconsistent state. If a path cannot meet that requirement, exclude it
from the supported set.

The exact mechanism for binding an observed userspace object to a lifetime-safe
kernel socket remains an open engineering question. This assessment has not
proved a particular helper, hook or kernel-memory traversal sufficient.

## Routing deadline and integration

### Obtain metadata before committing the route

In the inspected TCP path, Mihomo preprocesses metadata and runs sniffing before
rule selection and outbound dialing. Application-hostname lookup belongs in that
interval. UDP has its own sender/NAT association path and needs a separate audit.

A TLS hostname may be configured after the application's TCP `connect()` returns.
Transparent interception may allow a bounded wait for initial client activity
before selecting the outbound. Verify that behavior for each inbound mode; it is
not a universal assumption.

Waiting indefinitely can deadlock protocols where the application expects a
server greeting or proxy response before proceeding.

Proposed behavior:

1. Use a completed, verified association immediately when available.
2. Wait only within a bounded window appropriate to the supported inbound path.
3. Fall back to existing routing if metadata is still unavailable.
4. Keep the route fixed once the connection proceeds.

Late metadata cannot move an established connection to a different outbound.
Asynchronous delivery through a ring buffer does not remove the deadline. Where
feasible, publish completed correlation directly into BPF maps before the
associated traffic reaches Mihomo. This ordering still needs to be demonstrated.

### Separate routing hostname from dial destination

Existing domain rules use `Metadata.RuleHost()`, which currently selects
`SniffHost` when present and otherwise `Host`. This is a useful integration point.

Add explicit application-hostname provenance and selection semantics rather than
silently overloading sniffed-host metadata. Domain rule types should not need a
redesign.

**Application-hostname discovery should preserve the application-selected real
destination IP by default.** Learning a routing name must not implicitly cause
re-resolution or destination replacement.

Audit all effects of setting metadata, including hosts overrides, `Pure()`,
outbound address encoding and existing sniffer destination replacement. Adding a
field at rule lookup is insufficient if another path has already rewritten the
destination.

Define source selection explicitly:

- Retain existing behavior when the feature is disabled.
- Preserve valid Fake-IP and explicit inbound destination semantics.
- Allow a verified ECH inner name to represent the intended connection name.
- Reject ambiguous application associations.
- Avoid arbitrary first-observation or last-observation selection for unexplained
  conflicts between names representing the same role.
- Fall back to existing metadata/IP routing when application evidence is unusable.

The final precedence policy is not settled in this assessment.

## Multiplexing and coverage limits

### Routing remains connection-based

HTTP/2 permits connection reuse across different origins. A TLS connection
initially established for `a.example` may later carry a request for `b.example`
without another handshake.

Even observing the later request authority would not let Mihomo move that request
to another outbound while preserving the same end-to-end encrypted stream.

Add this explicit scope boundary:

> Routing applies to transport connections. Independently routing origins that
> share an established encrypted connection is outside scope.

A verified initial connection hostname remains useful metadata; it must not be
presented as proof that every request on the connection uses that hostname.

### QUIC needs separate correlation

A TLS session does not necessarily map one-to-one to a UDP socket. Multiple QUIC
connections can share a socket, and migration changes flow endpoints. A generic
UDP socket hostname is therefore insufficient.

Defer QUIC until TCP correlation is proven. Supporting an application that uses
DoQ for DNS does not necessarily require observing that DNS transport: the later
destination connection can still be observed through its supported stack.

### Browsers and Flatpak are explicit milestones

Generic OpenSSL support can validate the architecture. It does not establish
coverage of browser DoH/ECH or Firefox's QUIC paths.

Browser support requires verified object relationships and transport behavior.
Flatpak adds runtime library copies, mount namespaces and sandbox-specific binary
locations. Statically linked or stripped implementations may need supported
build-specific offsets.

Identify attachment targets by actual binary identity and verified ABI, not just
library basename. Handle updates and newly loaded libraries deliberately. Unknown
builds or layouts should disable the relevant adapter and preserve connectivity.

## Privileged component and failure boundaries

Implement privileged functionality in socketowner and service integration in
hardened-proxy-service. Mihomo should consume only validated routing records.

The current loader is a oneshot service that attaches programs and exits. Fixed
attachments to supported library files may fit that model, subject to the chosen
kernel/link support. Dynamic discovery of changing application binaries and
runtime libraries may require a resident observer.

If a resident observer is needed, reuse the project and BPF infrastructure while
giving hostname observation an independent lifecycle. A separate optional service
using shared tooling may provide that boundary without duplicating the owner
loader. Its failure must not detach owner programs, restart Mihomo or compromise
the kill-switch.

Hostname interface replacement and failure need explicit generation/invalidation
semantics. Already opened map descriptors can outlive pin removal; do not retain
old hostname data indefinitely after an observer restart or disable action.

The generator currently selects map access and service dependencies from process
lookup configuration. Extend that logic deliberately so hostname discovery can
operate independently of process-rule lookup, while preserving the current
process-only modes.

## Security and privacy design

The existing loader already has `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` and
`CAP_CHOWN` in its service unit. This does not establish that its current sandbox
or SELinux policy supports uprobes safely.

Uprobe attachment introduces perf-event access and access to target binaries.
Dynamic discovery may require selected process metadata. Review syscall filters,
filesystem exposure, SELinux permissions and the supported attachment scope.
Do not assume that broader process-memory access or `CAP_SYS_PTRACE` is required;
demonstrate the minimal permissions for the selected mechanism.

The BPF verifier enforces program safety, not hostname-only collection. Fixed,
reviewed probe code and bounded reads are the data-minimization boundary.

Proposed safeguards:

- Read only required hostname and correlation fields at known observation points.
- Bound hostname lengths, map capacities, pending state and wait durations.
- Reject malformed or truncated names; normalize according to a defined policy.
- Restrict observation to the configured processes/cgroups and supported adapters.
- Keep raw pointers and intermediate process state private to the observer.
- Keep published pins root-owned with read-only reader access; a reader owning a
  pin could grant itself write access and forge entries.
- Validate map type, key/value sizes and interface version before every new map is
  accepted by the reader.
- Publish complete records with explicit validity; avoid exposing partial updates.
- Use lifecycle cleanup and bounded expiry, without default activity histories.
- Audit existing connection logs and API metadata before exposing a new hostname
  field, since those paths may already record or publish routing names.

Unsupported kernels, denied attachments, invalid user-memory reads and observer
failures must degrade hostname availability without interfering with networking.
Do not weaken the host's security mechanisms to increase coverage.

## Expected behavior

| Scenario | Intended result |
| --- | --- |
| Mihomo Fake-IP DNS | Existing behavior remains available |
| System resolver call without verified transport binding | Candidate only; existing discovery/routing applies |
| Independent encrypted DNS plus supported destination transport | Verified destination name can inform routing |
| Visible SNI | Existing sniffing remains available |
| ECH plus supported inner-name observation and transport binding | Intended inner name can inform routing |
| Direct IP connection without a usable name | IP-based routing applies |
| Unsupported stack, build or transport path | Existing discovery and IP fallbacks apply |
| Concurrent connections in one process | Each connection requires its own verified association |
| Ambiguous association | No application hostname is promoted |
| Multiple origins on one established connection | One transport route; no independent origin routing |
| Hostname arrives after routing commitment | Existing route remains fixed |
| Feature disabled | Existing behavior remains unchanged |
| Observer fails | Owner tracking and networking remain operational |

These are acceptance targets, not demonstrated functionality.

## Suggested implementation milestones

### 1. Prove exact TCP correlation

Use one controlled TLS adapter and one precisely defined transport path. Establish
the object-to-socket relationship, lifetime safety and publication ordering.

Validate concurrent connections, both hostname/transport setter orders,
descriptor and object reuse, failed setup, reset, event loss and late observation.
Demonstrate interception/NAT behavior for the initial supported inbound mode.

Do not treat successful hostname capture as completion of this milestone.

### 2. Integrate routing metadata and independent operation

Introduce the optional hostname ABI, reader validation, explicit provenance,
source selection and bounded lookup timing. Preserve the owner ABI.

Verify destination preservation, existing Fake-IP/sniffer behavior, disabled
behavior and observer failure. Exercise hostname discovery with process-rule
lookup both enabled and disabled.

### 3. Demonstrate the motivating browser case

Support one real browser with a verified transport adapter. Demonstrate independent
encrypted DNS and confirmed ECH, then show that the intended connection hostname
selects the correct outbound before traffic is forwarded.

Choose the first browser from a source/ABI feasibility assessment. Do not assume
that generic OpenSSL support covers it.

Expand only after that demonstration, with separate support claims for additional
libraries, browser builds, Flatpak runtime variants and QUIC.

## Validation priorities

The decisive criterion is correct assignment, not the number of observed names.

| Area | Required evidence |
| --- | --- |
| Identity | No incorrect assignments in deliberate PID/FD/object/tuple reuse and concurrent-connection tests |
| Event loss | Missing lifecycle or observation events produce unknown/invalid state rather than stale attribution |
| Timing | Names arrive before routing commitment for supported paths; bounded fallback otherwise |
| Networking modes | Explicitly verified TUN/redirect/tproxy/proxy paths, including IPv4, IPv6 and relevant NAT behavior |
| Routing | Domain rule chooses the expected outbound while preserving the selected real destination |
| Encrypted DNS / ECH | Confirmed use in a supported real application, with correct intended-name attribution |
| Isolation | Reader cannot load probes, inspect application memory, modify records or access private correlation state |
| Failure | Observer stop/restart, attachment denial and map replacement leave owner tracking and connectivity functional |
| Privacy | No unrelated fields collected; no default hostname history or unexpected metadata exposure |
| Performance | CPU, memory and connection latency measurements under representative load |

Zero incorrect assignments in these tests is an acceptance requirement, not a
proof of universal correctness. Document the supported paths and remaining limits.

## Open decisions for the future agent

1. Which initial application/library build and transport path provide a verifiable
   object-to-socket relationship?
2. How is socket identity verified without trusting reusable descriptors or raw
   pointers, including when lifecycle probes are missed?
3. How does each supported interception mode map that socket to Mihomo's flow?
4. Can the initial attachments remain oneshot, or is a resident observer necessary?
5. How are adapter build identities, binary updates and namespace-specific runtime
   copies discovered within the permitted sandbox?
6. What exact hostname ABI, generation and atomic-publication rules are needed?
7. What bounded lookup deadline is safe for each supported inbound path?
8. What metadata precedence preserves intended routing and destination semantics?
9. What additional permissions are demonstrated necessary on supported hosts?

Before extending the experiment, recheck the repository state and resolve the
correlation mechanism, including the reproduced missed-observation case. Keep
support claims narrower than the verified paths.

## Primary references

Upstream links were inspected during the assessment. Branch-based links can change;
pin the relevant source versions when implementing an adapter.

- [Linux uprobe tracer documentation](https://docs.kernel.org/trace/uprobetracer.html):
  userspace probe points, file offsets and argument observation.
- [OpenSSL 3.0 TLS header](https://github.com/openssl/openssl/blob/openssl-3.0/include/openssl/tls1.h):
  hostname-setting macro and `SSL_ctrl()` dispatch.
- [OpenSSL `SSL_set_fd()` documentation](https://docs.openssl.org/3.6/man3/SSL_set_fd/):
  SSL object binding to a socket BIO.
- [OpenSSL upstream ECH API](https://github.com/openssl/openssl/blob/master/doc/man3/SSL_set1_echstore.pod):
  distinction between inner and outer server names.
- [NSS public SSL interface](https://github.com/nss-dev/nss/blob/master/lib/ssl/ssl.h):
  `SSL_SetURL()` and layered descriptor interfaces.
- [Chromium TLS socket implementation](https://github.com/chromium/chromium/blob/main/net/socket/ssl_client_socket_impl.cc):
  hostname configuration and custom BIO transport binding.
- [RFC 9113, section 9.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-9.1.1):
  HTTP/2 connection reuse across origins.
- [Linux perf security documentation](https://docs.kernel.org/admin-guide/perf-security.html):
  observability privileges and `CAP_PERFMON`.
