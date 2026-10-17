# Optional hostname contract v1

This is the frozen profile-1 contract. The current reader and observer use
[profile 2](PROFILE2.md), which explicitly changes guard reclamation obligations.

This contract is independent of [socket-owner map ABI 1](../docs/map-interface.md).
Enabling or updating it must not change the owner maps, their version marker,
process-lookup configuration, Mihomo's capabilities or network protection.
It defines a separately versioned [Go reader module](README.md),
an authenticated bootstrap protocol and a fixed first-send layout profile.
The protocol and layout versions are independent of the reader module release.

Protocol **1**, profile **1** freeze the already tested experimental bootstrap
bytes and sole-first-send semantics. Earlier experimental observers using these
exact bytes interoperate. This packaging does not broaden supported traffic.
An observer may change its implementation only while preserving every publisher
obligation below. Private pins and diagnostic maps alone confer no authority.

## Supported evidence

A positive name is an ordinary intended transport TLS hostname observed on a
verified live OpenSSL write path, bound to the kernel-held application socket and
the emitted first-write bytes. It is **not** a verified ECH-inner name. Profile 1
supports only the explicitly hash-verified OpenSSL 3.5.3 x86-64-v3/library profile
in the [observer documentation](../experiments/hostname/OBSERVER.md). It accepts
one target TGID per observer and a sole first TCP write of 1..4096 bytes. All
second send attempts, including retry or same-name writes, permanently exclude
the socket. Automatic TCP retransmission may still refer to the original bytes.
Unsupported paths and any ambiguity return unknown without blocking networking.

The complete flow key is the post-NAT tuple seen by the accepted connection,
including translated source ports, in its network namespace. It is not the
original destination recovered with `SO_ORIGINAL_DST`, and it is not the owner
map's source-only key. Tested coverage is IPv4/IPv6 direct and local REDIRECT;
TUN, TPROXY, UDP/QUIC, broader reinjection and browser DoH/ECH are unproved.
TLS bytes and the original dial IP/port must remain unchanged. Completed TLS,
application traffic and production performance have not yet been demonstrated.

## Endpoint and bootstrap

The observer itself creates a filesystem Unix `SOCK_SEQPACKET` listener. All
ancestors must be real root-owned directories with no group/world write bit.
The socket is root-owned, has no world permissions, and permits the configured
reader group (normally 0660). The observer checks the exact configured nonroot
reader UID through `SO_PEERCRED` **before** reading or granting descriptors.
The reader verifies paths and root peer credentials and obtains the peer's
pidfd directly with `SO_PEERPIDFD`, never by reopening a numeric credential PID.
The pidfd must be on pidfs, with preserved device/inode identity, and not ready
for exit. Alternate PID namespaces, symlinks, abstract endpoints, inherited or
delegated listeners and socket activation are unsupported.

One request and one response are separate, exactly 80-byte packets. Envelope
integers are little endian; all unspecified bytes must be zero.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `MHNAME01` |
| 8 | 2 | Protocol version, 1 |
| 10 | 2 | Request kind 1, response kind 2 |
| 12 | 2 | Status, zero |
| 14 | 2 | FD count: request 0, response 4 |
| 16 | 16 | Nonzero random request nonce, echoed exactly |
| 32 | 16 | Observer instance: request zero, response nonzero |
| 48 | 16 | Four uint32 map IDs in FD order: request zero, response exact nonzero IDs |
| 64 | 4 | Layout profile, 1 |
| 68 | 12 | Reserved, zero |

The response carries exactly four `SCM_RIGHTS` FDs, in the order below. No link,
program, writable map or application process FD is transferred. Every received
FD must be owned before rejecting a packet and closed on any failure, including
payload/control truncation and wrong ancillary types. Received FDs are
close-on-exec. A nonce/instance/version/profile/count mismatch, malformed packet,
unexpected object or unsupported profile rejects the entire exchange. There is
no lower-version fallback, raw-pin fallback or partial acceptance.

Bootstrap is bounded by one absolute deadline, with context cancellation
interrupting reads. After bootstrap, no further IPC is required. Reconnect means
a new session; an old candidate can never adopt replacement authority.

## Profile 1 maps and layouts

The maps are globally frozen against userspace update/delete, including through
reopened writable FDs, before being offered. BPF may continue to update them.
The transferred FD access mode must be `O_RDONLY`. Runtime map flags are zero:
`BPF_F_RDONLY` is an FD-open flag and is not retained in map-info flags. Verify
both FD access mode and map frozen state, separately from dimensions and IDs.
All four identities and exact dimensions must match on each guarded read.

| FD index | Role | Kernel map type | Key bytes | Value bytes | Capacity |
| ---: | --- | --- | ---: | ---: | ---: |
| 0 | Authority gate | ARRAY (2) | 4 | 8 | 1 |
| 1 | Publication control | ARRAY (2) | 4 | 8 | 1 |
| 2 | Permanent socket guards | HASH (1) | 8 | 8 | 256 |
| 3 | Post-NAT flows | LRU_HASH (9) | 48 | 312 | 256 |

Profile 1 is Linux amd64, little endian. Scalar keys/values are native little
endian. Addresses are 16 network-order bytes in `netip.Addr.As16` form, including
`::ffff:a.b.c.d` for IPv4. Ports are host-order uint16. Keys use zero padding.

| Flow-key offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 8 | Network namespace cookie |
| 8 | 16 | Post-NAT source address |
| 24 | 16 | Post-NAT destination address |
| 40 | 2 | Source port |
| 42 | 2 | Destination port |
| 44 | 4 | Zero padding |

| Flow-value offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 8 | Application socket cookie, nonzero |
| 8 | 8 | Observation's cookie, must equal the flow cookie |
| 16 | 8 | Observation boot-time timestamp in ns |
| 24 | 4 | Target TGID |
| 28 | 4 | Observed signed fd number, diagnostic only |
| 32 | 4 | Signed hostname length, including trailing NUL |
| 36 | 4 | Padding |
| 40 | 256 | NUL-terminated ASCII DNS hostname buffer |
| 296 | 4 | TCP sequence position |
| 300 | 4 | Matched first-write payload length |
| 304 | 8 | Packet boot-time timestamp in ns |

A name length must be 2..255, with a NUL at length minus one. Normalize a single
trailing dot and ASCII case; accept only DNS labels of 1..63 ASCII letters,
digits or hyphens, without leading/trailing hyphens, total at most 253 bytes.
Reject numeric-only dotted names, IP literals, empty labels, embedded NUL,
Unicode and truncated names. TGID/fd/timestamps are diagnostic fields, not
independent authority or freshness grants. The full original value must remain
identical at final validation; checking equal hostname text alone is insufficient.

## Publisher obligations and guarded consumption

The trusted publisher must retain all five original live create/release/state/
send/egress attachments through **private root-owned link pins** before activating
its gate. Pin ownership does not move to the reader. Pinning maps alone is
insufficient: process FD teardown precedes pidfd exit notification.
The authority word starts at 0, activates only by CAS 0 to 1, and is revoked by
atomically ORing 2. It can never reactivate. Revoke before detaching or removing
any required authority. A crash keeps pins until a trusted cleaner proves the
original observer dead. Startup cleanup identity, journaling and ownership rules
are recorded in [BOOTSTRAP.md](../experiments/hostname/BOOTSTRAP.md).

The publication word uses bits 0..15 for active writers, bits 16..62 for a
nonwrapping generation (step 65536), and bit 63 for sticky failure. Every
potentially authority-changing send, socket lifetime transition or publication
must participate. Failure, overflow or inability to record a monotonic guard
poisons the instance permanently. The guard hash is never deleted, reset or LRU
evicted within an instance: cookie state 0 means no send, 1 means sole send, and
3 means permanently excluded. Any other state is unusable for a positive name.
There is no profile-1 reclamation; exhausting 256 slots poisons publication.
New instances use fresh maps and never adopt existing sockets.

A reader checks live pidfd identity, exact map identities/layouts/freeze and
`authority == 1` before each publication-control read. It admits a record only
when the control word has no failure or active writers, the exact flow lookup
succeeds, its independent cookie guard authorizes a sole send, and the final
control word equals the first with all authority checks still passing. Missing,
evicted, changed or ambiguous evidence returns unknown. Observer/gate/identity
failure permanently revokes that reader. Mere busy/missing flow reads may be
retried within the caller's original deadline; no error exposes a positive value.

`Candidate.Validate` repeats that entire guarded read for the original session,
flow and absolute deadline, and compares every byte of the original record.
It must run after tentative rule matching and immediately before route commitment.
On failure the caller restores ordinary metadata and repeats ordinary routing.
A successful validation is a commitment point; it cannot atomically guarantee
observer lifetime through dial/TLS or retroactively reroute a committed connection.

## Compatibility and distribution

The reader's module releases, bootstrap protocol, layout profile and owner-map
ABI are four different version spaces. Reader updates do not install the observer.
Observer updates must continue to satisfy the supported contract or advertise a
new incompatible version/profile, which this reader rejects. A newer reader may
add explicit profiles without changing profile 1. Ordinary Mihomo builds omit the
module entirely; optional builds select an exact reader release, or an explicit
local checkout during development. No unpublished module requirement is added to
Mihomo's ordinary module graph.

Publisher golden-envelope and embedded-object BTF tests pin byte layout. The
reader has independent golden, parsing, publication/guard and FD-lifetime tests.
The VM `TestVMHostnameContract*` suite checks real nonroot bootstrap, candidate
validation/revocation/expiry, bad publishers, cancellation and the resident
command. Mihomo's real direct-reader and native REDIRECT route matrices consume
this independent module. These checks establish current interoperability, not
production readiness or completion of the broader hostname milestones.
