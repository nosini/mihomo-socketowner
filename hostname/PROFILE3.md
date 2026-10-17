# Protocol 1, profile 3: immutable initial ClientHello window

Profile 3 admits a larger first ClientHello write and verified retries within
its original byte window. It inherits the authentication, four-map bundle,
publication, authority, reader validation and final-release reclamation rules
of [profile 1](CONTRACT.md) and [profile 2](PROFILE2.md), except for the
sole-write/4096-byte restriction and the private storage details below.

The bootstrap profile field at offset 64 is **3** in both request and response.
The current reader requests exactly 3; the publisher rejects other profiles
before granting descriptors. Rebuild the optional reader consumer and observer
together. There is no downgrade, profile guessing or reconnect to replacement
authority. Historical profile-1/profile-2 envelopes and obligations remain frozen.
`InitialWindowProfile` is 3; `LayoutProfile` and `ReclaimProfile` retain their
historical values 1 and 2. Public map dimensions and the process-owner ABI do not
change.

## Initial capture and retries

A socket starts with guard 0. A CAS selects at most one initial send attempt and
changes the guard to 1. That attempt must use the verified live OpenSSL socket
BIO/write path, a single kernel `ITER_UBUF` matching the syscall arguments, and
an established TCP socket with no older queued or unacknowledged bytes. Capture
is limited to **16384 bytes**, including the TLS record header.

The attempted buffer must contain exactly one complete plaintext TLS handshake
record whose first and only handshake message is a complete ClientHello. Record
and handshake lengths must describe the whole captured buffer. Header checks
restrict eligibility; the hostname still comes from the verified live SSL
connection, never from parsing SNI, DNS or decrypting traffic. This is transport
hostname evidence, not verified ECH-inner evidence.

The original TCP sequence, bytes, live SSL address and raw hostname observation
are published once as an immutable private window. A later send is eligible
only if all of these hold:

- The guard is still 1 and the original window has been completely published.
- The same verified live SSL connection, descriptor and exact raw hostname
  length/buffer are observed on a supported write path.
- The established socket's current TCP write sequence lies inside the original
  window, and the whole requested buffer fits its remaining slice.
- The kernel's actual single-buffer iterator matches the syscall, its bytes
  exactly match that original slice, and the TCP write sequence has not changed
  during the comparison.

A retry cannot extend or overwrite the window or refresh its observation
timestamp. Emitted TCP payloads still require an exact byte/sequence match
against the window. Automatic retransmission can match those same bytes.

Every unsupported later attempt irreversibly changes the guard to 3, even for
the same hostname. No later attempt repairs an invalid initial capture. Changed
bytes/names, another TLS object, writes beyond the captured window, subsequent
records, vectors and general concurrent writes are unsupported. A positive
diagnostic flow record retained across exclusion cannot authorize routing:
readers independently check the guard and publication state at lookup and again
at route commitment.

## Reader lookup and validation

Every egress segment of the window rewrites the flow record's per-packet fields
(TCP sequence, payload length and packet timestamp, offsets 296..311), and a
retried window can still be emitting segments between lookup and route
commitment. Profile-3 `Candidate.Validate` therefore repeats the full guarded
read but requires only the cookie and the complete original observation
(offsets 0..295) to be unchanged. A changed name, another socket at the flow key,
an empty observation from a later packet or an excluded guard still fails.

The SYN publishes an unnamed record before the proxy can accept the connection.
A lookup that finds no record for the flow returns `ErrNoFlow` (which wraps
`ErrUnavailable`): the connection was not opened by the observed process, or its
record was evicted. Callers should return unknown immediately rather than wait.

## Private storage and retirement

Small socket storage retains readiness and the profile-2 callback lease word.
Captured windows live in a separate preallocated, non-evicting private hash of
256 entries, seeded from an immutable zero template at socket creation. Creating
either the guard, window or socket storage must succeed, or publication is
permanently poisoned. The capacity remains 256 concurrently retained socket
lifetimes, including peer-closed sockets still held by the application.

Every callback acquires its socket-local lease before looking up either private
hash. Final socket-file release sets irreversible retirement; only the final
older lease, or retirement with no leases, deletes both entries. Failed deletion
poisons publication. A late callback cannot acquire a lease or recreate entries.
This prevents preallocated slots from being reused while an older callback
still holds a pointer. All authority-changing transitions remain inside global
publication intervals. The observer checks the private maps' original identities
as part of its session; no additional reader FDs, capabilities or process
visibility are introduced.

## Verified scope

The adapter remains specific to the hashed OpenSSL 3.5.3 x86-64-v3/libc build
and one target process described in [OBSERVER.md](../experiments/hostname/OBSERVER.md).
Direct and local TCP REDIRECT and Mihomo's TUN system stack are tested for
IPv4/IPv6; the TUN case keys the flow by the original tuple in the device's
namespace (see [TUN.md](../experiments/hostname/TUN.md)). Local nftables
auto-redirect is also tested using the accepted post-NAT REDIR flow. This does
not add the gvisor native stack, TPROXY, UDP/QUIC, multi-application discovery,
browser/NSS support, ECH-inner names, HelloRetryRequest handling or general
later-write attribution.
See [retry validation](../experiments/hostname/RETRIES.md) for frame paths and
tests, including real short writes and completed TLS through confined services.

Controlled [TLS ticket resumption and SSL reuse](../experiments/hostname/TLS.md)
pass through the confined TUN service for TLS 1.2/1.3 and IPv4/IPv6 without any
profile or adapter change. This covers new SSL objects and `SSL_clear` onto new
socket lifetimes, including changed/removed names and ordinary fallback. It
does not establish early-data, HelloRetryRequest or cross-origin reuse support.
