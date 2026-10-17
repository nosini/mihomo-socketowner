# Reclaiming released socket guards

The current observer uses [protocol 1/profile 2](../../hostname/PROFILE2.md).
Final socket-file release now reclaims its guard slot without restarting the
observer. A socket-local retirement bit and callback count prevent reuse while
an older callback may still hold a guard pointer. Late orphaned TCP output is
ignored for discovery and continues normally. Active and peer-closed-but-held
sockets retain their non-evicting guards; 256 such lifetimes still exhaust the
instance and force ordinary routing.

Profile 1's wire bytes and permanent-allocation obligations remain frozen. The
new reader and observer explicitly request/serve profile 2; old pairs must be
rebuilt together. Missing or incompatible observers leave ordinary networking
unchanged. Broader first-send shapes, reinjection and browser TLS adapters remain
separate work.

## Validation

The tagged VM suite exercises:

- 1024 complete socket lifetimes per IP family with concurrent readers and an
  untouched live anchor guard. Reusing slots cannot reset that anchor's second
  send back into eligibility; fresh sockets still publish their own names.
- Deliberately retained old positive flow data through release and 512 further
  lifetimes per family. Missing old guards keep that data unusable.
- Duplicated descriptors: only final release reclaims. Peer RST alone retires
  but retains the guard until the application closes its descriptor.
- Corked ClientHello flushed after final release: late egress neither recreates
  authority nor poisons a healthy collection, and subsequent TLS still routes.
- Deterministically held callback/publication leases through retirement in the
  fault object: no deletion before the final lease, no new lease after
  retirement, no duplicate deletion and no late recreation.
- A real kernel ENOENT during deletion, preserving positive data while sticky
  publication failure prevents its use; ordinary TLS still reaches its peer.
- The resident observer remains alive through 512 sequential closed sockets.
  Holding 256 sockets open still causes the next allocation to revoke/exit;
  a fresh observer instance works as before.

Run using the ordinary/fault send objects and the environment documented in
[SEND.md](SEND.md), [PUBLICATION.md](PUBLICATION.md) and [OBSERVER.md](OBSERVER.md).
The client fixture permits 512 concurrent slots so exhaustion measures live
sockets instead of cumulative closed ones. Fault controls are absent from the
embedded production observer object.
