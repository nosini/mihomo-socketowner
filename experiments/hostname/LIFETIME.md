# Socket lifetime and observer sessions

The current [profile-2 reclamation follow-up](RECLAMATION.md) supersedes the
permanent-allocation limit described in this historical experiment. Live guards
remain monotonic; only final release plus drained callback leases permits deletion.

The live-send reader now rejects retained hostname records after socket release,
TCP closure or loss of its original observer session. A new socket reusing the
same tuple cannot inherit a retired socket's name. Stop/restart creates a fresh
collection and leaves already-open sockets unknown, while networking continues.

This is the private, in-process experiment's lifecycle contract. It does not yet
define a public map ABI or a crash-safe protocol between independent services.

## Retiring a socket

The observer attaches two additional cgroup programs:

- `cgroup/sock_release` permanently sets the cookie's existing non-evicting guard
  to excluded. It does not allocate, delete a record, or wait for final TCP object
  destruction. Closing one of several duplicated descriptors does not release
  the socket; releasing the final file reference does.
- `sockops` registers state callbacks at active establishment. Registration must
  succeed before a socket-local readiness marker permits first-write capture.
  A subsequent non-ESTABLISHED state permanently excludes the socket, including
  peer FIN/RST while the application still holds its descriptor. Registration
  failure poisons the collection rather than admitting an unmonitored socket.

Both paths use the same global publication interval as sends and egress. A reader
overlapping retirement rejects the changed generation or active writer count;
a later reader rejects the excluded cookie even if its old positive flow entry
has never been replaced. Guard entries are not reclaimed in this experiment.

The Linux reference implementation calls the
[release program before protocol close](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/af_inet.c)
and the [TCP state callback before unhashing a closing socket](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/tcp.c).
Those ordering points matter for reuse: invalidation must precede making the
old connection's tuple available to a different socket. These are direct cgroup
callbacks, rather than tracing exit events used as the sole lifetime authority.

The existing SYN publication still replaces a reused flow key with unknown for
the new socket. If that publication fails, the independent failure latch rejects
the whole collection. If publication is completely suppressed in the fault test,
the old cookie's excluded guard independently rejects the retained old name.

## A live reader requires the original session

After attaching every required program, the loader creates exactly one session
for that owner. The session records kernel identities for its five links
(creation, release, state, send and egress), their programs and attachment targets,
and five maps (control, guards, snapshots, flows and socket storage).

The session holds additional references to those exact kernel maps and links,
so their IDs cannot be recycled during its lifetime. These references do not
authorize reading after revocation. A lookup uses the retained map handles and
validates both the owner's original handles and the retained references, before
and after the existing publication/record/guard read interval. It requires:

- Original map identities throughout; matching shape or copying a healthy
  control word from another collection is insufficient.
- Original link and program identities, cgroup identity/attachment type or LSM
  target identity, with successful kernel information queries.
- An attached cgroup link: explicit detach can leave its FD open and inspectable,
  but its reported cgroup identity becomes zero.
- The same owner and session, with no previous revocation. A missing live-send
  control handle cannot fall back to the deliberately unsafe baseline reader.

Any failed check permanently revokes the session and returns a zero record.
Restoring a pointer or program afterward does not heal it. Legacy attachments
without inspectable BPF links are excluded. The comparison is performed for each
lookup; neither a cached health result nor a TTL replaces it.

An unexpected close of an owner's link FD causes unknown results even if the
session's extra reference temporarily keeps kernel observation attached. Normal
stop takes the session's exclusive lock, revokes readers, then closes both sets
of link references. Concurrent reads hold a shared lock, so an owned stop cannot
detach probes midway through an authorized lookup. Close also releases the map
references. In-place observer upgrades are unsupported: revoke and start a fresh
collection instead.

The handshake uprobe is a baseline diagnostic and is deliberately absent from
session requirements. The live-send suite continues with that uprobe disabled.

## Validation, 2026-10-16

The combined VM suite passes on the documented Linux x86-64/OpenSSL profile.
Local unit tests and VM-tagged vet pass; BPF/client compilation treats warnings
as errors. Stop/restart and concurrent lookup/stop also pass under Go's race
detector. Run with [SEND.md](SEND.md) and the [fault object](PUBLICATION.md).

The lifetime tests retain positive records while exercising:

- Final close versus closing only one duplicated descriptor, for IPv4/IPv6.
- Peer FIN and RST while the client descriptor remains open, for both families.
- Target process exit, without relying on a userspace cleanup notification.
- Exact IPv4/IPv6 tuple reuse with a new cookie while the old client FD remains
  open after RST. Suppressing flow updates retains the old positive entry, which
  is rejected until the new socket publishes its own name.
- Actual callback-registration failure, with optional metadata disabled and
  the TLS ClientHello still reaching its peer.
- Closing each required link; explicit cgroup detach with an open FD; replacing
  the program on a still-live link; and restoring it after revocation.
- Same-layout map replacement, swapped/missing control handles, and an original
  map FD closed while a separate lease retains its positive data.
- Stop with maps retained, restart with distinct map identities, old descriptors
  staying unobserved, and new sockets publishing only through the fresh session.

Local reader tests also revoke before and after copying retained data, check
zero results on errors, and reject missing or foreign sessions. The existing
packet, publication-failure, send-order and REDIRECT suites continue to pass.
The fault-only flow hold replaces the earlier test's deliberate egress detach;
actual detach now invalidates the entire reader session.

## Remaining scope

This requires the existing private cgroup and trusted ownership of its program
and callback configuration. Arbitrary privileged mutation followed by restoration
between checks is outside the contract; the owner must revoke before changing
attachments. The session references and kernel queries remain private to this
root-run harness, with no least-privilege reader/service boundary established.
The [authority experiment](AUTHORITY.md) now tests private link pins, frozen
maps and a pidfd-bound unprivileged reader through independent observer crash,
reconnect and fresh-instance restart. A public authenticated bootstrap and
deployment contract remain unimplemented.

The first-write/4 KiB restriction, fixed 256 lifetime guards and lack of guard
reclamation remain. Reinjection, other interception/send paths, broader runtime
coverage and performance remain unverified. The [routing experiment](ROUTING.md)
now tests bounded lookup timing and destination preservation through Mihomo's
real REDIRECT inbound. Its supervised test bridge does not establish independent
observer authority or a production routing interface.
