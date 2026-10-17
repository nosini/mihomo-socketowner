# Matching the observed write to emitted TCP bytes

The current [profile-3 follow-up](RETRIES.md) supersedes this historical
sole-write/4 KiB restriction with one immutable ClientHello window and verified
retries within its remaining bytes. The earlier evidence and limits below
describe the original experiment.

The live-send experiment now copies a hostname into a flow record only when
the packet's payload exactly matches bytes captured from the sole eligible
write, at the corresponding TCP sequence position. Control packets publish
unknown. Missing, changed or unsupported payload evidence permanently excludes
that socket. Application traffic continues through the observer unchanged.

This adds a bounded byte relationship to the existing publication and send-order
guards. It remains a private diagnostic experiment, with no routing integration.

## Capturing the attempted write

After verifying the live TLS/BIO call chain, the first LSM send attempt checks
the kernel's actual `msghdr.msg_iter` through CO-RE:

- It must be a write-direction `ITER_UBUF` with zero iterator offset.
- Its buffer pointer and count must match the live x86-64 `write` registers and
  the LSM's size argument.
- The socket must be established TCP, with `write_seq == snd_nxt == snd_una`:
  there are no older queued or unacknowledged bytes at capture.
- The count must be between 1 and 4,096 bytes, inclusive.

The hook copies the whole attempted buffer into its pre-created socket storage,
checks the TCP positions again, then publishes sequence and length. Any failed
check leaves the capture unusable. The storage is zero-initialized at socket
creation; its allocation failure still poisons the collection. Only the first
attempt writes these bytes. Later attempts cannot replace or reset them and
remain excluded by the independent monotonic send guard.

The iterator checks follow the kernel's
[single-buffer iterator definition](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/linux/uio.h).
The [socket write path](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/socket.c)
passes that iterator through LSM before protocol dispatch;
[TCP send](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/tcp.c)
serializes the subsequent copy and advances `write_seq` as bytes are accepted.
The experiment verifies the needed kernel types against the running VM's BTF.
Reading TCP positions alone is not a lock or an attribution proof: single-attempt
exclusion and comparison of the actual emitted bytes are also required.

## Matching at egress

The parser validates IP/TCP lengths, ports, sequence and payload bounds before
constructing the existing translated flow key. The supported shape is ordinary
IPv4 TCP, including bounded header options, or IPv6 TCP without extension headers.
Fragments, jumbograms, reserved header bits, truncated headers and inconsistent
lengths are excluded. IP length must equal the skb's network length.

A positive packet must have a nonempty payload and ACK set, with no SYN, FIN,
RST or urgent flag. Compute the unsigned 32-bit offset from the captured sequence:
the entire payload must fit inside the captured write. This handles segments
and a small write spanning sequence-number wrap. Every payload byte must equal
the corresponding captured byte; no hash or TLS/SNI parsing supplies the match.
A bounded BPF loop compares at most 4,096 bytes, using skb helpers so it can read
nonlinear packet storage.

The flow record includes packet sequence, payload length and observation time.
Only an eligible, matching payload receives the hostname. A normal ACK, SYN or
other packet with no payload publishes empty hostname metadata. Such a later
control packet can replace a positive result with unknown; availability is
deliberately conservative rather than retaining a last-known name.

An unparseable packet or a payload that fails comparison permanently sets the
socket guard to excluded, under the global publication interval. This also
rejects any retained old positive flow record through the reader. An uncaptured
or oversized first write cannot become eligible later. Networking is always
allowed as before, with previous LSM denials preserved.

## Validation, 2026-10-16

The full baseline, live-send, send-order, publication and packet suite passes on
the documented Linux 7.2.8 x86-64/OpenSSL profile, along with local unit tests and
VM-tagged vet. C objects and the fixture compile with warnings treated as errors.
Use [SEND.md](SEND.md) plus the [fault-object build](PUBLICATION.md) to run it.

Live IPv4 and IPv6 tests establish:

- A corked first ClientHello creates a diagnostic send snapshot but no named
  flow. Peer data triggers a new client ACK, verified by its packet timestamp,
  while `SIOCOUTQNSD` still reports unsent ClientHello bytes. That ACK stays
  unknown; uncorking publishes the correctly named payload.
- Dropping the first payload at the private namespace's input hook withholds it
  from the peer. After deleting the flow record and removing the drop rule,
  automatic TCP retransmission recreates a matching record inside the captured
  sequence window, without another application send. The peer reads its SNI.
- A private output rule changes the first payload byte after kernel copy. The
  peer receives the changed byte, and the observer permanently rejects both
  snapshot and flow hostname results for that socket.
- A ClientHello enlarged past 4 KiB with ALPN is unknown but still reaches the
  TLS peer. Another socket remains eligible, proving exclusion is local.
- Existing direct and REDIRECT flow tests continue to pass, including translated
  source-port collisions and preserved original destinations.

The fault build also runs the identical parser/comparator with synthetic packets
for both IP families: full 4 KiB writes, segment slices, sequence wrap, a final
single byte, header options, missing/oversized captures, byte differences around
loop boundaries, out-of-window sequences, control/urgent flags, fragments,
extensions and malformed/truncated lengths. These validate the comparison
algorithm; they are not live tests of every segmentation or offload mode.
Synthetic evidence maps and test programs are absent from the ordinary object.

## Remaining scope

This profile admits one observed `write` attempt of at most 4 KiB per newly
tracked socket. It does not admit retries, subsequent TLS/application writes,
Fast Open payloads, other syscall/iterator paths or concurrent mutation of an
SSL object's fields. Exact comparisons make changed transport bytes unknown;
the verified TLS object's hostname relationship still needs that userspace
lifetime assumption.

The [lifetime follow-up](LIFETIME.md) adds socket retirement, tuple-reuse tests and
in-process session revocation for stopped/replaced links and maps. Independent
service crashes, Mihomo's routing deadline, reinjection, other interception modes,
completed TLS, ECH/browser coverage, minimal privileges and performance remain
unverified.
The prototype performs up to one skb read helper per payload byte; its cost and
4 KiB per-socket storage need measurement before wider use. No routing reader
should treat these private records as authoritative yet.
