# Excluding ambiguous send ordering

The live-send experiment now permanently rejects hostname results after a
socket's second send attempt. This is a conservative coverage restriction, not
general support for concurrent writes. It prevents a later send's hostname from
being used for earlier bytes still queued in TCP, including when an old positive
flow record survives. Networking continues normally.

## Reproduced counterexample

Before this change, the publication guard correctly detected map-write failures
and overlapping map updates, but could accept a complete, stable, wrong name:

1. Create two live TLS objects with different names on duplicated descriptors
   for one connected socket.
2. Enable `TCP_CORK`, then invoke both handshakes sequentially. Each live LSM
   observation correctly identifies its own sending object.
3. Verify with `SIOCOUTQNSD` that TCP still holds unsent bytes, then uncork.
4. The peer reads `first.test` in the first ClientHello, but the flow map reports
   `second.test`, the latest per-socket observation.

This was reproduced on both IPv4 and IPv6 with the previous observer at
`2690b12`; TCP held 3,113 unsent bytes in each case. No missed observation,
concurrent mutation of an SSL object, map error or failed publication was needed.
The behavior is consistent with the documented
[TCP_CORK buffering semantics](https://man7.org/linux/man-pages/man7/tcp.7.html).
The test verifies bytes are still queued rather than relying on a sleep within
the cork timer.

The global publication guard alone cannot repair this: both writes may finish
before the packet is emitted, leaving an unchanged control word during lookup.
Moving the existing hostname copy to a later packet hook also cannot identify
which of several queued writes supplied its bytes.

## Monotonic socket guard

`send_guards` is a preallocated, non-evicting hash keyed by the actual application
socket cookie. Socket creation inserts state zero with `BPF_NOEXIST`; it never
reinitializes an existing key. Userspace cannot update or delete entries because
the map has `BPF_F_RDONLY`. The loader validates its exact specification.

| State | Meaning | Reader result |
| --- | --- | --- |
| 0 | No LSM send attempt yet | Empty flow identity only; reject a positive name |
| 1 | Exactly one attempt | Apply the remaining publication and hostname checks |
| 3 | Multiple attempts | Reject the entire record and return zero |

At LSM entry, before inspecting the userspace call chain, an atomic
compare-and-swap changes zero to one. Any attempt that does not win this first
transition atomically ORs in three. No operation clears the state. Raw writes,
other-process writes, zero-length writes and failed attempts count too; the guard
does not try to infer whether the eventual syscall accepted bytes.
An earlier LSM denial is preserved before any guard change, as in the existing
observer; such a denied operation cannot send bytes.

Every transition is inside the existing global publication interval. If two
LSM invocations overlap, at most one wins the first transition. The other makes
the socket ambiguous. A late-finishing first writer may still replace diagnostic
snapshot data, but cannot restore eligibility. No completion hook, trace event,
userspace setter or operation-exit observation is needed to preserve this state.

The egress publisher copies a hostname only while the guard is one. Readers
independently read the guard for the record's application cookie inside the same
global interval as the record lookup. This second check is necessary: an older
positive flow might never receive another successful packet-map update. A send
that starts after the guard lookup changes the global generation, so the final
control read rejects it. All checks use maps from the same collection.

The 256 guard entries are never reclaimed during this experiment, including for
closed sockets. Losing LRU snapshot or flow entries therefore cannot forget
ambiguity. At capacity, a failed insertion poisons publication for the entire
collection through the independent control word; no old record becomes eligible
again. This bounded diagnostic policy needs lifecycle work before a long-running
observer could use it.

## Validation, 2026-10-16

The combined privileged suite passes on the documented Linux x86-64/OpenSSL
profile, alongside local unit tests and VM-tagged vet. The BPF objects and client
compile with warnings treated as errors. Run using [SEND.md](SEND.md); include
the [fault object](PUBLICATION.md) for the complete publication suite.

- Sequential corked and barrier-started parallel handshakes on duplicated
  descriptors are rejected for both IP families, with different and identical
  names. The peer still receives a ClientHello. Parallel tests exercise separate
  SSL objects and do not claim a forced ordering inside the kernel.
- An unsupported first write followed by supported TLS stays unknown.
- Detaching only the private egress publisher retains its old positive flow;
  a second LSM send still makes guarded lookup reject that retained entry.
- Deleting diagnostic snapshot/flow records and sending through a replacement
  TLS object cannot reset ambiguity on the same live socket.
- Filling all 256 guard slots, including closed sockets, makes the next creation
  poison publication while TLS continues. Fault injection also exercises an
  actual `ENOENT` guard-insertion error.
- Userspace cannot reset or delete a guard. Local reader tests reject missing
  guards, incompatible/evicting maps, unexpected states and publication changes
  after the guard read, returning zero data on every failure.
- Existing first-send correlation, abandoned setup, shared-socket objects whose
  other object never sends, reuse, publication failure and REDIRECT tests pass.

## Remaining scope

A second attempt is excluded even when sequential, made by the same TLS object,
or named identically. This includes partial-write retries and subsequent TLS
handshake/application writes. Ordinary application networking is unaffected;
only optional diagnostic hostname availability is lost. Recovery requires a new
socket lifetime in a healthy collection, not waiting or changing the TLS object.

This guard does not prove packet provenance for every first attempt. The current
egress hook can copy the single observation onto control packets as well as data;
payload/sequence validation, deferred and retransmitted output, reinjection and
other kernel send paths still need a defined scope and proof. Mutating one SSL
object's fields concurrently remains unsupported. Flow tuple reuse, observer
detachment/replacement, map lifetime and Mihomo's routing deadline also remain
open. These maps are still diagnostic, with no routing integration or public ABI.
