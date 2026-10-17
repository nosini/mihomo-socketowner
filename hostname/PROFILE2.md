# Protocol 1, profile 2: final-release guard reclamation

This is the frozen historical profile-2 specification. The current reader and
observer require [profile 3](PROFILE3.md), which adds an immutable initial
ClientHello window and bounded retries. References below to the current reader
and publisher describe the profile-2 implementation.

Profile 2 replaces profile 1's permanent guard allocation with safe reclamation
at final socket-file release. All protocol-1 envelope fields, authentication,
map shapes, record bytes, publication control, authority lifetime and reader
validation rules in [the profile-1 contract](CONTRACT.md) remain mandatory,
except for the guard deletion prohibition and lifetime allocation limit below.
The first-write/4096-byte restriction is unchanged. This is not browser or ECH
support and does not admit broader send shapes.

The bootstrap profile field at offset 64 is **2** in both request and response.
There is no downgrade, guessing or retry against a replacement observer. The
current reader requests profile 2 and requires that exact response. The current
publisher rejects profile-1 requests before granting descriptors. Rebuild the
optional reader consumer and observer together when upgrading from profile 1;
a mismatched pair falls back to ordinary routing. Protocol 1/profile 1 bytes and
obligations remain frozen for historical implementations and golden tests.
`LayoutProfile` remains the historical constant 1; `ReclaimProfile` is 2.
No owner-map ABI changes are involved.

## Reclamation obligations

A live socket's guard remains a non-evicting hash entry: 0 means no attempt,
1 means sole send and 3 means permanently excluded. Neither a second send,
peer FIN/RST, diagnostic eviction nor a timer permits deletion or resetting.
A peer-closed socket with an application descriptor still consumes its slot.
The limit is 256 concurrently retained socket lifetimes; exhaustion still
permanently poisons publication. New observer instances still use fresh maps.

Only final socket-file release permits reclamation. Socket storage holds one
aligned atomic 64-bit callback word, independent of the recyclable hash slot.
Bit 63 is irreversible retirement; lower bits count callbacks that may hold a
guard pointer. Every send, state and egress callback must:

1. Begin the ordinary global publication interval.
2. Acquire a socket-local callback lease by bounded CAS, before any guard lookup.
   Retirement denies new leases; contention or overflow poisons publication.
3. Read or change the guard only while owning that lease.
4. Drop the lease after its last guard access. If it observes retired state and
   is the final lease, delete the guard before ending its publication interval.

The final-release callback begins publication and atomically sets retirement.
It deletes immediately only if the old count was zero. Otherwise the final older
callback owns deletion. Duplicate retirement cannot delete twice. Missing guards
on a leased live socket and failed deletions poison publication permanently.
Late callbacks on a retired socket return without looking up or recreating its
guard. Socket storage remains tied to the kernel socket through orphaned TCP
output and is never reset for that lifetime.

These leases matter because a deleted preallocated hash entry may be reused
while an older BPF callback still holds its value pointer. A global publication
writer count protects readers; it does not serialize writers. Retirement alone
would not protect another socket from an old pointer's atomic update. See the
[kernel hash implementation](https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/hashtab.c).
The socket-local lease protocol prevents the deletion/reuse until all such
pointer holders have left, without a spin lock across helper calls.

## Reader obligations

Guard deletion and every retirement/lease transition participating in authority
occur inside the existing global publication intervals. A read overlapping
retirement or deletion fails its generation/count checks. A later read rejects
the missing old cookie, even if its positive diagnostic record remains unchanged
and the hash slot has been reused for another cookie. Readers must never treat a
missing guard as an unused or eligible socket. An existing candidate repeats the
full guarded read and original-record comparison at route commitment as before.

No additional maps, FDs, reader capabilities or process visibility are needed.
The observer's embedded ordinary object contains no test controls. A separate
fault object tests held callback leases, final-release ordering and a real
ENOENT deletion failure with a retained positive record. See
[reclamation tests](../experiments/hostname/RECLAMATION.md).
