# Publication failure guard

The live send observer now rejects hostname records when a map insertion,
replacement or socket-scope storage creation fails. This covers the case where
an attempted invalidation leaves an older positive hostname in an LRU map.
Networking continues; hostname availability is lost for that observer instance.
All maps remain private, with no routing or service integration.

## Protocol

`publication_state` is a one-element array with a preallocated, zero-initialized,
aligned 64-bit control word. `BPF_F_RDONLY` prevents userspace from resetting it;
the loader checks its exact map specification. Kernel writers update it through
atomics, without allocating another map entry. The tested profile is Linux
x86-64; array preallocation and alignment are described in the
[kernel array-map documentation](https://docs.kernel.org/bpf/map_array.html).

| Bits | Meaning |
| --- | --- |
| 63 | Sticky publication failure |
| 16–62 | Generation, incremented at every successful writer entry |
| 0–15 | Active writer count |

Socket creation, live-send observation and flow publication enter this protocol
before reading or changing their metadata. Entry atomically increments generation
and writer count together. Writers may overlap; this is a reader-validation
protocol, not a lock. Exit decrements only the count. Any cookie-seeding update,
scope-storage creation, send-guard insertion or record-map update failure
atomically sets the failure bit before releasing its count. That bit survives
every writer's exit.

Entry uses at most 16 compare-and-swap attempts. Exhausted retries or either
counter reaching its limit permanently set failure rather than allowing an
unguarded write or counter wrap. This intentionally sacrifices availability under
heavy contention; performance and a suitable production scope are unmeasured.

`readPublished` performs these steps for each individual record lookup:

1. Read the control word; reject failure or any active writers.
2. Read the requested record from the same observer collection. The live-send
   reader also checks its [per-socket send guard](SEND_ORDER.md) in this interval.
3. Read the control word again; accept only if it exactly matches the first.

Every error returns a zero record. A complete writer between the reads changes
generation even if its count has returned to zero. A writer overlapping either
read exposes its count, changed generation or failure bit. Thus a failed update
cannot expose a retained old value through this reader. This claim concerns the
lookup interval; it does not establish the record's TLS-operation or flow-lifetime
validity. Cached health checks and direct record-map lookups do not implement
this protocol. The deliberately unsafe handshake baseline retains direct lookups.

The ordinary reader does not wait or retry. Test helpers retry transient busy or
changed results for at most 100 ms so unrelated ACK publication does not make
fixture assertions flaky. Sticky failure is never retried. This test convenience
is not a proposed routing wait policy.

## Failure and recovery

Failure disables hostname publication for the entire collection, including older
and newly opened sockets. The failed collection cannot recover in place. A fresh
collection starts with fresh control and record maps, but safely replacing an
observer and handling already-open sockets remains separate work. A reader must
never combine one collection's control map with another's data maps.

Socket creation, sends and egress still return their normal allow result; an
earlier LSM denial is preserved. Failure affects optional metadata availability,
not application connectivity. Unsupported live-send paths still publish unknown
records while healthy, and a failed attempt to publish unknown poisons the
collection just like a failed positive update.

## Validation, 2026-10-16

The full baseline, live-send, direct/REDIRECT flow and publication suite passed
on the documented Linux 7.2.8 x86-64/OpenSSL profile. C objects and the fixture
compile with warnings treated as errors; local unit tests and VM-tagged vet pass.

The opt-in fault object exercises actual kernel error paths:

- `BPF_NOEXIST` replacement of an existing snapshot or flow fails with `EEXIST`.
  IPv4/IPv6 tests confirm an old positive name remains in the raw map while
  guarded snapshot and flow lookups both return failure and zero records.
- `BPF_EXIST` insertion of a missing snapshot, flow or send guard fails with `ENOENT`.
  Both older and newly opened sockets become unknown to the guarded reader.
- Invalid socket-storage creation flags return NULL and poison publication,
  including when no scope marker could be installed on the new socket.
- Clearing fault injection cannot heal a failed instance; userspace cannot write
  its control word. TLS bytes still reach the peer after failure.
- Two deliberately held writer counts block reads even after another writer has
  fully copied a valid record. Reads become usable only after both counts end.
- Writer-count and generation exhaustion poison without wrapping. The ordinary
  object contains neither fault controls nor the test command program.

Local tests also exercise writes and failure between control reads, control and
record lookup errors, zeroing on every error, and rejection of incompatible
control-map layouts. The VM errors exercise failure handling without exhausting
real system memory; real OOM pressure and contention limits remain unmeasured.

Build the baseline and ordinary send object using [SEND.md](SEND.md), then add:

```sh
clang -O2 -g -Wall -Werror -mcpu=v3 -D__TARGET_ARCH_x86 -target bpfel \
    -DHOSTNAME_PUBLICATION_TEST -c experiments/hostname/bpf/send.c \
    -o experiments/hostname/build/send-fault.o
sudo env HOSTNAME_VM_OBJECT="$PWD/experiments/hostname/build/snapshot.o" \
    HOSTNAME_VM_SEND_OBJECT="$PWD/experiments/hostname/build/send.o" \
    HOSTNAME_VM_FAULT_OBJECT="$PWD/experiments/hostname/build/send-fault.o" \
    HOSTNAME_VM_CLIENT="$PWD/experiments/hostname/build/client" \
    unshare --net sh -c 'ip link set lo up; exec experiments/hostname/build/hostname.test -test.v -test.timeout 120s'
```

The test-only object can seed control states and force failures. It must never
substitute for the ordinary observer outside these tests.

## Remaining scope

The control generation detects publication changes during a lookup. It does not
identify socket, flow or observer lifetimes, serialize sends, or establish which
send produced a packet. The [send-order guard](SEND_ORDER.md) separately excludes
multiple attempts on a socket, including concurrent and corked writes. First-send
packet provenance, retransmission, reinjection, tuple reuse, detached observation
and Mihomo's route commitment still need proofs. A stable successful read alone
is not routing-safe hostname evidence.
