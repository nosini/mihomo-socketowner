# Authenticated hostname bootstrap and cleanup owner

This experiment replaces inherited map FDs with an authenticated local bootstrap
and gives one observer process responsibility for publication and cleanup. It
extends [AUTHORITY.md](AUTHORITY.md), preserving its frozen-map, pinned-link,
pidfd and irreversible-revocation rules. It is not wired into the installed
loader, Mihomo configuration, service generator or service units.

The prototype protocol is versioned so incompatible messages are rejected. It
does not establish a stable public hostname ABI or generic runtime support. The
existing socketowner v1 owner-map interface remains unchanged.

## Endpoint and peer identity

The observer creates a filesystem `SOCK_SEQPACKET` Unix socket in a root-owned
runtime directory. Every ancestor must be a real root-owned directory without
group/world write permission. The endpoint is a root-owned socket with mode
0660 and the configured reader GID; abstract sockets and symlink paths are not
supported. The server additionally checks the kernel's `SO_PEERCRED` UID against
the configured reader UID before receiving a request. Filesystem access alone
does not authorize a caller.

The client requires root peer credentials and obtains the original peer process
pidfd using `SO_PEERPIDFD`, rather than reopening a numeric PID supplied over the
connection. The socket-creating process must be the observer and cleanup owner;
delegated listener FDs and socket activation are outside this prototype. The
publisher verifies that its reader session and journal refer to its own process
identity before making the endpoint available.

Linux's [Unix socket documentation](https://man7.org/linux/man-pages/man7/unix.7.html)
describes credential snapshots, pathname permissions and descriptor passing.
The kernel's [peer-pidfd implementation](https://github.com/torvalds/linux/blob/v6.18/net/core/sock.c)
provides the process reference used here. Missing kernel support fails closed.

## Experimental protocol v1

One request and one response use separate 80-byte packets. Integers in this
envelope are little endian. Reserved bytes and status must be zero.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | Magic `MHNAME01` |
| 8 | 2 | Bootstrap version, 1 |
| 10 | 2 | Kind: request 1, response 2 |
| 12 | 2 | Status, zero |
| 14 | 2 | FD count: request 0, response 4 |
| 16 | 16 | Random client nonce, echoed in the response |
| 32 | 16 | Instance ID; zero in request, nonzero in response |
| 48 | 16 | Four uint32 map IDs in response order; zero in request |
| 64 | 4 | Diagnostic layout profile, 1 |
| 68 | 12 | Reserved, zero |

The response passes exactly four read-only map FDs using `SCM_RIGHTS`, in order:
authority, publication control, sole-send guards and translated flows. The peer
pidfd comes from the kernel socket option, not ancillary data. No link/program
FD, snapshot map, socket storage or write credential is transferred. The current
profile retains the experiment's fixed capacities and Linux x86-64 record layouts;
it is not the version-1 owner-map profile.

The receiver validates every envelope field, nonce, FD count and map identity,
then applies the existing type/size/capacity/frozen-state and authority checks.
Short/oversized packets, payload/control truncation, unexpected ancillary data,
extra/missing FDs and wrong object types reject the entire response. Delivered
FDs are close-on-exec and are closed on every failure; kernel-dropped truncated
rights are not installed in the receiver. VM tests check failure-path FD counts,
and local pipe-lifetime tests verify delivered/truncated rights do not leak.

Both directions use an absolute I/O deadline. The client also rejects completion
after its deadline. The server handles one handshake at a time with a 200 ms I/O
deadline, limiting active handlers and FDs; malformed or stalled clients do not
poison a healthy instance. These are test settings, not a production latency or
denial-of-service claim. Bootstrap occurs when opening/reconnecting a reader
session; per-connection map reads and routing deadlines remain separate.

## Owned lifecycle and recovery journal

The owner uses a private mode-0700 state directory and a stable mode-0600 flock
file. It never unlinks the lock file. A second owner cannot initialize while the
first holds that lock. Root-owned files must be regular, singly linked and mode
0600; opens reject symlinks.

Before the first attachment can be pinned, the owner atomically commits a bounded
JSON journal through a temporary file, file sync, rename and directory sync. The
journal contains no hostname history. It records:

- Journal version and boot/PID-namespace identity.
- Original owner PID plus pidfs device/inode identity.
- A random instance name and the configured pin-root path/device/inode.
- Pending/ready state and, once verified, the four shared map identities.

Pins live in a unique private instance directory. Before publication, the owner
checks that the frozen map bundle belongs to its observer collection and that
all five required pins refer to the original live links/programs/targets. It
commits ready state before creating the reader endpoint.

Graceful shutdown stops accepting handshakes, revokes authority, closes observer
references, removes its socket and known instance pins, clears the journal and
releases the lock. Retained reader FDs continue to exist, but their frozen gate
is permanently revoked. Cleanup is idempotent after completion.

After a crash, the next owner acquires the lock and examines the old journal.
It reopens the recorded numeric PID only for cleanup, comparing the resulting
pidfs device/inode with the original identity. A matching live process prevents
cleanup, even if its lock has already closed. A matching exited process or a
different process now using that PID permits cleanup of the old instance. The
cleaner never signals a numeric PID or the replacement process. The
[64-bit pidfs identity implementation](https://github.com/torvalds/linux/blob/v6.18/fs/pidfs.c)
is the basis for this comparison on the verified platform.

Recovery checks boot, namespace and pin-root identity before touching pins. It
removes only the journal's own instance and known root-owned private pin files.
Unexpected contents, symlinks, malformed/oversized journals or incompatible
versions fail closed and preserve the journal for inspection. An unrelated pin
directory is left intact. Pending intent and partially pinned setup are covered,
so recovery does not depend on the previous owner reaching ready state.

Recovery happens on the next owner start. If no owner restarts, crash pins remain
until trusted cleanup runs; readers still reject the dead peer immediately.
The [observer command](OBSERVER.md) runs recovery on start and has a `cleanup`
subcommand; there is still no deployed watchdog or restart policy.
Boot/namespace/pin-root mismatches require deliberate administrative handling,
rather than guessing which resources can be deleted.

## Validation

The full VM suite passes, including existing Mihomo routing and authority tests.
The bootstrap and relevant crash/interrupted-read cases also pass with the
supervisor, observer and reader built under Go's race detector. Local unit/race
tests and VM-tagged vet pass; C/BPF compilation treats warnings as errors.

The new cases cover real nonroot FD transfer and reconnect for IPv4/IPv6, exact
UID denial, clean stop while the owner process remains alive, held/released lock
behavior, restart after intent/partial-pin/ready crashes, reused-PID identity,
unrelated-pin preservation, malformed client/server packets, stalled clients,
wrong FD types/counts and corrupt/foreign recovery state.

Run the combined suite with [AUTHORITY.md](AUTHORITY.md). Bootstrap tests create
and remove their own root-owned runtime directories and private bpffs mounts
inside the VM's isolated mount namespace. They do not edit existing services or
owner pins. Without the authority VM environment, privileged tests skip.

## Next integration work

The implementation remains private to `experiments/hostname`. Production use
still needs a stable optional reader record contract, reader packaging and
tested service confinement/restart policy. The resident
[observer command](OBSERVER.md) now packages this initialization. The native
[lookup follow-up](NATIVE.md) provides independent configuration and bounded,
cancelable bootstrap/lookup with routing-only descriptor lifetime.
The exact-build, single-target, first-send/4 KiB and fixed-guard restrictions
remain. Broader sends, reinjection, full TLS and browser encrypted-DNS/ECH support
remain unverified.

The [Mihomo metadata follow-up](../../../mihomo/docs/application-hostname-metadata.md)
defines internal rule-source precedence and destination preservation. It remains
a supervised consumer. The [consumption follow-up](CONSUMPTION.md) connects this
bootstrap directly to capability-free Mihomo with a fresh post-match check and
fallback before dialing. The native hook remains experimental and has no
installed observer service.
