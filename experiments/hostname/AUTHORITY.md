# Independent observer authority experiment

This private VM experiment separates the privileged observer from an
unprivileged map reader. It tests observer exit/crash, descriptor teardown,
revocation and reconnect while deliberately retaining old positive records.
It does not introduce a public hostname ABI, authenticated service endpoint,
production reader, systemd unit or deployment policy. The subsequent
[bootstrap experiment](BOOTSTRAP.md) replaces inherited credentials with a tested
authenticated socket and journaled cleanup/recovery owner.

## Why process liveness alone is insufficient

Linux's [exit path](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/exit.c)
tears down file descriptors before the later exit notification. The
[pidfd poll implementation](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/pidfs.c)
reports process exit, rather than the lifetime of each observer attachment.
Consequently, checking a pidfd cannot by itself prove uninterrupted observation.

The counterexample closes the observer's descriptors but keeps its process alive.
The application then closes its socket. Its positive flow and sole-send guard
remain unchanged because retirement observation has stopped; the pidfd still
reports a live process. A pidfd-only check would accept that stale record.
The experiment leaves this unsafe instance inactive and verifies it is rejected.

## Private initialization and revocation

The trusted initializer performs these steps for a fresh instance:

1. Verify the controlled target's library mappings/hashes and attach the five
   required creation, release, TCP-state, send and egress links.
2. Pin all shared maps in a private root-owned bpffs directory, freeze them, and
   pin every required link. The authority map initially contains zero.
3. Activate authority with a private BPF control program that atomically changes
   zero to one. No reader is issued an active instance before setup completes.
4. Give the reader only read-only FDs for authority, publication control, send
   guards and translated flows, plus the observer's original pidfd. A trusted
   manifest binds all four map identities to that bootstrap. No link/program FD,
   snapshot map or socket-storage map is transferred.

Link pins retain kernel references independently of observer descriptors; see
the [bpffs reference handling](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/bpf/inode.c).
They keep observation active through descriptor teardown and process exit until
the pidfd can report death. A trusted cleaner may remove them after that point.
The VM supervisor waits for the observer to be reaped before removing crash pins.
Graceful stop instead revokes first, then removes pins and closes all link FDs.

Revocation atomically sets the revoked bit (mask two): active one becomes three. Activation's
compare-and-swap accepts only zero, so a revoked map cannot be reactivated by the
same control program. Restart requires a new map set and observer pidfd.

Pins survive a crash. A real deployment therefore needs a trusted cleanup owner;
pidfd detection alone does not reclaim resources. A stopped/hung userspace
observer can leave this fixed-profile kernel observation running. This experiment
does not depend on a heartbeat or userspace event consumer for its supported path.

## Read-only descriptors and frozen maps

`BPF_F_RDONLY` controls a map descriptor's access mode. It is not a global map
write prohibition and is not retained in `MapInfo.Flags`. An accessible pin can
be opened with different descriptor permissions. A reader must not infer global
immutability from the creator's FD flag.

All four shared maps are frozen before the reader gets them. Freezing prevents
userspace updates/deletion even through reopened writable FDs, while the reviewed
BPF programs can continue publishing data and changing authority. See the kernel's
[syscall permission and freeze checks](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/bpf/syscall.c).
The VM test verifies a writable authority FD still cannot change its value.
Root can load another writing BPF program; arbitrary privileged mutation is
outside this trust boundary.

The reader validates descriptor mode, exact map ID/type/key/value size/capacity,
expected runtime flags and frozen state. Frozen-state inspection uses its own
procfs FD information. It requires a pidfs-backed pidfd on the verified kernel;
older pidfd implementations or unavailable required information fail closed.

## Lookup and reconnect

Each lookup applies the existing publication/sole-send protocol, with authority
checks on both sides of the record/guard interval:

- The reader still owns the original pidfd identity and it has no exit/error
  readiness. This is polled synchronously for each lookup.
- The original frozen map identities and layouts remain present.
- The authority value is exactly one.

An authority failure permanently revokes that reader. Every failed read returns
a zero record; an already copied positive cannot escape after the final check
fails. Busy/changed publication and absent/unsupported data remain unknown.
There is no cached health result, positive-name cache or time-based authority lease.

A new reader can reconnect to the same still-active instance. Reconnecting to a
dead or revoked instance fails even with retained data. Old readers cannot adopt
new maps or a new observer. Restart removes the old links only after death, creates
distinct maps/pidfd, and observes new sockets. Already-open application sockets,
including those whose first ClientHello is sent after restart, remain unknown.

This validates a read interval. It is not permission to cache a returned name or
use it for a later connection. Production route commitment still needs explicit
instance binding, bounded freshness and metadata precedence; the supervised
[routing experiment](ROUTING.md) is not replaced by an independent service here.

## Validation, 2026-10-16

The full VM suite passes, including the existing Mihomo routing matrix. All new
authority cases also pass with the supervisor, observer and reader built under
Go's race detector. Local unit tests and VM-tagged vet pass.

The opt-in VM suite exercises:

- IPv4/IPv6 observer SIGKILL, normal process exit and explicit revocation while
  the process remains alive, with old positive flow records retained.
- Descriptor teardown held open before exit: private pins preserve new-socket
  observation and socket-retirement callbacks even after all observer FDs close.
- The deliberately unsafe unpinned/pidfd-only counterexample described above.
- Crash and revocation after a separate reader has copied a positive record but
  before it finishes validation; the interrupted read returns zero/unknown.
- Independent reader reconnect while alive, rejection after death/revocation,
  irreversible revocation and fresh-instance restart with old sockets excluded.
- Rejection of a foreign map identity, non-pidfd and writable bootstrap FD.
- A capability-free nonroot reader: map update/delete/freeze, private pin access,
  signaling the privileged observer and BPF program loading are denied. The
  existing VM's unprivileged-BPF policy is part of this test environment.

The target still sends its ClientHello after optional metadata authority is lost.
The peer stops after ClientHello; full TLS, browser/ECH and broader transport
coverage remain outside these tests. This does not establish a production
minimal-capability or SELinux/systemd confinement policy.

## Running

Build the BPF objects, client and Go test binaries as in [SEND.md](SEND.md),
[PUBLICATION.md](PUBLICATION.md) and [ROUTING.md](ROUTING.md). In the VM task
directory containing those artifacts:

```sh
mkdir -p bpffs tmp
sudo env TMPDIR="$PWD/tmp" HOSTNAME_VM_PIN_ROOT="$PWD/bpffs" \
  HOSTNAME_VM_OBJECT="$PWD/snapshot.o" \
  HOSTNAME_VM_SEND_OBJECT="$PWD/send.o" \
  HOSTNAME_VM_FAULT_OBJECT="$PWD/send-fault.o" \
  HOSTNAME_VM_CLIENT="$PWD/client" \
  HOSTNAME_VM_MIHOMO="$PWD/mihomo-route.test" \
  unshare --mount --net sh -c '
    mount --make-rprivate / &&
    mount -t bpf -o mode=0700 bpf "$HOSTNAME_VM_PIN_ROOT" &&
    ip link set lo up &&
    exec ./hostname.test -test.v -test.timeout 150s'
```

The private mount/network namespaces disappear when the run ends. Tests reap
helpers before removing their private pins. No existing owner pins, programs or
services are changed. Without `HOSTNAME_VM_PIN_ROOT`, these tests skip.
The reader helper uses the test VM's ordinary UID/GID 1000; it is not a proposed
deployment identity. Build the socketowner test binary with `-race` to cover the
observer, reader and supervising test processes under the race detector.

## Trust and remaining work

The initializer and cleaner are trusted to pin the correct complete link set,
retain the configured cgroup/attachment scope, and revoke before any deliberate
detach, program replacement or cleanup while the observer lives. The unprivileged
reader does not independently inspect each attachment: it has no link authority.
Unannounced privileged mutation/restoration is outside this contract, as it was
for the in-process experiment. A public bootstrap must authenticate its source;
an untrusted manifest and arbitrary pidfd are not sufficient credentials.

The [bootstrap follow-up](BOOTSTRAP.md) adds an experimental versioned Unix
socket exchange, kernel peer credentials/pidfd and a cleanup journal with crash
recovery. The original inherited-FD tests remain useful isolation tests.
Stable publication/connection identity, production entry points, operator
enable/disable, service confinement and source precedence still need integration
before this becomes a routing interface.
Guard reclamation, broader sends, reinjection and runtime coverage remain open.
