# Resident hostname observer

`mihomo-hostname-observer` runs the experimental hostname observer for one
OpenSSL process and serves the endpoint that Mihomo's `hostname-discovery`
reader connects to. It is the observer setup from the [bootstrap](BOOTSTRAP.md)
experiment, packaged as a command. It is separate from `socketowner`;
process lookup does not need it, and it does not need process lookup.

This is still an experiment. It supports exactly one verified OpenSSL build
and one target process per observer, and its raw diagnostic maps are not standalone routing evidence. The optional
[hostname contract v1](../../docs/hostname-interface.md) defines the authenticated
reader bundle and its lifetime checks.

## Building

On Linux x86-64, from the socketowner repository root:

```sh
go build -o mihomo-hostname-observer ./experiments/hostname/cmd/mihomo-hostname-observer
sudo install -m 755 mihomo-hostname-observer /usr/local/bin/mihomo-hostname-observer
```

The BPF object is embedded in the binary, so building needs only Go.
Regenerating it after changing `bpf/send.c` needs clang and llvm-strip:
`go generate ./experiments/hostname`.

## Running

The target must be an already running process that has loaded the profile's
libraries. Give the observer its PID, a cgroup v2 directory containing it, the
library files exactly as the process mapped them (no symlinks), and the user
that Mihomo runs as:

```sh
pid=$(pidof my-openssl-client)
sudo /usr/local/bin/mihomo-hostname-observer \
    -target-pid "$pid" \
    -cgroup "/sys/fs/cgroup$(cut -d: -f3 /proc/$pid/cgroup)" \
    -profile openssl-3.5.3-x86-64-v3 \
    -libssl /usr/lib64/glibc-hwcaps/x86-64-v3/libssl.so.3.5.3 \
    -libcrypto /usr/lib64/glibc-hwcaps/x86-64-v3/libcrypto.so.3.5.3 \
    -libc /usr/lib64/libc.so.6 \
    -reader-user mihomo -reader-group mihomo \
    run
```

`grep -E 'libssl|libcrypto|libc\.so' /proc/$pid/maps` shows which files the
process mapped. The observer refuses to start unless the mapped device and
inode are the files it hashed and the hashes are the profile's:

| Library | SHA256 |
| --- | --- |
| libssl 3.5.3, x86-64-v3 | `2dead83fbc10ddfbc6240921ebe691995df7753e1a11319de923534e4c992064` |
| libcrypto 3.5.3, x86-64-v3 | `f1b2c9b4070ea2724480a3f0d65e0f80b5d5665782e0de18e7190a0348f33c0b` |
| libc | `090f858814642a3f28e5f4ae6499667e7901e47902ca3e72fb9c8a1967a3b8df` |

Then enable discovery in an experimental Mihomo build, using the default
endpoint:

```yaml
hostname-discovery:
  enable: true
  endpoint: /run/mihomo-hostname/bootstrap.sock
  wait-ms: 50
```

See Mihomo's [hostname discovery documentation](../../../mihomo/docs/hostname-discovery.md)
for that side. Mihomo routes normally whenever the observer is missing.

Stop the observer with Ctrl-C or SIGTERM. If it was killed, the next `run`
cleans up after it, or clean up without starting a new one:

```sh
sudo /usr/local/bin/mihomo-hostname-observer cleanup
```

Use the same `-runtime` and `-pin` for `run` and `cleanup` if you change them.
The defaults are `/run/mihomo-hostname` and `/sys/fs/bpf/mihomo-hostname`. The
command needs root. Under systemd it reports readiness with `READY=1`, so a
unit can use `Type=notify`; no unit or confinement policy is provided yet.

## When it stops

| Event | What the observer does | Exit status |
| --- | --- | --- |
| SIGTERM, SIGINT or SIGHUP | Revokes readers, detaches, removes endpoint, pins and journal | 0 |
| The target exits | Same as SIGTERM | 0 |
| Publication failed, including a full send-guard table | Same as SIGTERM | 1 |
| A link, map or the endpoint server stops matching the instance | Same as SIGTERM | 1 |
| Killed or crashed | Nothing; pins and journal remain. Readers reject it at once | — |
| Started while another observer holds the lock | Refuses and changes nothing | 1 |

Revocation always comes first: an already connected reader returns unknown
before any program is detached. Each start is a new instance with new maps.
Sockets the target opened earlier stay unknown, including their first send.

The send-guard table has 256 entries that are never reclaimed. The target's
257th TCP socket therefore ends the instance. Restarting the observer, for
example with `Restart=on-failure`, gives it a fresh table; connections meanwhile
use Mihomo's ordinary routing.

Startup recovery and `cleanup` use the journal described in
[BOOTSTRAP.md](BOOTSTRAP.md#owned-lifecycle-and-recovery-journal). They never
clean up while the original observer process is alive, and they refuse state
from another boot, PID namespace or pin directory.

## What it checks before attaching

- The profile name is `openssl-3.5.3-x86-64-v3`, the only verified profile.
- All paths are absolute and canonical. The reader user is not root.
- The target is inside the given cgroup v2 directory, as seen from the root
  cgroup namespace at `/sys/fs/cgroup`.
- Each library file is a regular file, not a symlink, with the profile's
  SHA256. The target maps that very file at offset zero.
- The embedded object contains the live-send programs and none of the
  fault-injection maps or programs. The handshake uprobe is not attached.
- The target is still alive after attachment, so the mappings read earlier
  belonged to it and not to a process that reused its PID.

The observer then commits its journal, pins and freezes the reader maps, pins
all five links, activates the authority gate and opens the endpoint. While it
runs, it checks four times a second that the target lives, its links and maps
are the original ones, the gate is active and publication has not failed.
It logs no hostnames.

## Validation, 2026-10-17

Run on the test VM described in [README.md](README.md), with the observer and
test binaries built with the race detector:

- Lifecycle: readiness notification, named lookup through a capability-free
  reader, refusal of a second observer and of `cleanup` while it runs, SIGTERM
  revocation and cleanup, restart without adopting an old socket, SIGKILL with
  pins retained and readers rejecting it, `cleanup` after the crash, automatic
  recovery by the next `run`, and stop after the target exits.
- Refusals: wrong library hash, target outside the cgroup, symlinked library
  path and an unsupported profile, each leaving no endpoint, pins or journal.
- Guard exhaustion: the observer exits 1 after revoking, and a restart serves
  names again.
- The complete earlier VM suite, including the Mihomo routing, reader-commit
  and native lookup matrices, which now share the extracted initialization.

## Not done yet

- A systemd unit, sandboxing, capabilities and SELinux policy, planned for
  hardened-proxy-service. The command currently runs as full root.
- Finding targets by itself. One observer follows one PID; a different
  OpenSSL build, Flatpak runtime or statically linked program is unsupported.
- Reclaiming send guards without a restart.
- Published releases of the [separate reader module](../../hostname/README.md).
  Its v1 contract now freezes the existing bootstrap/profile layout.
- `exec` by the target is not detected. After it, libraries normally load at
  new addresses, so the frame checks stop matching and names become unknown.
