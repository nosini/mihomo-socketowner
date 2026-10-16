# Development

On Linux, mihomo can look up the process behind a connection in BPF maps instead of searching
`/proc`. The maps also answer for connections whose socket has already closed, and, with
`-exec-paths`, for processes that have exited.

- `bpf/sockowner.c` holds cgroup programs that record the process that creates, connects or
  sends on each TCP/UDP socket. On a socket's first outgoing packet they publish that process ID
  and user ID in the `conn_owners` LRU map, keyed by network namespace, protocol, source
  address and source port, both read from the packet after any NAT translation. Socket
  ports can differ when redirection remaps a port to avoid a collision at its listener.
  The cgroup hooks don't see sends on a connected socket, so with
  `-exec-paths` LSM programs in `execpath.c` record those. Without it, a connected socket
  that a process hands to another stays with the process that connected it.
- `bpf/execpath.c` holds LSM programs that record the executable of every process: when it
  executes a program, when it's forked (a copy of the parent's) and when it's freed. Running
  processes keep their record in task storage, `exec_tasks`; `exec_recent` keeps the latest
  records by process ID, including those of processes that have exited. A process's record goes
  there at exec and when it's freed, which can be well after it was reaped and can no longer be
  found by process ID, so LSM hooks on `socket_connect` and `socket_sendmsg` also save it the
  first time the process uses a socket. Each record has the process's start time, so a reused
  process ID isn't mistaken for the owner. An iterator adds the processes that were already
  running. Only LSM hooks record, because the kernel skips a tracing program on a CPU where the
  same program was preempted, which would leave a forked process without a record.
- The repository root builds `socketowner` as an independent Go module using
  cilium/ebpf. `socketowner attach` loads the programs, attaches them to the root cgroup
  and pins the links in `/sys/fs/bpf/mihomo/links` and the map in
  `/sys/fs/bpf/mihomo/maps/conn_owners`, then exits. `socketowner detach` removes the
  pins. It needs `CAP_BPF` and `CAP_NET_ADMIN`, plus `CAP_CHOWN` for `-reader-group`. With
  `-exec-paths` it also attaches the programs of `execpath.c` and pins their maps next to
  `conn_owners`. Those read kernel structures, relocated with the kernel's BTF, so they need
  `CAP_PERFMON` and a kernel with the BPF LSM active (`bpf` in `/sys/kernel/security/lsm`).
  `-reader-group` gets read access to the `maps` directory and the maps, which stay root's:
  their owner could make them writable and forge entries. Anyone may pass through the pin
  directory to `maps`. `/sys/fs/bpf` itself is usually root's alone, though, so a reader that
  isn't root needs the `maps` directory bound somewhere it can reach, for example with
  systemd's `BindReadOnlyPaths=`.
- mihomo opens the maps read-only with plain `bpf()` calls
  (in its `component/process/sockowner_linux.go`), at the path in `find-process-bpf-map`. It needs no
  capabilities for that where the maps' file permissions allow it. It finds a running process
  in `exec_tasks` through a pidfd, which needs no access to the process either. Without the
  exec-path maps it reads the owner's `/proc/<pid>/exe`, and it falls back to the netlink and
  `/proc` lookup when the maps are missing or don't know a connection.
  `find-process-bpf-only: true` turns both fallbacks off, so that mihomo needs no access to
  other processes at all.

## Building

Go 1.25 or newer builds the loader. The embedded objects are checked in, so a normal
build needs no C compiler:

```sh
CGO_ENABLED=0 go build -o socketowner .
go test ./...
```

To regenerate the BPF objects after a C source change:

```sh
go generate   # needs clang, llvm-strip and the libbpf headers
CGO_ENABLED=0 go build -o socketowner .
```

`go generate` rebuilds `sockowner_bpf*.o` and `execpath_bpf*.o`, which are committed so the
loader builds without clang. `go test ./...` checks that the objects carry the programs
and the map layouts mihomo reads.

The loader's privileged regression test requires cgroup v2, nftables and iproute2.
Run it in a dedicated network namespace; it attaches only to its own temporary cgroup:

```sh
go test -c -tags sockowner_vm -o socketowner.test .
sudo unshare --net sh -c 'ip link set lo up; ./socketowner.test -test.v -test.run Redirect'
```

It forces source-port collisions at a redirect listener and checks that the translated
TCP and UDP peers resolve to the sending process, for IPv4 and IPv6. TCP cases also
cover IPv4 options and IPv6 destination options. The packet parser skips noninitial
fragments and supports chains of up to eight IPv6 extension headers.

In a separate mihomo checkout, `component/process/sockowner_vm_test.go` compares
the BPF lookup with the `/proc` lookup. It needs the programs attached (with
`-exec-paths` for the exec-path tests) and root:

```sh
go test -c -tags sockowner_vm -o process.test ./component/process/
sudo env SOCKOWNER_MAP=/sys/fs/bpf/mihomo/maps/conn_owners \
    ./process.test -test.v -test.run 'SockOwner|ExecPath|ExecMaps'
```

## Interface checks

[Map interface v1](map-interface.md) is the public contract. The loader validates
embedded map types and sizes before loading and advertises v1 through a frozen
`abi_version` map. Tests parse both little- and big-endian objects and check BTF
field offsets as well as sizes. The reader in mihomo checks the version and each
map's dimensions independently; it does not import this Go module.

When testing on a shared machine, use a dedicated `-pin` directory and pass its
`maps/conn_owners` path through `SOCKOWNER_MAP`. Detach that directory after the
tests. The integration tests remain in mihomo because they exercise its reader
and process matching, including missing/unsupported version markers.

## Hostname discovery experiment

The isolated [OpenSSL hostname/socket experiment](../experiments/hostname/README.md)
contains a BPF probe, a controlled TLS client and opt-in privileged VM tests.
It demonstrates ordinary correlation and a missed-observation counterexample;
its snapshots must not be consumed as routing evidence. It has no public pins
and does not change the owner loader or ABI.

The [live send-hook experiment](../experiments/hostname/SEND.md) reads the active
TLS object from a verified call chain at the kernel's send hook. It addresses
that counterexample and tests full flow mapping through IPv4/IPv6 REDIRECT port
collisions. Its [publication guard](../experiments/hostname/PUBLICATION.md) rejects
records after map-update or socket-storage failure, including retained stale
values. Its [send-order guard](../experiments/hostname/SEND_ORDER.md) excludes
sockets permanently after a second send attempt, including parallel/corked writes
that could otherwise mislabel earlier bytes. First-send packet provenance,
flow/observer generations and the routing deadline still require work before
routing integration.

## Independent distribution

Build and distribute the loader from this repository, including its license and
the corresponding BPF sources. Do not add it to mihomo's build or release scripts.
Deployments install or update this binary explicitly, then restart its service.
Service units, SELinux policy and reader-group setup belong to
[hardened-proxy-service](https://github.com/nosini/hardened-proxy-service).
