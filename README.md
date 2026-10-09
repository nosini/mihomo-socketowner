# Socket-owner BPF programs

On Linux, mihomo can look up the process behind a connection in BPF maps instead of searching
`/proc`. The maps also answer for connections whose socket has already closed, and, with
`-exec-paths`, for processes that have exited.

- `bpf/sockowner.c` holds cgroup programs that record the process that creates, connects or
  sends on each TCP/UDP socket. On a socket's first outgoing packet they publish that process ID
  and user ID in the `conn_owners` LRU map, keyed by network namespace, protocol, source
  address and source port. The cgroup hooks don't see sends on a connected socket, so with
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
- `mihomo-sockowner` is the loader, a separate Go module so that mihomo itself doesn't
  depend on cilium/ebpf. `mihomo-sockowner attach` loads the programs, attaches them to the root cgroup
  and pins the links in `/sys/fs/bpf/mihomo/links` and the map in
  `/sys/fs/bpf/mihomo/maps/conn_owners`, then exits. `mihomo-sockowner detach` removes the
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

```sh
go generate   # needs clang, llvm-strip and the libbpf headers
CGO_ENABLED=0 go build -o mihomo-sockowner .
```

`go generate` rebuilds `sockowner_bpf*.o` and `execpath_bpf*.o`, which are committed so the
loader builds without clang. `go test` checks that the objects carry the programs
and the map layouts mihomo reads.

In a mihomo checkout, `component/process/sockowner_vm_test.go` compares the BPF lookup with the `/proc` lookup. It
needs the programs attached (with `-exec-paths` for the exec-path tests) and root:

```sh
go test -c -tags sockowner_vm -o process.test ./component/process/
sudo ./process.test -test.v -test.run 'SockOwner|ExecPath'
```
