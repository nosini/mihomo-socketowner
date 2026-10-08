# Socket-owner BPF programs

On Linux, mihomo can look up the process behind a connection in a BPF map instead of searching
`/proc`. The map also answers for connections whose socket has already closed.

- `bpf/sockowner.c` holds cgroup programs that record the process that creates, connects or
  sends on each TCP/UDP socket. On a socket's first outgoing packet they publish that process ID
  and user ID in the `conn_owners` LRU map, keyed by network namespace, protocol, source
  address and source port.
- `mihomo-sockowner` is the loader, a separate Go module so that mihomo itself doesn't
  depend on cilium/ebpf. `mihomo-sockowner attach` loads the programs, attaches them to the root cgroup
  and pins the links in `/sys/fs/bpf/mihomo/links` and the map in
  `/sys/fs/bpf/mihomo/maps/conn_owners`, then exits. `mihomo-sockowner detach` removes the pins.
  It needs `CAP_BPF` and `CAP_NET_ADMIN`, plus `CAP_CHOWN` for `-reader-user` and
  `-reader-group`.
- mihomo opens the map read-only with plain `bpf()` calls
  (in its `component/process/sockowner_linux.go`), at the path in `find-process-bpf-map`. It needs no
  capabilities for that where the map's file permissions allow it, and falls back to the
  netlink and `/proc` lookup when the map is missing or doesn't know a connection.

## Building

```sh
go generate   # needs clang, llvm-strip and the libbpf headers
CGO_ENABLED=0 go build -o mihomo-sockowner .
```

`go generate` rebuilds `sockowner_bpfel.o` and `sockowner_bpfeb.o`, which are committed so the
loader builds without clang. `go test` checks that both objects carry the programs
and the map layout mihomo reads.

In a mihomo checkout, `component/process/sockowner_vm_test.go` compares the BPF lookup with the `/proc` lookup. It
needs the programs attached and root:

```sh
go test -c -tags sockowner_vm -o process.test ./component/process/
sudo ./process.test -test.v -test.run SockOwner
```
