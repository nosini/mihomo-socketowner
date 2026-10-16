# OpenSSL hostname/socket correlation experiment

This experiment reads a live OpenSSL connection hostname and socket BIO at
`SSL_do_handshake()` entry and checks the observed kernel socket cookie against
the client's `SO_COOKIE`. It is development work toward application hostname
discovery, with no public map interface or Mihomo integration.

**Handshake-entry snapshots are not sufficient routing evidence.** The VM suite
reproduces a stale-name counterexample on a single live TCP socket. Resolving
that problem is required before adding a routing reader.

A second [live send-hook experiment](SEND.md) now addresses that specific
counterexample without depending on handshake uprobes or descriptor-table
traversal. It also tests full flow identity through IPv4/IPv6 REDIRECT source-port
collisions. Its [publication guard](PUBLICATION.md) rejects stale records after
map-update or socket-storage failure. Concurrent-send and observer-lifetime
requirements remain open; both experiments still keep all records private.

## Running

Use a disposable Linux x86-64 test VM with cgroup v2, kernel BTF, uprobe support,
Go 1.25+, clang with the BPF backend, libbpf development headers, GCC, OpenSSL
development headers, iproute2 and util-linux. The current profile accepts only
the OpenSSL 3.5.3 x86-64-v3 library files with these SHA256 hashes:

| Library | SHA256 |
| --- | --- |
| `libssl.so.3.5.3` | `2dead83fbc10ddfbc6240921ebe691995df7753e1a11319de923534e4c992064` |
| `libcrypto.so.3.5.3` | `f1b2c9b4070ea2724480a3f0d65e0f80b5d5665782e0de18e7190a0348f33c0b` |

The VM test looks for these under
`/usr/lib64/glibc-hwcaps/x86-64-v3/`. An unknown build or a different mapped
library is rejected before attachment. Supporting another build requires
reviewing its actual layouts and code, including `BIO_s_socket()`'s method
address; changing just a version check or hash is insufficient.

From the socketowner repository root:

```sh
mkdir -p experiments/hostname/build
clang -O2 -g -Wall -Werror -D__TARGET_ARCH_x86 -target bpfel \
    -c experiments/hostname/bpf/snapshot.c \
    -o experiments/hostname/build/snapshot.o
gcc -O2 -g -Wall -Wextra -Werror experiments/hostname/testdata/client.c \
    -o experiments/hostname/build/client -lssl -lcrypto -pthread
go test -c -tags hostname_vm -o experiments/hostname/build/hostname.test \
    ./experiments/hostname
sudo env HOSTNAME_VM_OBJECT="$PWD/experiments/hostname/build/snapshot.o" \
    HOSTNAME_VM_CLIENT="$PWD/experiments/hostname/build/client" \
    unshare --net sh -c 'ip link set lo up; exec experiments/hostname/build/hostname.test -test.v -test.timeout 120s'
```

The root tests require a separate network namespace and refuse the initial
namespace. Each fixture creates its own temporary cgroup, attaches the cookie
program there, and attaches a PID-specific uprobe to its controlled client.
Links and maps are held by descriptors and released at cleanup; nothing is
pinned or installed. No existing service, firewall or owner map is changed.

The ordinary `go test ./...` runs only the unprivileged tests. Privileged tests
also require the `hostname_vm` build tag and both environment variables.

## Observation path

1. The fixture loads OpenSSL, then waits on stdin before creating sockets.
2. The harness verifies the exact binaries and their mappings in that process.
3. A cgroup socket-create program generates a cookie for each of the target's
   TCP sockets. A separate diagnostic entry proves this happened before the
   fixture's reference `getsockopt(SO_COOKIE)`, which could itself create one.
4. At `SSL_do_handshake()` entry, the uprobe reads the current connection's
   type, client/server role, write BIO, hostname pointer and bounded hostname.
5. The BIO method must be the verified library's actual socket method, with
   an initialized descriptor. Memory and custom BIO methods are excluded.
6. Kernel BTF relocations locate the current task's descriptor table, socket
   file and established IPv4/IPv6 TCP socket. The probe reads its nonzero cookie.
7. A private LRU map with 256 entries receives an observation keyed by cookie.
   A fresh observation without a usable hostname invalidates an earlier name
   on that cookie. No object-pointer, PID/FD or resolver history supplies a name.
8. The test peer reads the first ClientHello and independently checks its SNI.

The collected record contains cookie, observation time, TGID, FD and a bounded
hostname. Intermediate pointers stay inside the BPF program. Hostname validation
accepts conservative ASCII DNS names, folds case and removes one trailing dot;
it rejects empty labels, embedded NUL, IP addresses, invalid characters,
oversized labels, oversized names and unterminated/truncated observations.
International names must already be in ASCII form.

The OpenSSL layouts used by this profile are:

| Field | Offset |
| --- | ---: |
| SSL connection type | `0x0` |
| SSL connection write BIO | `0x58` |
| SSL connection server flag | `0x78` |
| SSL connection hostname pointer | `0xa20` |
| BIO method pointer | `0x8` |
| BIO initialized flag | `0x28` |
| BIO descriptor | `0x38` |
| Socket BIO method relative to libcrypto load base | `0x654620` |

These were checked against the verified binaries' `SSL_get_wbio()`,
`SSL_get_servername()`, `BIO_get_init()`, `BIO_s_socket()` and their OpenSSL source
implementations. The descriptor field is also checked against live `SSL_set_fd()`
and duplicated-descriptor cases. `SSL_connect()` reaches the probed
`SSL_do_handshake()` in this build.

## Results, 2026-10-16

All unprivileged tests and `go vet ./...` passed. The BPF and fixture compiled
with warnings treated as errors. The privileged suite passed on Linux 7.2.8
x86-64, with the exact libraries above:

- IPv4 and IPv6, hostname-before-FD and FD-before-hostname configuration.
- Ordinary and duplicated descriptors, with the handshake on a different thread
  from configuration.
- 24 simultaneously open connections, handshaken in reverse order with different
  hostnames, without incorrect assignments in this test.
- 64 descriptor-reuse cycles, also asserting actual SSL object address reuse.
  Each new socket is unknown before its own handshake observation.
- Transport replacement on an existing TLS object: only the new socket receives
  the name.
- Memory BIOs and a descriptor replaced with `/dev/null` produce no snapshot.
- Missing, malformed and maximum-buffer-length names are unusable.
- A fresh unnamed observation invalidates an earlier name on the same socket.
- A missed initial handshake observation leaves the name unknown while the TLS
  ClientHello still reaches the peer.
- The deliberately unsafe same-socket counterexample below is reproduced.

These are ClientHello/correlation tests. They do not complete TLS or validate
certificate/pinning behavior, ECH, encrypted DNS, routing, interception/NAT,
browser support, service privileges, SELinux isolation or performance. Root was
used for the VM harness; minimal observation privileges have not been established.

## Counterexample: abandoned setup and a missed observation

`TestVMMissedObservationCounterexample` performs this sequence:

1. Configure `abandoned.test` on a new TLS object and connected TCP socket.
2. Install a callback on its ordinary socket BIO that rejects writes before they
   reach the socket. Invoke the handshake. The uprobe publishes `abandoned.test`,
   but the test peer confirms that no bytes arrived.
3. Free that TLS object and replace it with a new object configured for
   `actual.test`, using the same live socket.
4. Detach the uprobe, preserving its map, to simulate a completely missed next
   observation. Invoke the new handshake.
5. The peer reads `actual.test` in the first ClientHello, while the private map
   still holds `abandoned.test` for the same socket cookie.

This test passes when it reproduces the unsafe state; it does not certify safe
routing. A real socket cookie eliminates attribution to another socket lifetime,
but cannot distinguish abandoned TLS setup attempts on the same socket. A TTL,
FD generation, one-shot lookup or successful hostname capture does not close
this gap. Fresh unnamed observations help only when that observation runs.

## Work required before routing integration

- Establish evidence tied to the actual sending TLS/transport operation that
  stays valid when an entire observation is missed or setup is abandoned.
  Consider an adapter at a verified write boundary, with kernel validation of
  the active operation; a probe moved closer to a write is not sufficient alone.
- Resolve descriptor lookup lifetime safety. `bpf_probe_read_kernel()` guarded
  traversal does not acquire a file reference. The current experiment assumes
  that the application does not concurrently close/replace its descriptor
  during the observation. The VM's sequential reuse tests do not prove that
  concurrent traversal safe.
- Prove application-socket to intercepted-flow identity, including translated
  source ports, full endpoints, network namespaces and flow lifetime. The
  application and proxy's accepted sockets have different cookies.
- Demonstrate publication before Mihomo's route commitment and bounded fallback
  for one explicitly supported inbound path.

Only after those requirements are met should a separately versioned optional
hostname interface, reader, routing precedence and independent observer service
be introduced. The existing owner ABI and loader do not incorporate this code.

## Source references

- [OpenSSL 3.5.3 SSL implementation](https://github.com/openssl/openssl/blob/openssl-3.5.3/ssl/ssl_lib.c)
- [OpenSSL 3.5.3 socket BIO](https://github.com/openssl/openssl/blob/openssl-3.5.3/crypto/bio/bss_sock.c)
- [Linux uprobe documentation](https://docs.kernel.org/trace/uprobetracer.html)
