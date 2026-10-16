# Live TLS send correlation

The second experiment uses `lsm/socket_sendmsg` to read the active TLS connection
from verified live userspace call frames. The kernel supplies the actual socket
being used for this write. It does not use a cached SSL pointer, descriptor
binding or earlier hostname observation.

This removes the baseline's dependency on observing handshake entry: the entire
send suite runs with that uprobe detached. The abandoned-setup counterexample
now produces no send record for the abandoned attempt and the correct hostname
for the replacement's first ClientHello. The original unsafe experiment and test
remain available as a comparison.

This is still a diagnostic prototype. A [publication guard](PUBLICATION.md) now
rejects records after failed map writes or scope-storage creation. A separate
[send-order guard](SEND_ORDER.md) now excludes every socket after its second
send attempt, addressing a reproduced corked-write counterexample. A bounded
[packet comparison](PACKET.md) now ties eligible payloads to captured write bytes
and TCP sequence positions. [Lifetime checks](LIFETIME.md) now retire closed
sockets and revoke detached/replaced in-process observer sessions. Routing timing
and independent-service operation still need proof. No Mihomo routing or service
integration is enabled.

## Running

Use the environment and exact OpenSSL binaries in [README.md](README.md).
This experiment also requires an active BPF LSM and this exact x86-64 libc:

| File | SHA256 |
| --- | --- |
| `/usr/lib64/libc.so.6` | `090f858814642a3f28e5f4ae6499667e7901e47902ca3e72fb9c8a1967a3b8df` |

The binary hashes and the selected process's actual library mappings are checked
before attachment. The decoded frame slots were checked against these binaries'
disassembly, their `.eh_frame` unwind rules, and live single-threaded and
multithreaded `write` syscall stops. Unknown call sites or incomplete chains
produce unknown metadata.

From the socketowner repository root, after building the baseline fixture,
object and test executable as described in README.md:

```sh
clang -O2 -g -Wall -Werror -mcpu=v3 -D__TARGET_ARCH_x86 -target bpfel \
    -c experiments/hostname/bpf/send.c \
    -o experiments/hostname/build/send.o
sudo env HOSTNAME_VM_OBJECT="$PWD/experiments/hostname/build/snapshot.o" \
    HOSTNAME_VM_SEND_OBJECT="$PWD/experiments/hostname/build/send.o" \
    HOSTNAME_VM_CLIENT="$PWD/experiments/hostname/build/client" \
    unshare --net sh -c 'ip link set lo up; exec experiments/hostname/build/hostname.test -test.v -test.timeout 120s'
```

`send.c` includes the baseline object for side-by-side comparison. The harness
attaches the additional LSM and cgroup egress programs only for the send tests.
The LSM link is global, but its first check requires socket-local storage created
only for the selected fixture's TCP sockets in its private cgroup. Another
process sending on one of those sockets invalidates its previous name.

All maps remain unpinned, and the tests remove their private cgroups and network
namespaces. Redirect tests use nftables only inside those namespaces.

## Live association

The hook first obtains the socket cookie from the kernel's held socket and then
checks the current task's original syscall number and user instruction pointer.
It supports these exact libc `write(2)` paths:

- The noncancellable path at libc-relative IP `0x9ab8a`.
- The cancellable path at libc-relative IP `0xa7992`.

It then reads only known saved return-address/register slots. Each return address
must match the corresponding relocated code address; it does not scan stack
memory for possible SSL pointers. The required chain, starting above libc, is:

| Active frame | Return PC relative to its library | Unwind rule at that PC |
| --- | ---: | --- |
| socket BIO `sock_write` | libcrypto `0x188a18` | CFA = rbp + 16; rbp = current frame SP + `0x90` |
| legacy BIO write adapter | libcrypto `0x17aeeb` | CFA = rsp + 16 |
| internal BIO write | libcrypto `0x178ec0` | CFA = rsp + 64; saved caller rbp at CFA − 32 |
| `BIO_write` | libcrypto `0x1794e6` | CFA = rsp + 32 |
| buffering BIO control | libcrypto `0x174adf` | CFA = restored rbp + 16; bounded to this frame |
| `BIO_ctrl` | libcrypto `0x17a091` | CFA = rsp + 48; saved caller rbx at CFA − 40 |
| TLS `statem_flush` | libssl `0xd6911` | Active SSL connection is in caller rbx |

At that last call site, `statem_flush` keeps its current `SSL_CONNECTION` in rbx.
The socket BIO in the live syscall's rbx is also validated. The active SSL object's
write BIO must be its actual buffering BIO, with the verified buffer method and
a next pointer to this raw socket BIO. The raw BIO must have the verified socket
method, be initialized, and hold the same descriptor as the actual `write`
syscall. The additional profile offsets are:

| Field | Offset |
| --- | ---: |
| SSL connection buffering BIO | `0x60` |
| BIO next pointer | `0x48` |
| Buffer method relative to libcrypto base | `0x653da0` |

The kernel has already resolved the syscall's descriptor and holds the actual
socket used for that operation. The send path does **not** walk the descriptor
table or dereference a file obtained from it. Replacing a descriptor slot after
kernel lookup cannot redirect this hook's socket pointer to a different file.
This addresses the raw descriptor-traversal lifetime problem of the baseline.
It does not make concurrent mutation of an SSL object's userspace fields safe.

Only after all checks does the hook read the current bounded hostname. Unknown
paths on a tracked socket publish an invalid observation rather than retaining
the last usable name. Neither an allocation event nor a setter/destroy event is
needed for these associations.

`observation.Pad` is private diagnostic status: 0 means a captured name, 1 means
unsupported process/syscall/frame chain, 2 means invalid TLS/BIO relationship,
4 means no usable string, and 6 means unusable first-write capture. Syntax
validation remains in the
test reader. There is no public ABI or promise to preserve these values.

## Mapping to an intercepted flow

The cgroup egress program separately publishes a private mapping from network
namespace cookie and the packet's full source/destination endpoints to the
application socket cookie and its sole send observation, when eligible under
the send-order guard and exact byte/sequence comparison. It reads both ports
from the packet after redirection, including a translated source port. The
proxy's accepted socket has a different cookie; it is never compared for equality
with the application cookie.

The SYN publishes its cookie even when no hostname exists. Tests first confirm
that the accepted flow is unknown, then invoke TLS and confirm the hostname is
available when the peer receives its first ClientHello. The redirect collision
tests bind two application sockets to the same loopback source address/port and
different destinations, forcing Netfilter to change one source port. They also
verify that `SO_ORIGINAL_DST` still returns each application-selected destination.

This bridge supports the ordinary local TCP packets exercised by these tests.
IPv6 extension headers and fragmented IPv4 packets are excluded. It is not an
interception-mode compatibility claim beyond the tested direct/REDIRECT paths.

## Validation, 2026-10-16

The combined VM suite and local unit/vet checks pass. The send tests cover:

- IPv4/IPv6; both hostname/FD setter orders; direct, cross-thread and implicit
  `SSL_write_ex` handshakes; both libc syscall paths.
- 24 open TLS connections with reverse-order cross-thread handshakes and
  duplicated descriptors, followed by 64 socket/object reuse cycles.
- Abandoned setup followed by object replacement on the same live socket, with
  the handshake uprobe disabled throughout.
- Two simultaneously live TLS objects on duplicated descriptors for one socket:
  the name comes from the object actually sending.
- An unsupported raw send, including from a forked child, invalidating earlier
  socket and flow evidence while allowing networking to proceed.
- Memory BIOs and missing/malformed names producing no usable hostname.
- Full flow lookup before/after TLS and forced REDIRECT source-port collisions
  for both IP families, with original destinations preserved.
- Guarded publication, failed insertions/invalidation, scope-storage failure,
  active writers and counter exhaustion; see [PUBLICATION.md](PUBLICATION.md)
  for the protocol, fault-build command and limits.
- Corked and parallel same-socket writes, permanent exclusion after a second
  attempt, retained old flow records, record eviction and guard-map exhaustion;
  see [SEND_ORDER.md](SEND_ORDER.md).
- First-write payload comparison, unknown ACKs during corking, automatic TCP
  retransmission, modified bytes and oversized ClientHellos; see [PACKET.md](PACKET.md)
  for the 4 KiB limit and synthetic parser/window tests.
- Final close, peer FIN/RST, tuple reuse with retained records, link/map
  replacement and checked in-process stop/restart; see [LIFETIME.md](LIFETIME.md).
- Real Mihomo REDIRECT routing deadlines, bounded lookup/failure, fixed routes
  after late evidence, and destination preservation; see [ROUTING.md](ROUTING.md).

The TLS peer stops after reading ClientHello. Completed TLS, ECH, real encrypted
DNS, browser builds, Flatpak, TUN, TPROXY, explicit proxies, performance, minimal
capabilities and service confinement remain unverified.

## Remaining correctness work

1. **Broader send coverage.** The first bounded write now has an exact emitted
   byte/sequence comparison, including tested deferred output and retransmission.
   Multiple attempts remain excluded. Supporting them needs attribution across
   retries and corked/coalesced writes. Reinjection and other kernel send paths
   still need explicit scope and tests.
2. **Independent observer operation.** Socket retirement, tuple reuse and
   in-process link/map identity checks are tested. An external reader still
   needs an explicit authority/reconnect contract, independent observer-crash
   tests, least-privilege separation and a versioned optional ABI.
3. **Production routing metadata.** The supervised [REDIRECT test](ROUTING.md)
   now proves bounded lookup and destination preservation at the real Mihomo
   tunnel. Explicit provenance, source precedence, Fake-IP/sniffer interactions
   and a safe external reader still need design and validation.

The live-frame mechanism solves the reproduced stale handshake-cache case for
the tested path. It is a foundation for milestone 1, not completion of it.
