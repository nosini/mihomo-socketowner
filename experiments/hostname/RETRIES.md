# Larger ClientHellos and immutable-window retries

The current [profile-3 contract](../../hostname/PROFILE3.md) replaces the
historical sole-write/4 KiB restriction with one immutable initial ClientHello
window of at most 16 KiB, including the record header. Subsequent supported
nonblocking writes must match the remaining original bytes on the same live SSL
connection and kernel socket. They cannot extend the window, change its name or
refresh its timestamp. Unsupported later attempts still exclude the socket
permanently; retained diagnostic records cannot override that exclusion.

## Verified live frames

The adapter still requires the exact library hashes in [OBSERVER.md](OBSERVER.md).
Both libc syscall paths and the existing socket-BIO frame checks are unchanged.
In addition to the earlier `buffer_ctrl` / `statem_flush` path, larger records
use `buffer_write`. Disassembly and controlled live traces establish these
return addresses, relative to the verified ELF load bases:

| Library | Return address | Role |
| --- | --- | --- |
| libcrypto | `0x174f2e` or `0x174fd7` | Direct buffer write or pending-buffer flush |
| libcrypto | `0x17aeeb`, `0x178ec0`, `0x1794e6` | Fixed intervening BIO frames |
| libssl | `0xc00b1` | Record flush |
| libssl | `0xb6d64` or `0xb6ba6` | Initial record creation or resumed pending record |

The fixed frame sizes lead to the record-flush frame's saved caller `rbx`,
holding the active `SSL_CONNECTION`. Every frame is checked; no stack scan or
cached setter observation supplies the pointer. The existing live BIO chain,
descriptor and SSL field checks then apply. Different builds need a separately
verified adapter, even if their OpenSSL version string is the same.

The initial capture checks TLS record and handshake lengths before copying the
whole attempted buffer and rechecks the copied header and TCP sequence. This
only limits scope to one complete plaintext ClientHello. Hostname evidence still
comes from the SSL object, without SNI parsing or decryption. A retry compares
the actual syscall buffer in bounded chunks with the original window at the
current TCP write sequence. Egress independently checks emitted bytes as before.

## Storage and failure behavior

Large socket-storage values failed allocation on the test kernel, correctly
poisoning publication. The byte windows therefore use a bounded preallocated
private hash; socket storage contains only small lifetime/control state. The
same callback leases protect both guard and window pointers until final release
and callback drain. Window insertion/deletion errors poison publication just as
guard errors do. No private capture map is transferred to a reader.

The ordinary embedded object contains no fault switches or retry counters.
A separately compiled test object counts initial, accepted-retry and rejected
attempts. Real `ENOENT` window insertion/deletion failures exercise fail-closed
behavior while ordinary networking continues.

## Validation

The race-built VM tests cover both IPv4 and IPv6:

- A ClientHello above the historical 4 KiB limit receives its live SSL name and
  reaches a TLS parser unchanged.
- Small send/receive buffers and MSS force `SSL_ERROR_WANT_WRITE`. Fourteen
  actual retry hooks per family pass exact remaining-window validation while
  preserving the original observation timestamp and bytes.
- Changed names, mutated pending bytes and a different TLS object sharing the
  socket revoke eligibility. An unchanged retained positive flow record remains
  unusable, and the private window remains byte-for-byte unchanged.
- Non-ClientHello initial data, oversized captures, existing multi-object and
  parallel-write cases stay unknown. Final-release callback-drain and private-map
  replacement/failure tests cover the expanded storage lifetime.
- Bootstrap rejects profile-1/profile-2 peers in both directions. Historical
  golden envelopes and the four public map layouts remain pinned by tests.

The [hardened-service harness](https://github.com/nosini/hardened-proxy-service/blob/ebpf-hostname-discovery/docs/hostname-development.md)
also completes large-window and real short-write TLS 1.2/1.3 exchanges through
the confined observer and Mihomo, preserving certificate/hostname/pin checks,
application bytes, selected route and original destination. Only its disposable
network namespace has reduced receive buffers; this is test forcing, not a
deployment setting.

This remains one exact OpenSSL adapter, one target and TCP direct/local REDIRECT.
Browser TLS stacks, ECH, TUN, broader reinjection, multiple initial records,
HelloRetryRequest, session resumption and production performance remain open.
