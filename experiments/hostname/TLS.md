# Completed TLS through the optional service

The controlled OpenSSL fixture supports certificate and hostname verification,
a SHA-256 peer-certificate pin, and a bounded application request/response.
The disposable hardened-service harness runs it through the actual static
optional-reader Mihomo binary, authenticated observer and shipped service policy.
See [service test instructions](https://github.com/nosini/hardened-proxy-service/blob/ebpf-hostname-discovery/docs/hostname-development.md).

For both IPv4 and IPv6, the matrix fixes TLS 1.2 or TLS 1.3 and checks:

- The DOMAIN rule selects NAMED before the handshake completes, while the
  outbound destination remains the original IP/port and the server receives
  the original `route.invalid` SNI.
- The client verifies the fixture certificate using its own test trust store,
  verifies the hostname, checks the exact certificate pin and exchanges known
  application bytes in both directions.
- An unrelated trust root fails with OpenSSL verification error 18; a wrong
  expected hostname fails with error 62. A wrong certificate pin is rejected
  after the handshake, before application data. All three cases deliver no
  application request to the server.
- Stopping the observer or disabling hostname discovery uses ordinary DIRECT
  routing and still completes both TLS versions and the application exchange.
- TLS 1.3 also completes after graceful observer restart and automatic recovery
  from SIGKILL, using fresh observer instances.
- Later TLS writes leave the committed connection on its original chain. The
  first-send authority can be revoked without interrupting an established relay.

The [profile-3 extension](RETRIES.md) adds, for both TLS versions, a
ClientHello larger than the historical 4 KiB limit and an exchange whose
ClientHello needs real nonblocking retries. Each default TUN IP-family run has
fifty-four TLS connections: forty-three successful application exchanges and
eleven deliberate certificate/hostname/pin rejections, including the TUN,
resumption, key-share HRR and HTTP/2 cases below. It also reruns the service confinement,
missing/stale registration, kill-switch, restart, disable/re-enable and
target-exit checks with SELinux enforcing.

The service harness's `--auto-redirect` mode runs the remote-server and
resumption groups through the actual local nftables redirect listener, which
supplies REDIR metadata. Eight additional cases check certificate, hostname and
pin behavior for both TLS versions there: sixty-two TLS test connections
per family (forty-five successful application connections, seventeen deliberate
rejections). A separate two-ClientHello collision group checks different
names/destinations at one requested source port and real NAT source-port remapping.
The original loopback REDIRECT groups remain in this matrix. See [TUN and
auto-redirect coverage](TUN.md) for the interception scope.

## TUN session resumption and SSL reuse

The confined system-stack TUN matrix adds eleven connections for each TLS
version and IP family. The server keeps one context and its ticket keys across
connections. Both `SSL_session_reused` on the client and `session_reused` on the
server must agree; offering a saved session alone does not count as resumption.

| Case, for each TLS version | Expected handshake and route |
| --- | --- |
| Verified seed | Full handshake, NAMED |
| Saved session on a new SSL object | Resumed, NAMED |
| Two successive `SSL_clear` resets onto new TCP sockets | Resumed, NAMED; one connection exchanges three requests |
| Reset with `reuse.invalid` and no saved session | Full handshake, RENAMED |
| Reset with the name removed | Full handshake, ordinary DIRECT |
| Reset back to `route.invalid` | Full handshake, NAMED |
| Offer a ticket to a new server context | Ticket declined, full handshake, NAMED |
| Resume with the observer stopped | Resumed, ordinary DIRECT |
| Resume after a fresh observer restart | Resumed, NAMED |
| Resume with a deliberately wrong certificate pin | Resumed, NAMED, no application request |

Every socket has a fresh kernel cookie. Reset cases keep the same SSL object
without freeing or reallocating it, replace its socket BIO, and explicitly clear
its old session and name. The test checks the original destination and incoming
SNI before application traffic, then verifies that the connection ID and chain
stay fixed through each request/response. The no-name case cannot inherit a
previous positive name. The second fixture hostname has its own domain rule,
so a stale name would select the wrong chain.

Sessions originate from a certificate/hostname-verified seed; the client
checks the cached peer certificate's pin on each resumed connection. It uses
no early data. Sessions and tickets stay in the fixture process's memory.
Clean bidirectional TLS shutdown precedes saving or resetting a session:
OpenSSL can invalidate a session after an unclean close, and TLS 1.3 tickets
arrive after the initial handshake. See the upstream documentation for
[session retrieval](https://docs.openssl.org/3.5/man3/SSL_get_session/),
[SSL reset](https://docs.openssl.org/3.5/man3/SSL_clear/) and
[shutdown](https://docs.openssl.org/3.5/man3/SSL_shutdown/).

## Fixture commands

The existing single-step commands retain their old behavior. After `open`, use:

```text
verify SLOT CA_FILE EXPECTED_HOSTNAME SHA256_CERTIFICATE_HEX 12|13
handshake SLOT
exchange SLOT
close SLOT
```

`verify` gives that SSL object its own trust store and fixes the TLS version.
`handshake` emits ClientHello using the original single-call path, letting the
harness inspect the committed route before the peer replies. `exchange` has one
five-second deadline for handshake completion, pin verification, request and
response. Its nonblocking retries do not extend the deadline. The server stays
open until the harness confirms that the connection ID and chain are unchanged.

Additional completed-TLS commands are:

```text
session-state SLOT
shutdown SLOT
save-session SLOT
resume SLOT
reopen SLOT NAME|-
```

`session-state` reports only reused/resumable flags. `save-session` retains one
reference to a resumable session; `resume` explicitly attaches it to an SSL
object before ClientHello. `shutdown` completes the TLS close-notify exchange
within a separate five-second deadline and half-closes TCP. `reopen` requires
that clean shutdown, calls `SSL_clear`, clears the previous session and name,
and binds the same SSL object to a new TCP socket. It does not imply resumption;
use `resume` separately. All older commands keep their original behavior.

The shutdown fixture retries a zero `SSL_shutdown` result immediately within
its deadline. Only a negative WANT_READ/WANT_WRITE result waits on socket
readiness; zero is progress and can precede consumption of a buffered peer
alert. `testdata/shutdown_test.c` is a deterministic API-contract regression for
that distinction and both I/O directions. It fails with the earlier loop.
Compile it from this experiment directory, placing output in a task build folder:

```sh
gcc -O2 -g -Wall -Wextra -Werror testdata/shutdown_test.c \
  -o /path/to/build/hostname-shutdown.test \
  -Wl,--wrap=SSL_shutdown,--wrap=SSL_get_error,--wrap=poll,--wrap=shutdown \
  -lssl -lcrypto -pthread
/path/to/build/hostname-shutdown.test
```

This regression simulates only the shutdown API contract; the service matrices
exercise actual TLS shutdown and resumption over the network.

The confined IPv4/IPv6 TUN and local auto-redirect matrices also force TLS 1.3
HelloRetryRequest with a P-256-only server and a client initially sharing
X25519. The fixture's `groups` command selects the client group order and
installs a protocol-message counter; `hello-state` reports sent ClientHellos
and received HRRs, without retaining message contents or secrets. The server
must see the unchanged SNI twice. A reversed-preference control sends one
ClientHello and receives no HRR; forced retries require two and one. Both
complete verified TLS and repeated application exchanges on the initially
selected connection/chain. Cases include observer stop after route selection,
ordinary fallback on a new socket, and wrong-pin rejection without application
data. No second initial window or new attribution is authorized by HRR.

References: OpenSSL [group selection](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/),
[message callback](https://docs.openssl.org/3.5/man3/SSL_CTX_set_msg_callback/), and
[RFC 8446 HRR encoding](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3).

Controlled HTTP/2 multiplexing and reuse also pass over TLS 1.2/1.3 through
both confined interception modes and address families. The fixture offers only
`h2` ALPN and exposes bounded `tls-send`/`tls-recv` byte transport after
`tls-ready` verifies the peer certificate, hostname, pin and negotiated ALPN.
The harness's packaged hyper-h2 library supplies HTTP/2/HPACK state machines at
both peers; no new Go dependency or TLS adapter is needed. The original
`exchange` command retains its combined five-second handshake/application budget.

Each version proves two simultaneously open streams, interleaved request DATA
and out-of-order/interleaved responses with correct status/bodies. Named and
ordinary-fallback connections retain their original ID/chain/destination through
observer stop/restart and later streams; a fresh connection with a changed SNI
selects RENAMED. Wrong pins send no HTTP/2 preface or request. This covers
same-origin reuse on the controlled socket-BIO fixture, not browser coalescing
across origins or general HTTP/2 conformance.

The harness creates ephemeral test certificates in its run directory. Trust is
never added to the system store. Only the client and fixture server handle TLS
keys or application bytes; the observer and reader gain no such access.

This proves completed TLS for the exact supported OpenSSL profile and controlled
TCP REDIRECT and system-stack TUN paths. Resumption is tested with TLS tickets
and the controlled OpenSSL socket-BIO fixture. It does not establish browser
compatibility, encrypted DNS, ECH, early data, cookie-only HRR or
cross-origin reuse, other send shapes, TPROXY, throughput or a
production latency budget. The observer admits only one initial ClientHello
window and verified retries of its remaining bytes, as defined by
[profile 3](../../hostname/PROFILE3.md); unsupported later sends revoke
discovery authority. Later application writes on an already committed
connection are relayed normally. The service test needs no Mihomo behavior
changes beyond the optional reader.
