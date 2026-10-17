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

Each IP-family run has fourteen TLS cases: eight successful application
exchanges and six deliberate certificate/hostname/pin rejections. It also reruns
the service confinement, missing/stale registration, kill-switch, restart,
disable/re-enable and target-exit checks with SELinux enforcing.

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

The harness creates ephemeral test certificates in its run directory. Trust is
never added to the system store. Only the client and fixture server handle TLS
keys or application bytes; the observer and reader gain no such access.

This proves completed TLS for the exact supported OpenSSL profile and controlled
TCP REDIRECT path. It does not establish browser compatibility, encrypted DNS,
ECH, resumption, HTTP workloads, other send shapes, TUN/TPROXY, throughput or a
production latency budget. The observer still admits only the sole first write
of at most 4096 bytes; later sends revoke discovery authority. No production
BPF program, reader contract or Mihomo behavior changes are needed for this test.
