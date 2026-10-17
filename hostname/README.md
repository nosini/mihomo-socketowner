# Optional hostname reader

This Go module reads application hostname evidence from a separately installed
`mihomo-hostname-observer`. It implements [hostname contract v1](CONTRACT.md),
layout profile 1. It has no dependency on socketowner's loader or experiment Go
packages, and does not install or start either privileged executable.

The feature remains experimental: one exact OpenSSL build, one target process,
TCP, a sole first send of at most 4096 bytes, and 256 socket guards per observer
instance. It does not provide ECH inner names or browser support. Observer service
confinement and broader transport coverage remain separate work.

## Using the reader

The module path is `github.com/nosini/socketowner/hostname`. Go 1.25 or newer is
required; Linux amd64 is the only supported runtime. Other platforms compile an
unavailable implementation. Use an explicit released module version in your
application; there is no published release from this checkpoint yet.

```go
reader, err := hostname.DialReaderContext(ctx, endpoint, deadline)
if err != nil {
    // Use ordinary routing.
    return
}
defer reader.Close()

candidate, err := reader.Lookup(flow, deadline)
if err != nil {
    return // ordinary routing, or poll within the same absolute deadline
}
route := matchRules(candidate.Name()) // tentative; preserve the real destination
if err := candidate.Validate(); err != nil {
    return // restore ordinary metadata and evaluate ordinary rules again
}
commitRoute(route) // validation is the commitment point
```

`TCPFlow` contains the accepted TCP socket's namespace cookie and both complete
post-NAT endpoints. The observer's application socket cookie is different from
the proxy socket cookie. The caller must obtain this flow from the accepted
connection, rather than guess it from process IDs, DNS answers or a source-only
owner-map key. Scoped IPv6, mixed address families and invalid endpoints fail.
IPv4-mapped addresses are normalized.

`DialReaderContext` uses the earlier of context cancellation and the absolute
bootstrap deadline. Its context applies to bootstrap only; after success,
`Close` owns the session lifetime. Each `Lookup` is a single guarded read and
returns an immutable tentative candidate. Its absolute deadline also bounds
`Validate`. The library does not poll, reconnect, cache positive grants or adopt
another observer instance. Methods are safe to call concurrently, including
idempotent `Close`; closing invalidates all candidates. `Name` remains tentative
text after invalidation and never substitutes for `Validate`.

Any error requires fallback. Error text is diagnostic, not a protocol or API
classification. `ErrUnavailable` identifies revoked or unsupported sessions;
other errors may identify missing records, busy publication, expiry or invalid
inputs. A successful validation is a commitment point, not an atomic lease
through network dial or TLS. The caller owns its configuration cancellation,
routing deadline, concurrency bound and prompt descriptor cleanup.

The reader authenticates root with `SO_PEERCRED` and obtains `SO_PEERPIDFD`
directly. It receives four frozen read-only map descriptors, verifies their
identities/layouts and repeatedly checks the peer pidfd, authority gate,
publication generation and permanent socket guard. It never opens pins or
application `/proc` files, and never loads or attaches BPF. Access to its own
`/proc/self/fdinfo` is needed for frozen-state validation. Missing kernel
features return unknown. The trusted publisher's obligations are part of the
[contract](CONTRACT.md); this is not authentication against a
malicious root publisher.

For builds, tests and independent release tags, see [development](DEVELOPMENT.md).

## License

[GNU GPL v3](LICENSE).
