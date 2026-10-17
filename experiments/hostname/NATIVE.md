# Native lookup and configuration follow-up

The companion Mihomo native entry point is commit `f7d34d88` on its
`ebpf-hostname-discovery` branch.

Mihomo's [native hostname lookup](../../../mihomo/docs/hostname-discovery.md)
now owns the pre-routing wait and reader lifetime. Its independent
`hostname-discovery` setting is disabled by default. Enabling requires an
explicit 1–250 ms budget and a canonical absolute endpoint. Ordinary builds
reject enablement; the diagnostic adapter requires Linux amd64 and
`hostname_discovery_experimental` in a temporary two-module Go workspace.
The [resident observer command](OBSERVER.md) serves that endpoint; there is
no installed observer service or stable public map interface yet.

Each eligible TCP REDIRECT attempt opens one authenticated reader and uses one
absolute deadline for bootstrap, polling and post-match validation. It cannot
reconnect into another instance while waiting. At most 64 attempts hold reader
resources; overload, missing endpoints and failed bootstrap return unknown.
Readers close on failure, expiry, configuration replacement/disable and final
route selection. No BPF-map or pidfd descriptors remain for the relay.

Committed reloads replace the configuration token, invalidate pending candidates
and cancel bootstrap/polling. Parsing a proposed configuration is side-effect
free for this setting, despite the existing parser's temporary general-settings
application. Already committed routes remain fixed. No process lookup setting
or privileged owner-map ABI was changed.

The bootstrap facade adds `DialReaderContext`: cancellation interrupts the
socket reply wait and closes any temporary descriptors through the existing
strict ancillary-data cleanup. The original deadline API remains available for
the earlier tests.

## Validation

The native matrix adds 32 IPv4/IPv6 and process off/always cases: healthy data,
an initial miss followed by data, late data, absent observer, stalled bootstrap,
post-match disable, identical reload and observer crash. It parses actual YAML
and uses the ordinary tunnel hook. Its wrapper supplies only synchronization;
it neither supplies names nor performs lookup/waiting. Each case checks the
outbound, original IP/port, ClientHello relay, single route commitment and zero
BPF-map/pidfd descriptors at dial.

The earlier 68 routing cases remain regression coverage. Both Go binaries use
the race detector. A separate VM check authenticates a root publisher, waits
until it has received the request, then cancels the reader while that publisher
withholds a reply; the pending bootstrap returns and closes the connection.
Local tests cover configuration independence and validation, cancellation,
deadline handling, capacity, exactly-once cleanup, wrapper traversal and parsing
without revoking already active evidence.

## Running

Use the existing [consumption build](CONSUMPTION.md) and add
`hostname_discovery_experimental` to the Mihomo test build tags. Build both
binaries with `-race`. In the isolated VM mount/network namespace with private
bpffs and the existing C/BPF objects, set `HOSTNAME_VM_NATIVE_MIHOMO` to the
helper's absolute path and select `TestVMHostnameNativeLookup`. Add
`TestVMBootstrapContextCancellation` for the cancellation case. Also set
`HOSTNAME_VM_MIHOMO` and `HOSTNAME_VM_READER_MIHOMO` to include the earlier
`TestVMHostnameRoutingDeadline` and `TestVMHostnameReaderCommit` matrices.

No existing service, firewall namespace or owner pin is modified. The C/BPF
profile, first-send and fixed-guard restrictions are unchanged. Full TLS,
throughput/latency under load, broader send/reinjection behavior and browser
encrypted-DNS/ECH coverage remain open. The [observer command](OBSERVER.md)
now exists; its service unit, confinement and restart policy are the next
integration work.
