# Authenticated reader at route commitment

The `hostname_reader_vm` companion now runs the experimental reader directly
inside capability-free Mihomo. It authenticates the observer through the Unix
socket [bootstrap](BOOTSTRAP.md), receives frozen read-only maps and binds to the
kernel peer pidfd. Only the test control socket is inherited. No hostname, map
descriptor or pidfd is supplied to Mihomo by the supervisor.

This connects the existing [authority](AUTHORITY.md) and [routing](ROUTING.md)
experiments. The consumer now imports the independent
[`hostname` reader module](../../hostname/README.md), implementing the optional v1
contract. The old experimental facade remains for historical tests. No observer
service is installed.
Ordinary Mihomo builds have no socketowner dependency or enabled backend.
The [native lookup follow-up](NATIVE.md) adds independent configuration and a
bounded tunnel hook behind an explicit experimental backend build tag.

## Candidate and final read

`Reader.Lookup` takes the full post-NAT TCP source/destination endpoints and
network namespace, with one absolute deadline. It performs the existing guarded
read, rejects empty or malformed names and inconsistent application cookies,
and returns an opaque candidate bound to that exact reader, flow and record.
The facade supplies only ordinary TLS-name provenance. It cannot claim ECH-inner
support for the current OpenSSL profile.

The tentative name is passed to Mihomo with a required validation callback.
Mihomo performs preprocessing, sniffing and rule matching on tentative metadata.
**After matching and before the main outbound dial**, confirmation rereads the
same flow through the same reader. The check includes current peer liveness,
the irreversible authority gate, frozen map identities, publication stability,
the socket send/lifetime guard, an unchanged socket cookie and observation and
the original deadline. Profile 3 no longer requires the per-packet fields to
match, because later segments of the same window rewrite them.
A reconnect cannot change a candidate's reader or replace it with a new instance.
There is no positive authority lease or cached health check.

The successful final read is the route's commitment point. Process death or
record changes after that point do not move the connection to another outbound.
This is a checked instant, not an atomic transaction spanning later kernel
events and the outbound network handshake.

If the candidate becomes unusable, expires, fails confirmation, or route
evaluation returns an error, Mihomo restores a snapshot captured before
application-dependent processing and
selects once without application evidence. That reruns ordinary DNS/Fake-IP,
hosts and sniffer policy; it does not merely clear the routing name after those
policies have already been suppressed. It performs no new hostname lookup and
cannot heal the failed candidate. Main outbound dialing starts only after this
choice. An unchanged name also cannot replace its original validation callback.

The fallback may repeat ordinary preprocessing/sniffing once. Existing sniffer
read deadlines apply to each attempt; this is not a new production latency
policy or a performance claim. The background peek runs only for the final
attempt, so it cannot overlap rollback sniffing. Without application evidence,
the existing preparation/peek/rule order is preserved.

## VM checks

The reader matrix has 36 cases: IPv4/IPv6 and process lookup off/always, each
with healthy authority, observer crash, revocation, a second send, flow eviction,
expiry, reader closure, observer restart or crash after commitment.

A test-only barrier pauses after the ordinary DOMAIN matcher has consumed the
candidate but before confirmation. The supervisor changes authority or flow
state there. Every failed confirmation must choose the fallback, dial the
original IP/port exactly once and relay the original ClientHello. Healthy
authority selects the named route; a post-commit crash leaves that route fixed.
The supervisor supplies no positive names. Mihomo asserts UID 1000, zero
effective capabilities and no-new-privileges before bootstrapping.

The ordinary cases use one absolute 1 s experiment budget so a deliberate
restart can finish before expiry. The expiry case uses 250 ms and deliberately
crosses it. Other cases assert that dialing starts before their deadline, so
expiry cannot mask the authority/correlation rejection being tested. Neither
budget is a proposed production setting. The earlier 32-case supervised routing
matrix still uses its 250 ms budget, including its final validation exchange.

Local race tests cover post-match revocation and metadata mutation, removal of
tentative effects, restoration of hosts policy, required validation callbacks,
copied-name invalidation and the existing metadata/Fake-IP/sniffer checks.
The peer still stops after ClientHello. Completed TLS, browser encrypted DNS,
ECH, broader sends and reinjection remain outside these results.

## Building the companion

The extra test file imports the independent reader module only under
`hostname_vm && hostname_reader_vm`. Build it in a temporary Go workspace that
contains Mihomo, socketowner and socketowner/hostname. This avoids committing
an unpublished cross-repository dependency or a machine-specific `replace` directive. From the parent workspace,
with `route_build` set to an existing absolute task build directory:

```sh
workspace="$PWD"
(cd "$route_build" && go work init "$workspace/mihomo" "$workspace/socketowner" "$workspace/socketowner/hostname")
(cd mihomo && GOWORK="$route_build/go.work" go test -c -race \
  -tags 'hostname_vm hostname_reader_vm' \
  -o "$route_build/mihomo-reader.test" ./tunnel)
(cd socketowner && GOWORK="$route_build/go.work" go test -c -race -tags hostname_vm \
  -o "$route_build/hostname.test" ./experiments/hostname)
```

Transfer the binaries and existing C/BPF artifacts to the isolated VM. Use the
private mount/network namespace and bpffs setup in [AUTHORITY.md](AUTHORITY.md).
Set `HOSTNAME_VM_READER_MIHOMO` to the reader helper's absolute VM path and run
`TestVMHostnameReaderCommit`. Also set `HOSTNAME_VM_MIHOMO` to the same binary
and select `TestVMHostnameRoutingDeadline` to include the earlier matrix.
Neither test deploys a service or modifies existing owner pins.

## Remaining integration

The separately versioned [reader module and contract](../../hostname/README.md)
now package this consumer. The resident observer command also exists. Production
work still needs service confinement and restart policy. The
native follow-up supplies independent configuration and a bounded inbound lookup.
The existing process owner map/loader and
kill-switch are unchanged. Guard reclamation, broader sends and transport/runtime
coverage remain separate work.
