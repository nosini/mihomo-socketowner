# Mihomo routing deadline experiment

This opt-in VM experiment runs the verified OpenSSL client through Mihomo's real
Linux REDIRECT listener, TCP tunnel, DOMAIN rule matcher, DIRECT adapter and TCP
relay. It tests when the outbound is chosen relative to the first ClientHello.
There is no production hostname reader, configuration option or public map ABI.

## Deadline and destination

Without sniffing, Mihomo can select an outbound immediately after accept. The
background 200 ms `Peek(1)` in `handleTCPConn` does not delay `resolveMetadata`.
The unmodified path therefore chooses its fallback while this test deliberately
holds back the ClientHello. A later positive map record cannot change that route.

A test-only `C.Tunnel` wrapper tries a bounded lookup before entering that same
tunnel. Each request uses the accepted socket's namespace and full post-NAT
source/destination tuple. The parent harness applies the existing session,
publication and lifetime checks to `send_flows`; errors return unknown. It also
verifies the resulting application cookie and TGID against the controlled client.
The accepted proxy cookie must differ from the application cookie.

The wrapper uses one absolute 250 ms experiment budget for all requests,
including IPC reads/writes. A missing reply, late reply or unknown result cannot
extend that budget. A successful name ends the wait early. The budget starts
after a test synchronization barrier at accept; the barrier and diagnostic event
reporting are outside it. This is a correctness test setting, not a proposed
production timeout or latency measurement. Process lookup and ordinary tunnel
work can add time after the hostname wait ends.

Evidence stays in a test-only field. A rule wrapper supplies it on a metadata
clone to the ordinary DOMAIN rule for `route.invalid`, selecting an outbound
named `NAMED`; fallback selects `DIRECT`. Both outbounds use the real DIRECT
adapter. Neither `Host` nor `SniffHost` on the original metadata is changed.
The test checks the dial address against the application's original IP and port,
then verifies the intended ClientHello arrives there through Mihomo's TCP relay.
It does not resolve or dial `route.invalid`.

## Private supervision

The companion Mihomo test is `tunnel/hostname_vm_test.go`, introduced in commit
`b5d86d48` on its `ebpf-hostname-discovery` branch. It is built only with
`hostname_vm` and skips
unless explicitly launched as a helper. The socketowner test passes an inherited
Unix socket, receives tuple/route events and answers lookup requests. The parent
retains every BPF map/link FD. There are no public sockets, pins, transferred BPF
handles or independently reusable reader credentials.

The redirect rule matches only the client's private cgroup. Mihomo's outgoing
sockets are outside it. This matters even on loopback: Mihomo's dialer deliberately
skips routing marks for addresses that are not global unicast, so a routing-mark
exclusion alone would reinject the proxy's loopback connection. This test does
not establish support for arbitrary interception or reinjection policies.

This IPC is an experiment seam, not a service contract. A copied name is consumed
once under controlled supervision; reader authority, observer crash/reconnect,
revocation across processes and least-privilege service operation remain open.
Do not turn this bridge into a production consumer of the diagnostic maps.

## Validation, 2026-10-16

The full socketowner VM suite passes with the companion Mihomo helper. All 24
routing cases also pass with both Go binaries built under the race detector.
Local unit checks and VM-tagged vet pass in both affected packages.

The matrix covers IPv4/IPv6 with process lookup both `off` and `always`:

- Current path: the outbound is chosen before any ClientHello is sent, with no
  lookup wait; subsequently available evidence does not cause a second dial.
- Before deadline: an initial miss precedes the sending operation; a subsequent
  verified flow lookup selects the named outbound before dialing.
- Late ClientHello: the bounded wait expires, fallback dials, then the client
  sends and publishes a positive record; the existing route remains fixed.
- Observer stopped: lookup remains unknown and ClientHello still reaches its
  original destination through fallback.
- Stalled lookup: an unanswered IPC request times out within the same budget;
  fallback still forwards the subsequently sent ClientHello.
- Late reply: a real positive BPF result is deliberately delivered after the
  deadline; it cannot change the fallback route.

Each case checks the real outbound dial and relay, the original IP/port, and a
single route commitment. IPv6 is explicitly enabled in the helper, since Mihomo's
resolver defaults to disabling it. Sniffing remains off for this matrix.
The peer stops after ClientHello; full TLS, certificate validation, encrypted DNS,
ECH, Fake-IP/sniffer precedence and browser workloads are not demonstrated.

## Running

Use the exact library/kernel profile and build the BPF objects/client described
in [SEND.md](SEND.md) and [PUBLICATION.md](PUBLICATION.md). Build these test
binaries from the two companion checkouts, then transfer them alongside those
artifacts into the isolated test VM:

```sh
# From the Mihomo checkout; route_build is an existing task build directory.
go test -c -tags hostname_vm -o "$route_build/mihomo-route.test" ./tunnel

# From the socketowner checkout.
go test -c -tags hostname_vm -o "$route_build/hostname.test" ./experiments/hostname
```

In the VM task directory containing the transferred binaries and built objects:

```sh
sudo env HOSTNAME_VM_OBJECT="$PWD/snapshot.o" \
  HOSTNAME_VM_SEND_OBJECT="$PWD/send.o" \
  HOSTNAME_VM_FAULT_OBJECT="$PWD/send-fault.o" \
  HOSTNAME_VM_CLIENT="$PWD/client" \
  HOSTNAME_VM_MIHOMO="$PWD/mihomo-route.test" \
  unshare --net sh -c 'ip link set lo up; exec ./hostname.test \
    -test.v -test.run TestVMHostnameRoutingDeadline -test.timeout 90s'
```

Omit `-test.run` to include the existing experiment suites. Without
`HOSTNAME_VM_MIHOMO`, only these new route tests skip. A missing required object,
unsupported library profile or failed attachment never enables hostname routing.

## Next requirements

Define independent observer authority and crash/reconnect behavior before a
versioned optional service ABI or production routing consumer. Define explicit
application-name provenance and precedence alongside Fake-IP, explicit proxy
names and sniffing. Broader send paths and reinjection remain outside the proved
first-write path; browser/encrypted-DNS/ECH support remains a later milestone.
