# Lookup through Mihomo's TUN system stack

Mihomo's default Linux inbound is a TUN device with the `system` stack. No
kernel NAT changes the application's packets: they leave the application
socket with their original tuple, pass the observer's cgroup egress program and
enter the device. sing-tun's system stack reads them, translates them in
userspace to its own kernel listener on the TUN address, and reports the
original source and destination to Mihomo from its NAT table.

Mihomo therefore keys a TUN lookup by that original tuple and by the network
namespace cookie of the kernel socket the stack accepted, which lives in the TUN
device's namespace. The observer published the application socket's flow
record under the same namespace and tuple. All other checks are unchanged: the
guarded publication read, send/lifetime guard, profile-3 window and the fresh
validation after rule matching.

## Scope

- TCP from the `system` stack, and from `mixed`, which uses the system stack for
  TCP. IPv4 and IPv6.
- Applications in the TUN device's network namespace. A flow from another
  namespace has no record under the device's namespace and returns unknown.
- `auto-redirect` sends TCP through a kernel redirect instead. Its accepted
  socket's peer is the original source; Mihomo refuses that case until it is
  tested separately. The `gvisor` stack has no kernel socket and also returns
  unknown.
- With `auto-route`, destinations in a directly connected subnet bypass the
  device (sing-tun's `suppress_prefixlength 0` rule) and never reach Mihomo, so
  they get no name. The harness therefore places its server behind a gateway.
- Fake-IP destinations keep their existing behavior. With fake-ip DNS only
  applications that resolve names themselves reach Mihomo with a real IP.

Unlike an accepted REDIRECT socket, the tuple is derived from packets routed
into the device. A local process with CAP_NET_RAW could inject packets carrying
an observed connection's tuple. That can only choose the route of the injected
connection itself, which ordinary SNI already lets it choose, and cannot change
the name or route of the application's own connection.

## Tests

`TestVMHostnameNativeTUN` runs the native Mihomo helper with a real sing-tun
system-stack inbound, as UID 1000 with only ambient CAP_NET_ADMIN (the hardened
service's Mihomo capability for TUN). The server sits behind a veth pair in a
second network namespace, so its address is not local. An nft route-hook mark
sends every connection to it, except the helper's own dial, into the device by
policy routing. The client binds a wildcard source (`any-source`) so it keeps
the routed address.

For both families it covers a named route with unchanged ClientHello bytes and
real destination, a ClientHello sent after the lookup started, a stopped
observer, observer death after the rule matched (fallback at validation) and a
connection from a process outside the observed cgroup, which must route
ordinarily without waiting for the budget.

The [hardened-service harness](https://github.com/nosini/hardened-proxy-service/blob/ebpf-hostname-discovery/docs/hostname-development.md)
switches the real confined Mihomo service to the shipped TUN shape (system
stack, auto-route, auto-detect-interface, device `Mihomo`) under the shipped
kill switch and enforcing SELinux, and checks named routing, completed TLS 1.3
and fallback with the observer stopped.
