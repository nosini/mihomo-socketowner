# Optional hostname contract

The optional reader has its own [hostname contract v1](../hostname/CONTRACT.md),
shipped with the independently versioned `hostname` Go module. Protocol 1 and
layout profile 1 freeze the authenticated first-send bundle. They are separate
from [socket-owner map ABI 1](map-interface.md), which remains unchanged.

The [reader documentation](../hostname/README.md) covers API use and release tags.
The [observer command](../experiments/hostname/OBSERVER.md) remains experimental;
optional service confinement is available separately, and broader traffic
coverage remains open.

The current implementation explicitly uses [profile 3](../hostname/PROFILE3.md)
for one initial ClientHello window of at most 16 KiB and verified retries within
its remaining bytes. It retains profile-2 final-release reclamation. Historical
profiles 1 and 2 remain frozen; upgrade the optional reader consumer and observer
together. No owner-map ABI changes.
