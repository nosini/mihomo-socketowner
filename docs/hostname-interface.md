# Optional hostname contract

The optional reader has its own [hostname contract v1](../hostname/CONTRACT.md),
shipped with the independently versioned `hostname` Go module. Protocol 1 and
layout profile 1 freeze the authenticated first-send bundle. They are separate
from [socket-owner map ABI 1](map-interface.md), which remains unchanged.

The [reader documentation](../hostname/README.md) covers API use and release tags.
The [observer command](../experiments/hostname/OBSERVER.md) remains experimental;
service confinement and broader traffic coverage are still pending.

The current implementation explicitly uses [profile 2](../hostname/PROFILE2.md)
for final-release guard reclamation. Profile 1 remains frozen; upgrade the
optional reader consumer and observer together. No owner-map ABI changes.
