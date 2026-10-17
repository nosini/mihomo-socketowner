# Reader development and distribution

This directory is a separate module. From here:

```sh
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

Root-module `go test ./...` does not include nested modules. Test both. For the
privileged interoperability suite, put this module and the socketowner root
module in a temporary Go workspace, then use `-tags hostname_vm` for the root
experiment tests. `TestVMHostnameContract*` exercises this public reader across
the real endpoint, including a nonroot process with no capabilities or inherited
BPF/pidfd descriptors. Mihomo's direct-reader and native VM routing matrices also
use this module.

The module is released independently with a subdirectory-prefixed Git tag, for
example `hostname/v0.1.0`, rather than a loader release tag. The initial Go API is
staged for that first release; the documented v1 wire/profile semantics must not
change under the same numbers. A new incompatible profile or protocol requires
new numbers and explicit reader support; there is no downgrade or guessing.
Follow the [Go module tag rules](https://go.dev/ref/mod#vcs-version).
No release tag or publication is performed by building it.

The standalone module includes its GPL-3.0 license. Distribute it with the reader
sources. Observer binaries, BPF sources and service packaging are separate
artifacts; a reader-only dependency must not install or update them.
