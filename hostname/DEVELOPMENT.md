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

On Linux/amd64, the reader and root experiment both check observer liveness
with a zero-timeout pidfd poll. Even that poll can return `EINTR`; each check
retries only interruptions, at most three times. Actual exit, invalid FDs,
other errors and persistent interruptions still fail closed. This does not
change the observer identity contract or extend the lookup deadline.

Run `go test -race ./...` and `go vet ./...` from the root module as well.
For deterministic interruption checks on a disposable Linux VM with `strace`,
compile each package's test binary and run it as follows (use a task build path):

```sh
# From this directory; repeat from experiments/hostname for the root helper.
go test -c -o /absolute/task/build/pidfd.test .
strace -f -e trace=ppoll -e inject=ppoll:error=EINTR:when=1 /absolute/task/build/pidfd.test -test.run '^TestPidfdLiveness$' -test.v
strace -f -e trace=ppoll -e inject=ppoll:error=EINTR /absolute/task/build/pidfd.test -test.run '^TestPidfdInvalid$' -test.v
```

The first test must accept the live pidfd and reject the exited child. The
second must reject after three interrupted polls without spinning. The service
VM harness also offers `--interrupt-recovery-poll` to inject the first poll
interruption after automatic observer recovery and require named routing on
that first connection.

The VM observer fixture retains bootstrap-server rejection reasons in its
stderr, included when a supervised case fails. A reader-side EOF alone cannot
distinguish a rejected envelope, expired handshake or failed authority check.
The resident observer keeps its existing error handling; no per-client
production logging is enabled. Keep failing logs when a later repetition passes.

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
