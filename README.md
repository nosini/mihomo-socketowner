# socketowner

socketowner records which Linux process owns an outgoing TCP or UDP connection, so
mihomo can match process rules without permission to inspect other processes.
A small privileged loader attaches the BPF programs and exits. mihomo reads the
resulting maps without BPF capabilities. Records can outlive both the socket and
the process, so short connections can still be identified.

The loader is installed and updated separately from mihomo. Its executable stays
named `mihomo-sockowner` for compatibility with existing deployments.

## Installing and using

Install a separately built `mihomo-sockowner` binary:

```sh
sudo install -m 755 mihomo-sockowner /usr/local/bin/mihomo-sockowner
```

For a sandboxed systemd setup with a reader group, read-only map mounts and SELinux
policy, follow [hardened-mihomo-service](https://github.com/nosini/hardened-mihomo-service#process-lookup).
That repository owns the service units and policy; it uses this loader as a
separate prerequisite.

To attach manually, with the existing `mihomo` group allowed to read the maps:

```sh
sudo /usr/local/bin/mihomo-sockowner -reader-group mihomo -exec-paths attach
```

The default pin directory is `/sys/fs/bpf/mihomo`. `-pin` changes it; `-cgroup`
selects a cgroup v2 directory instead of `/sys/fs/cgroup`. Flags precede `attach`
or `detach`. bpffs must already be mounted at `/sys/fs/bpf`.

`-exec-paths` requires kernel BTF and an active BPF LSM. Without it, the loader
records socket owners only, and mihomo needs `/proc` access to resolve their
executables. Attaching needs `CAP_BPF` and `CAP_NET_ADMIN`, plus `CAP_CHOWN` for
`-reader-group` and `CAP_PERFMON` for `-exec-paths`. The loader exits after attach;
pinned links keep the programs running.

Point mihomo's `find-process-bpf-map` at `maps/conn_owners` inside the pin directory
(or its read-only bind mount). Set `find-process-bpf-only: true` with `-exec-paths`
to prevent fallback to `/proc`. An unprivileged reader needs directory traversal
and map read permission; the systemd setup supplies both.

To stop recording, after stopping dependent readers:

```sh
sudo /usr/local/bin/mihomo-sockowner detach
```

Use the same `-pin` for attach and detach if you changed it. Both commands preserve
the map directory so existing directory bind mounts keep working.

## Compatibility and updates

This loader publishes [map interface v1](docs/map-interface.md). Update it
independently from mihomo, keeping a version whose map interface the reader
supports. Installing mihomo must not build, install or replace this privileged
executable. A loader update takes effect when its service is restarted.

See [development](docs/development.md) for source builds and tests.

## License

[GNU GPL v3](LICENSE). The BPF object files retain the same license as their
sources.
