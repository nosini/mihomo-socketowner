# Pinned map interface, version 1

This is the contract between independently released socketowner loaders and
readers. It covers pinned names, map types, field offsets, byte order and record
meaning. Loader and reader release numbers are independent of this ABI version.

## Discovery and lifetime

Under the loader's `-pin` directory (default `/sys/fs/bpf/mihomo`), public maps
live in `maps/` and private BPF links in `links/`. A reader is given only `maps/`,
usually through a read-only directory bind mount. Pins remain owned by the loader
(root in the service setup); the reader group gets directory mode 0750 and map
mode 0440. Owning a pin would let a reader grant itself write access.

| Pin in `maps/` | Linux map type | Key bytes | Value bytes | Availability |
| --- | --- | ---: | ---: | --- |
| `abi_version` | `BPF_MAP_TYPE_ARRAY` (2) | 4 | 4 | Required; one entry |
| `conn_owners` | `BPF_MAP_TYPE_LRU_HASH` (9) | 32 | 16 | Required |
| `exec_tasks` | `BPF_MAP_TYPE_TASK_STORAGE` (29) | 4 | 1048 | With `-exec-paths` |
| `exec_recent` | `BPF_MAP_TYPE_LRU_HASH` (9) | 4 | 1048 | With `-exec-paths` |

The `abi_version` entry at native-endian uint32 key 0 is native-endian uint32
value 1. The loader freezes this map before pinning it. Readers must reject a
missing marker or an unsupported version before interpreting connection records.
They must also check the type, key size and value size of every map before
performing any lookup; a larger kernel value would overflow a smaller userspace
buffer. Open maps with `BPF_F_RDONLY` and close-on-exec descriptors.

Attach replaces previous links and pins in the same directories. Optional maps
and the version marker are pinned before `conn_owners`, which is the publication
point. Readers should reopen all maps when that pin's inode changes and retry
unavailable optional maps. Detach removes pins but keeps the directories.
Previously opened map descriptors remain valid, so readers must notice pin
removal and replacement rather than retaining old maps indefinitely. Replacement
is not atomic and may briefly leave lookup unavailable.

Private socket storage, scratch maps and program/link names are implementation
details. Map capacities are not part of the ABI. This interface describes the
initial PID namespace and the network namespaces where the programs are attached;
readers in a separate PID namespace cannot resolve the recorded host PIDs through
local pidfds or `/proc`.

## Connection records

All integers are native endian; address bytes use network order. A connection key
is exactly 32 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Network namespace cookie (`SO_NETNS_COOKIE`) |
| 8 | byte[16] | Source IP; IPv4 uses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) |
| 24 | uint16 | Source port, host byte order |
| 26 | uint8 | IP protocol: 6 for TCP, 17 for UDP |
| 27 | byte[5] | Zero padding |

A connection value is exactly 16 bytes:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint32 | Owner TGID (process ID); 0 means unknown |
| 4 | uint32 | Owner UID |
| 8 | uint64 | `CLOCK_BOOTTIME` nanoseconds when that owner was recorded |

The owner is the process that creates, connects or sends on the socket. With
`-exec-paths`, LSM hooks also see sends on connected sockets; without it, passing
an already connected socket may leave the earlier owner recorded. The egress hook
publishes the current owner against the outgoing packet's source address/port.
The key does not distinguish remote destinations. Entries outlive closed sockets
and are evicted by LRU; active flows republish after eviction. Connections from
sockets that existed before attachment or were accepted may have an unknown
owner. Repeated observations of the same owner retain its original timestamp.

## Executable records

Both executable maps use the same 1048-byte value:

| Byte offset | Type | Meaning |
| ---: | --- | --- |
| 0 | uint64 | Process start time, `CLOCK_BOOTTIME` nanoseconds |
| 8 | uint64 | Task-free time in the same clock, or 0 while not freed |
| 16 | int32 | Path byte length including NUL, or negative errno |
| 20 | uint32 | Padding |
| 24 | byte[1024] | NUL-terminated executable path |

`exec_tasks` is keyed by an int32 pidfd opened by the reader for the recorded
TGID. `exec_recent` is keyed by uint32 TGID and retains the most recent record,
including processes that have exited. Its entries are published at exec, first
socket use by an owner, and task-free; the latter can occur after reaping. Forked
processes inherit the parent's executable. An iterator seeds existing processes
when the loader attaches.

A record belongs to an owner only if `start_ns <= owner.boot_ns` and either
`exit_ns == 0` or `exit_ns >= owner.boot_ns`. Check task storage first and then
history; reject records outside that interval to avoid PID reuse. A valid path
length is 1 through 1024; omit the final NUL when using the path. Scripts name
the interpreter, like `/proc/<pid>/exe`. Paths reflect the recording task's root
and mount context and need not name an accessible file in the reader's namespace.

## Evolution

Changes to names, layouts, byte order or record meaning require a new ABI version.
A breaking version must also use a separate pin directory so a reader cannot mix
old and new maps during replacement. Keep old ABI support explicitly if needed;
never silently reinterpret v1 records. Extra private maps or optional features
that preserve all v1 guarantees do not require a version change.

Loaders before v1 used the same record layouts but had no version marker.
Updated readers require this loader's marker; update the loader first. Readers
that predate version checks can continue to consume this loader's unchanged v1
record maps.
