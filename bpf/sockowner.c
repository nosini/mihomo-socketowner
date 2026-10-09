// Records which process owns each outgoing TCP/UDP flow, so that mihomo can
// match PROCESS-NAME and PROCESS-PATH rules after the socket has gone away and
// without scanning /proc.
//
// The cgroup socket hooks run in the context of the process that creates,
// connects or sends on a socket and remember it in socket-local storage. The
// egress hook publishes the owner in conn_owners, keyed by network namespace,
// protocol, source address and source port, as taken from each outgoing
// packet. Entries outlive the socket and are evicted least-recently-used.
//
// The cgroup programs use only UAPI context structures, so they need no BTF
// relocations. They avoid helpers that need CAP_PERFMON (such as
// bpf_get_current_comm), so loading them needs only CAP_BPF and CAP_NET_ADMIN.
// record_send is an LSM program, which needs CAP_PERFMON and the BPF LSM; the
// loader only loads it along with execpath.c.
//
// Build: go generate in the repository root, which needs clang and the libbpf headers.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

struct conn_key {
	__u64 netns;
	__u8 addr[16]; // IPv4 is stored IPv4-mapped (::ffff:a.b.c.d)
	__u16 port;    // host byte order
	__u8 proto;    // IPPROTO_TCP or IPPROTO_UDP
	__u8 pad[5];
};

struct conn_owner {
	__u32 tgid;
	__u32 uid;
	__u64 boot_ns; // CLOCK_BOOTTIME when the owner was recorded
};

struct sock_owner {
	struct conn_owner owner;
	__u64 netns;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sock_owner);
} sock_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_owner);
} conn_owners SEC(".maps");

static __always_inline int tracked_protocol(__u32 protocol)
{
	return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

// Keeps the time of an owner that is recorded again, which must stay before
// the process exits for mihomo to accept it.
static __always_inline void record_current(struct sock_owner *so)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (so->owner.tgid == tgid && so->owner.boot_ns)
		return;
	so->owner.tgid = tgid;
	so->owner.uid = (__u32)bpf_get_current_uid_gid();
	so->owner.boot_ns = bpf_ktime_get_boot_ns();
}

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *sk)
{
	struct sock_owner *so;

	if ((sk->family != AF_INET && sk->family != AF_INET6) ||
	    !tracked_protocol(sk->protocol))
		return 1;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (so) {
		record_current(so);
		so->netns = bpf_get_netns_cookie(sk);
	}
	return 1;
}

// connect and unconnected sendmsg run in the process that actually uses the
// socket, which may differ from its creator when the socket was inherited or
// passed over a UNIX socket. They also cover sockets created before the
// programs were attached. Sends on a connected socket skip the sendmsg hooks;
// record_send covers those.
static __always_inline int record_sock_addr(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct sock_owner *so;

	if (!sk || !tracked_protocol(sk->protocol))
		return 1;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (so) {
		record_current(so);
		so->netns = bpf_get_netns_cookie(ctx);
	}
	return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

// Kernel structures for record_send, reduced to the fields used here. The
// loader relocates field offsets against the running kernel's BTF.
struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr;

// Runs in the sending process for every send, write or splice on a socket,
// connected or not, before the data goes out. ret is the verdict of the BPF
// LSM programs that ran before this one; a denial must stand.
SEC("lsm/socket_sendmsg")
int BPF_PROG(record_send, struct socket *sock, struct msghdr *msg, int size,
	     int ret)
{
	struct sock *sk = sock->sk;
	struct sock_owner *so;

	if (ret)
		return ret;
	if (!sk ||
	    (sk->__sk_common.skc_family != AF_INET &&
	     sk->__sk_common.skc_family != AF_INET6) ||
	    !tracked_protocol(sk->sk_protocol))
		return 0;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (so)
		record_current(so);
	return 0;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	struct sock_owner *so;
	struct conn_key key = {};
	__u8 version;

	if (!sk)
		return 1;
	sk = bpf_sk_fullsock(sk);
	if (!sk || !tracked_protocol(sk->protocol))
		return 1;
	// Sockets that existed before the programs were attached and accepted
	// sockets have no owner. They still publish an empty owner, so that a
	// stale entry for the same address and port is not mistaken for theirs.
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!so)
		return 1;
	if (!so->netns)
		so->netns = bpf_get_netns_cookie(skb);

	// The socket may be bound to a wildcard address, so take the source
	// address from the packet. Egress data starts at the network header.
	if (bpf_skb_load_bytes(skb, 0, &version, 1))
		return 1;
	version >>= 4;
	if (version == 4) {
		key.addr[10] = 0xff;
		key.addr[11] = 0xff;
		if (bpf_skb_load_bytes(skb, 12, &key.addr[12], 4))
			return 1;
	} else if (version == 6) {
		if (bpf_skb_load_bytes(skb, 8, key.addr, 16))
			return 1;
	} else {
		return 1;
	}

	key.netns = so->netns;
	key.port = sk->src_port;
	key.proto = sk->protocol;

	// Check the map on every packet rather than remembering what this
	// socket published: the source address and port can change (a UDP
	// socket that disconnects is bound again on its next send), and the
	// entry may have been evicted. The lookup also keeps the entry of an
	// active flow recently used.
	struct conn_owner *published = bpf_map_lookup_elem(&conn_owners, &key);
	if (published &&
	    !__builtin_memcmp(published, &so->owner, sizeof(so->owner)))
		return 1;
	bpf_map_update_elem(&conn_owners, &key, &so->owner, BPF_ANY);
	return 1;
}

char _license[] SEC("license") = "GPL";
