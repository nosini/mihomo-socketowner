// Socket-local owner records, shared by the cgroup programs in sockowner.c and
// the LSM programs in execpath.c. The loader gives both objects the same
// sock_owners map.

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10

struct conn_owner {
	__u32 tgid;
	__u32 uid;
	__u64 boot_ns; // CLOCK_BOOTTIME when the owner was recorded
};

struct sock_owner {
	struct conn_owner owner;
	__u64 netns;
	// The owner whose executable execpath.c saved in exec_recent last.
	__u32 saved_tgid;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sock_owner);
} sock_owners SEC(".maps");

static __always_inline int tracked_protocol(__u32 protocol)
{
	return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

// Records the current process as the owner. Keeps the time of an owner that
// is recorded again, which must stay before the process exits for mihomo to
// accept it.
static __always_inline void record_current(struct sock_owner *so)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (so->owner.tgid == tgid && so->owner.boot_ns)
		return;
	so->owner.tgid = tgid;
	so->owner.uid = (__u32)bpf_get_current_uid_gid();
	so->owner.boot_ns = bpf_ktime_get_boot_ns();
}
