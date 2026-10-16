// Diagnostic experiment, not a routing interface. See ../README.md.
// Compile on x86-64: clang -O2 -g -Wall -Werror -D__TARGET_ARCH_x86 -target bpfel -c snapshot.c -o snapshot.o
#include <linux/bpf.h>
#include <linux/in.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
} __attribute__((preserve_access_index));
struct files_struct {
	struct fdtable *fdt;
} __attribute__((preserve_access_index));
struct task_struct {
	struct files_struct *files;
} __attribute__((preserve_access_index));
struct inode {
	unsigned short i_mode;
} __attribute__((preserve_access_index));
struct file {
	struct inode *f_inode;
	void *private_data;
} __attribute__((preserve_access_index));
struct atomic64_t {
	long counter;
} __attribute__((preserve_access_index));
struct sock_common {
	unsigned short skc_family;
	unsigned char skc_state;
	struct atomic64_t skc_cookie;
} __attribute__((preserve_access_index));
struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));
struct socket {
	struct file *file;
	struct sock *sk;
} __attribute__((preserve_access_index));

const volatile __u32 target_tgid;
const volatile __u64 socket_method;

// Layouts below apply ONLY to the binary hashes checked by probe_linux_amd64.go.
#define SSL_WBIO 0x58
#define SSL_SERVER 0x78
#define SSL_HOSTNAME 0xa20
#define BIO_METHOD 0x08
#define BIO_INIT 0x28
#define BIO_NUM 0x38

struct observation {
	__u64 cookie;
	__u64 boot_ns;
	__u32 tgid;
	__s32 fd;
	__s32 len; // including NUL; zero means invalidated
	__u32 pad;
	char hostname[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct observation);
} snapshots SEC(".maps");

// Test evidence that sock_create generated the cookie before the fixture's
// reference getsockopt(SO_COOKIE), which could itself generate a missing one.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} last_seeded SEC(".maps");

// Ensure cookies exist before the uprobe. This touches only sockets created
// by the selected process in the experiment's private cgroup.
SEC("cgroup/sock_create")
int seed_cookie(struct bpf_sock *sk)
{
	if ((__u32)(bpf_get_current_pid_tgid() >> 32) == target_tgid &&
	    (sk->family == 2 || sk->family == 10) && sk->protocol == IPPROTO_TCP) {
		__u64 cookie = bpf_get_socket_cookie(sk);
		__u32 zero = 0;
		bpf_map_update_elem(&last_seeded, &zero, &cookie, BPF_ANY);
	}
	return 1;
}

#define READ_USER(dst, base, offset) \
	bpf_probe_read_user(&(dst), sizeof(dst), (void *)((base) + (offset)))

SEC("uprobe")
int BPF_UPROBE(snapshot, __u64 ssl)
{
	struct observation o = {};
	__u64 bio = 0, method = 0, name = 0;
	int type = -1, server = -1, init = 0, fd = -1;
	struct task_struct *task;
	struct fdtable *fdt;
	struct file **fds, *file = 0;
	struct socket *socket;
	struct sock *sk;
	unsigned short family, mode;

	o.tgid = bpf_get_current_pid_tgid() >> 32;
	if (o.tgid != target_tgid || !ssl ||
	    READ_USER(type, ssl, 0) || type != 0 ||
	    READ_USER(server, ssl, SSL_SERVER) || server != 0 ||
	    READ_USER(bio, ssl, SSL_WBIO) || !bio ||
	    READ_USER(method, bio, BIO_METHOD) || method != socket_method ||
	    READ_USER(init, bio, BIO_INIT) || init != 1 ||
	    READ_USER(fd, bio, BIO_NUM) || fd < 0)
		return 0;

	// Resolve the current descriptor, never a cached fd/object relationship.
	// These are guarded reads, NOT a reference-acquiring fdget(). Concurrent
	// close/replacement is unresolved and excluded from any support claim.
	task = bpf_get_current_task_btf();
	fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || (__u32)fd >= BPF_CORE_READ(fdt, max_fds))
		return 0;
	fds = BPF_CORE_READ(fdt, fd);
	if (!fds || bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]) || !file)
		return 0;
	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if ((mode & 0170000) != 0140000)
		return 0;
	socket = BPF_CORE_READ(file, private_data);
	if (!socket || BPF_CORE_READ(socket, file) != file)
		return 0;
	sk = BPF_CORE_READ(socket, sk);
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP ||
	    BPF_CORE_READ(sk, __sk_common.skc_state) != 1) // TCP_ESTABLISHED
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != 2 && family != 10)
		return 0;
	o.cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
	if (!o.cookie)
		return 0;
	o.fd = fd;
	o.boot_ns = bpf_ktime_get_boot_ns();
	// A fresh observation that has no name invalidates an earlier snapshot
	// of this socket. Missing this entire uprobe remains an open problem.
	if (!READ_USER(name, ssl, SSL_HOSTNAME) && name) {
		o.len = bpf_probe_read_user_str(o.hostname, sizeof(o.hostname), (void *)name);
		if (o.len <= 1 || o.len >= sizeof(o.hostname)) {
			o.len = 0;
			__builtin_memset(o.hostname, 0, sizeof(o.hostname));
		}
	}
	bpf_map_update_elem(&snapshots, &o.cookie, &o, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
