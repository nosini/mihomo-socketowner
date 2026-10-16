// A separate experiment: derive the active SSL connection from verified live
// call frames in socket_sendmsg. No previous uprobe/object/FD state is used.
// Requires -mcpu=v3 for publication atomics. See ../SEND.md for the profile.
#include "snapshot.c"
#include <bpf/bpf_endian.h>
#include "publication.h"
#include "packet.h"

const volatile __u64 ssl_base;
const volatile __u64 crypto_base;
const volatile __u64 libc_base;

// A CO-RE flavor avoids colliding with the userspace pt_regs definition used
// by the baseline uprobe. These are the kernel's member names.
struct pt_regs___kernel {
	unsigned long sp, ip, bp, bx, di, si, dx, orig_ax;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 write_seq, snd_nxt, snd_una;
} __attribute__((preserve_access_index));
enum iter_type { ITER_UBUF };
struct iov_iter {
	__u8 iter_type, data_source;
	unsigned long iov_offset, count;
	void *ubuf;
} __attribute__((preserve_access_index));
struct msghdr {
	struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct send_evidence);
} send_scope SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct observation);
} send_snapshots SEC(".maps");

// Monotonic, non-evicting state: 0 = no attempt, 1 = exactly one attempt,
// 3 = permanently ambiguous. A second send is excluded even if sequential or
// identically named: TCP may still hold bytes from the first. Never delete or
// reinitialize these entries while this observer collection is in use.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, __u64);
} send_guards SEC(".maps");

SEC("cgroup/sock_create")
int seed_send(struct bpf_sock *sk)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == target_tgid && (sk->family == 2 || sk->family == 10) &&
	    sk->protocol == IPPROTO_TCP) {
		__u64 *publication = publication_begin();
		if (!publication)
			return 1;
		__u64 cookie = bpf_get_socket_cookie(sk);
		__u64 initial = 0;
		__u32 zero = 0;
		long seeded = bpf_map_update_elem(&last_seeded, &zero, &cookie, BPF_ANY);
		long error = bpf_map_update_elem(&send_guards, &cookie, &initial,
			(fault_mask() & FAULT_GUARD_INSERT) ? BPF_EXIST : BPF_NOEXIST);
		if (error)
			save_publication_error(error);
		if (!cookie || seeded || error ||
		    !bpf_sk_storage_get(&send_scope, sk, 0,
			BPF_SK_STORAGE_GET_F_CREATE | ((fault_mask() & FAULT_SCOPE) ? 2 : 0)))
			publication_fail(publication);
		publication_end(publication);
	}
	return 1;
}

static __always_inline int expected_return(__u64 slot, __u64 expected)
{
	__u64 actual = 0;
	return !READ_USER(actual, slot, 0) && actual == expected;
}

// Deliberately fixed to one reviewed libc/OpenSSL path. Never scan the stack
// for plausible pointers or accept a partially matched call chain.
static __always_inline __u64 sending_ssl(struct pt_regs___kernel *regs)
{
	__u64 sp = BPF_CORE_READ(regs, sp), ip = BPF_CORE_READ(regs, ip);
	__u64 bp, buffer_bp = 0, ssl = 0;

	if (BPF_CORE_READ(regs, orig_ax) != 1) // x86-64 write(2)
		return 0;
	if (ip == libc_base + 0xa7992) { // cancellable syscall path
		if (!expected_return(sp, libc_base + 0x9ab58))
			return 0;
		sp += 8;
		if (!expected_return(sp + 40, libc_base + 0x9abb1))
			return 0;
		sp += 48;
	} else if (ip == libc_base + 0x9ab8a) { // noncancellable syscall path
		if (!expected_return(sp + 24, libc_base + 0x9abb1))
			return 0;
		sp += 32;
	} else {
		return 0;
	}
	if (!expected_return(sp + 24, libc_base + 0x119a8a))
		return 0;
	sp += 32;
	if (!expected_return(sp + 24, crypto_base + 0x188a18))
		return 0;
	sp += 32;
	// sock_write has a frame pointer and 0x90 bytes below it. Neither libc
	// syscall path changes rbp. Validate its relationship to the active SP.
	bp = BPF_CORE_READ(regs, bp);
	if (bp != sp + 0x90 || !expected_return(bp + 8, crypto_base + 0x17aeeb))
		return 0;
	sp = bp + 16;
	if (!expected_return(sp + 8, crypto_base + 0x178ec0))
		return 0;
	sp += 16;
	if (!expected_return(sp + 56, crypto_base + 0x1794e6) ||
	    READ_USER(buffer_bp, sp, 32))
		return 0;
	sp += 64;
	if (!expected_return(sp + 24, crypto_base + 0x174adf))
		return 0;
	sp += 32;
	// buffer_ctrl aligns its stack. Its saved frame pointer gives the CFA;
	// bound it to this live frame rather than assuming a fixed alignment.
	if (buffer_bp < sp || buffer_bp - sp > 256 || (buffer_bp & 7) ||
	    !expected_return(buffer_bp + 8, crypto_base + 0x17a091))
		return 0;
	sp = buffer_bp + 16;
	if (!expected_return(sp + 40, ssl_base + 0xd6911) || READ_USER(ssl, sp, 8))
		return 0;
	// BIO_ctrl saved its caller's rbx here. The verified statem_flush call
	// keeps the active SSL_CONNECTION in rbx, not an earlier observation.
	return ssl;
}

static __always_inline int capture_send(struct send_evidence *evidence,
	struct sock *sk, struct msghdr *msg, struct pt_regs___kernel *regs, int size)
{
	// Validate the kernel's real single-buffer iterator against the syscall,
	// and exclude any older queued/unacknowledged bytes. Only the first LSM
	// attempt can write this socket-local evidence; it is immutable afterward.
	struct tcp_sock *tcp = (void *)sk;
	__u32 sequence, next, unacked;
	__u64 buffer = 0, count = 0;
	if (size <= 0 || size > SEND_BYTES_MAX ||
	    BPF_CORE_READ(sk, __sk_common.skc_state) != 1 ||
	    BPF_CORE_READ(msg, msg_iter.iter_type) != bpf_core_enum_value(enum iter_type, ITER_UBUF) ||
	    BPF_CORE_READ(msg, msg_iter.data_source) != 1 ||
	    BPF_CORE_READ(msg, msg_iter.iov_offset) != 0 ||
	    BPF_CORE_READ_INTO(&buffer, msg, msg_iter.ubuf) ||
	    BPF_CORE_READ_INTO(&count, msg, msg_iter.count) ||
	    buffer != BPF_CORE_READ(regs, si) || count != BPF_CORE_READ(regs, dx) || count != size ||
	    BPF_CORE_READ_INTO(&sequence, tcp, write_seq) ||
	    BPF_CORE_READ_INTO(&next, tcp, snd_nxt) ||
	    BPF_CORE_READ_INTO(&unacked, tcp, snd_una) || sequence != next || sequence != unacked)
		return 0;
	if (bpf_probe_read_user(evidence->bytes, size, (void *)buffer))
		return 0;
	if (BPF_CORE_READ_INTO(&next, tcp, write_seq) || next != sequence ||
	    BPF_CORE_READ_INTO(&next, tcp, snd_nxt) || next != sequence ||
	    BPF_CORE_READ_INTO(&unacked, tcp, snd_una) || unacked != sequence)
		return 0;
	evidence->sequence = sequence;
	evidence->len = size;
	return 1;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(observe_send, struct socket *socket, struct msghdr *msg, int size,
	     int ret)
{
	struct sock *sk;
	struct send_evidence *evidence;
	__u64 *publication;
	struct observation o = {};
	struct task_struct *task;
	struct pt_regs___kernel *regs;
	__u64 ssl, bio, wbio = 0, bbio = 0, method = 0, next = 0, name = 0;
	int type = -1, server = -1, init = 0, fd = -1;

	if (ret)
		return ret;
	sk = socket->sk;
	if (!sk || !(evidence = bpf_sk_storage_get(&send_scope, sk, 0, 0)))
		return 0;
	publication = publication_begin();
	if (!publication)
		return 0;
	o.cookie = bpf_get_socket_cookie(sk);
	__u64 *guard = bpf_map_lookup_elem(&send_guards, &o.cookie);
	if (!guard) {
		publication_fail(publication);
		publication_end(publication);
		return 0;
	}
	// Count the attempt before inspecting userspace, including unsupported and
	// failed writes. CAS chooses at most one first attempt; OR never restores
	// eligibility when another writer finishes out of order.
	int first = __sync_val_compare_and_swap(guard, 0, 1) == 0;
	if (!first)
		__sync_fetch_and_or(guard, 3);
	o.boot_ns = bpf_ktime_get_boot_ns();
	o.tgid = bpf_get_current_pid_tgid() >> 32;
	o.fd = -1;
	// Unknown paths on a tracked socket actively invalidate the last name.
	o.pad = 1;
	if (o.tgid != target_tgid || size <= 0)
		goto publish;
	task = bpf_get_current_task_btf();
	regs = (void *)bpf_task_pt_regs(task);
	ssl = sending_ssl(regs);
	if (!ssl)
		goto publish;
	o.pad = 2;
	bio = BPF_CORE_READ(regs, bx); // live sock_write's raw socket BIO
	if (READ_USER(type, ssl, 0) || type != 0 ||
	    READ_USER(server, ssl, SSL_SERVER) || server != 0 ||
	    READ_USER(wbio, ssl, SSL_WBIO) || !wbio ||
	    READ_USER(bbio, ssl, 0x60) || bbio != wbio ||
	    READ_USER(method, bbio, BIO_METHOD) || method != crypto_base + 0x653da0 ||
	    READ_USER(next, bbio, 0x48) || next != bio ||
	    READ_USER(method, bio, BIO_METHOD) || method != socket_method ||
	    READ_USER(init, bio, BIO_INIT) || init != 1 ||
	    READ_USER(fd, bio, BIO_NUM) || fd < 0 || fd != BPF_CORE_READ(regs, di))
		goto publish;
	o.fd = fd;
	if (first && !capture_send(evidence, sk, msg, regs, size)) {
		o.pad = 6;
		goto publish;
	}
	// The verified write syscall used this BIO's descriptor. The kernel
	// has already resolved that descriptor and holds THIS socket for the
	// operation, even if another thread changes the descriptor slot later.
	// Do not traverse the descriptor table or dereference a user-resolved
	// file pointer: the hook's socket is the actual transport being used.
	o.pad = 4;
	if (!READ_USER(name, ssl, SSL_HOSTNAME) && name) {
		o.len = bpf_probe_read_user_str(o.hostname, sizeof(o.hostname), (void *)name);
		if (o.len <= 1 || o.len >= sizeof(o.hostname)) {
			o.len = 0;
			__builtin_memset(o.hostname, 0, sizeof(o.hostname));
		}
	}
	if (o.len)
		o.pad = 0;
publish:
	{
		long error = bpf_map_update_elem(&send_snapshots, &o.cookie, &o,
			(fault_mask() & FAULT_SEND) ? BPF_NOEXIST :
			(fault_mask() & FAULT_SEND_INSERT) ? BPF_EXIST : BPF_ANY);
		if (error) {
			save_publication_error(error);
			publication_fail(publication);
		}
	}
	publication_end(publication);
	return 0;
}

// Private diagnostic bridge from the application's socket to the translated
// flow seen by a transparent listener. This is not a public reader ABI.
struct flow_observation {
	__u64 cookie;
	struct observation observation;
	__u32 sequence, payload_len;
	__u64 packet_ns;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, struct flow_key);
	__type(value, struct flow_observation);
} send_flows SEC(".maps");

SEC("cgroup_skb/egress")
int observe_flow(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	struct send_evidence *evidence;
	__u64 *publication;
	struct packet_info packet = {};
	struct flow_observation record = {};
	struct observation *name;

	if (!sk || !(sk = bpf_sk_fullsock(sk)) ||
	    !(evidence = bpf_sk_storage_get(&send_scope, sk, 0, 0)))
		return 1;
	publication = publication_begin();
	if (!publication)
		return 1;
	record.cookie = bpf_get_socket_cookie(skb);
	__u64 *guard = bpf_map_lookup_elem(&send_guards, &record.cookie);
	if (!guard) {
		publication_fail(publication);
		goto done;
	}
	if (!parse_packet(skb, &packet)) {
		__sync_fetch_and_or(guard, 3);
		goto done;
	}
	packet.key.netns = bpf_get_netns_cookie(skb);
	record.sequence = packet.sequence;
	record.payload_len = packet.payload_len;
	record.packet_ns = bpf_ktime_get_boot_ns();
	name = bpf_map_lookup_elem(&send_snapshots, &record.cookie);
	if (packet.payload_len && !packet_matches(skb, &packet, evidence))
		__sync_fetch_and_or(guard, 3);
	if (name && packet.payload_len && *(volatile __u64 *)guard == 1)
		__builtin_memcpy(&record.observation, name, sizeof(*name));
	// The SYN also publishes, with unknown hostname. Never wait until a name
	// exists to replace a previous cookie at a reused flow key.
	{
		long error = bpf_map_update_elem(&send_flows, &packet.key, &record,
			(fault_mask() & FAULT_FLOW) ? BPF_NOEXIST :
			(fault_mask() & FAULT_FLOW_INSERT) ? BPF_EXIST : BPF_ANY);
		if (error) {
			save_publication_error(error);
			publication_fail(publication);
		}
	}
done:
	publication_end(publication);
	return 1;
}
