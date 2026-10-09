// Records the executable of every process, so that mihomo can name the owner
// of a connection (see sockowner.c) without reading other processes' /proc
// entries.
//
// Each process carries its record in exec_tasks, task-local storage of its
// thread group leader, which userspace looks up with a pidfd. An LSM hook sets
// it when the process executes a program, and a new process starts with a
// copy of its parent's. The record goes away with the process, so the map
// can't fill up or keep stale entries. When a process is freed, its record is
// copied to exec_recent, keyed by process ID, which keeps the most recent
// processes so connections of short-lived ones can still be named; exec also
// writes there, so it holds new programs before their process is freed.
//
// A process that has been reaped can't be looked up by pidfd any more, but
// its record only reaches exec_recent once the task is freed, which can be
// much later. So when a process first sends on or connects a socket, its
// record is saved in exec_recent too, and the owner of a connection can still
// be named right after it exits. These hooks also record the process that
// sends on a connected socket as its owner, which the cgroup hooks in
// sockowner.c don't see.
//
// Every record carries the process's start time. A record only belongs to a
// connection's owner if the process started before the owner was recorded and,
// once it has exited, exited after that. This rules out process IDs that were
// reused in between.
//
// Only LSM hooks record, because the kernel skips tracing programs (tp_btf,
// fentry, kprobes) on a CPU where the same program was preempted, and a
// missed fork would leave a process without a record. LSM programs are never
// skipped.
//
// seed_tasks is an iterator the loader runs once after attaching, to add the
// processes that were already running.
//
// Unlike sockowner.c, these programs read kernel structures (relocated with
// BTF) and call bpf_d_path, so loading them needs CAP_PERFMON in addition to
// CAP_BPF, and the kernel needs CONFIG_BPF_LSM with "bpf" among its active
// LSMs.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "sockowner.h"

#define CLONE_THREAD 0x00010000

// Long enough for nearly every executable; paths that don't fit are recorded
// with len set to -ENAMETOOLONG.
#define EXEC_PATH_SIZE 1024

// Kernel structures, reduced to the fields used here. The loader relocates
// field offsets against the running kernel's BTF.
struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

struct mm_struct {
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
	__u64 start_boottime;
	struct mm_struct *mm;
	struct task_struct *group_leader;
} __attribute__((preserve_access_index));

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
struct sockaddr;

struct bpf_iter_meta;

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct exec_path {
	__u64 start_ns; // CLOCK_BOOTTIME when the process started
	__u64 exit_ns;  // CLOCK_BOOTTIME when it was freed, or 0
	__s32 len;      // bytes in path including the NUL, or a negative errno
	__u32 pad;
	char path[EXEC_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct exec_path);
} exec_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, struct exec_path);
} exec_recent SEC(".maps");

// Space to build a record in, as it's too large for the stack. The exec hook
// can sleep and be preempted, so it uses storage of the executing task rather
// than a per-CPU buffer.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct exec_path);
} exec_scratch SEC(".maps");

// The same for the iterator, of which only one runs at a time.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_path);
} seed_scratch SEC(".maps");

// Called once a new program has replaced the process image; bprm->file is the
// program that runs, which for a script is its interpreter, as in
// /proc/<pid>/exe. A thread that executes has become the thread group leader
// by now and taken over the process's ID and start time.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(record_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 tgid = task->tgid;
	struct exec_path *e;

	e = bpf_task_storage_get(&exec_scratch, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!e)
		return 0;
	e->start_ns = task->start_boottime;
	e->exit_ns = 0;
	e->len = bpf_d_path(&bprm->file->f_path, e->path, sizeof(e->path));
	bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY);
	// Storage is only initialised when it's created, so replace it rather
	// than writing into it, which a reader could see half done. Until the
	// new record is in place, readers find it in exec_recent.
	bpf_task_storage_delete(&exec_tasks, task);
	bpf_task_storage_get(&exec_tasks, task, e,
			     BPF_LOCAL_STORAGE_GET_F_CREATE);
	bpf_task_storage_delete(&exec_scratch, task);
	return 0;
}

// Called for every new task before it gets its ID. The hook decides whether
// the fork may go ahead: ret is the verdict of the BPF LSM programs that ran
// before this one, which must stand, and this one never denies.
SEC("lsm/task_alloc")
int BPF_PROG(record_fork, struct task_struct *task, unsigned long clone_flags,
	     int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf()->group_leader;
	struct exec_path *e;

	if (ret)
		return ret;
	if (clone_flags & CLONE_THREAD)
		return 0;
	e = bpf_task_storage_get(&exec_tasks, parent, 0, 0);
	if (!e)
		return 0;
	e = bpf_task_storage_get(&exec_tasks, task, e,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	// The task's own start time isn't set yet. Nothing can look the
	// record up before the task has an ID.
	if (e)
		e->start_ns = bpf_ktime_get_boot_ns();
	return 0;
}

// Called when the last reference to a task goes, after it has been reaped.
// After a thread executed, the old leader is freed as an ordinary thread, so
// only tasks that still lead their group count.
SEC("lsm/task_free")
int BPF_PROG(record_free, struct task_struct *task)
{
	__u32 tgid = task->tgid;
	struct exec_path *e;

	if (task->group_leader != task || !tgid)
		return 0;
	e = bpf_task_storage_get(&exec_tasks, task, 0, 0);
	if (!e || bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY))
		return 0;
	e = bpf_map_lookup_elem(&exec_recent, &tgid);
	if (e)
		e->exit_ns = bpf_ktime_get_boot_ns();
	return 0;
}

// Records the current process as the owner of a TCP or UDP socket it uses,
// and saves its record in exec_recent the first time it does.
static __always_inline void record_socket_user(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sock_owner *so;
	struct exec_path *e;
	__u32 tgid;

	if (!sk ||
	    (sk->__sk_common.skc_family != AF_INET &&
	     sk->__sk_common.skc_family != AF_INET6) ||
	    !tracked_protocol(sk->sk_protocol))
		return;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!so)
		return;
	record_current(so);
	tgid = so->owner.tgid;
	if (so->saved_tgid == tgid)
		return;
	e = bpf_task_storage_get(&exec_tasks,
				 bpf_get_current_task_btf()->group_leader, 0, 0);
	if (e && !bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY))
		so->saved_tgid = tgid;
}

// Runs in the sending process for every send, write or splice on a socket,
// connected or not, before the data goes out. ret is the verdict of the BPF
// LSM programs that ran before this one, which must stand.
SEC("lsm/socket_sendmsg")
int BPF_PROG(record_send, struct socket *sock, struct msghdr *msg, int size,
	     int ret)
{
	if (ret)
		return ret;
	record_socket_user(sock);
	return 0;
}

// A TCP connection's first packet leaves on connect, before any send.
SEC("lsm/socket_connect")
int BPF_PROG(record_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret)
		return ret;
	record_socket_user(sock);
	return 0;
}

SEC("iter/task")
int seed_tasks(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct mm_struct *mm;
	struct file *exe;
	struct exec_path *e;
	__u32 zero = 0;

	if (!task || task->group_leader != task)
		return 0;
	mm = task->mm;
	if (!mm) // kernel thread or exited
		return 0;
	exe = mm->exe_file;
	if (!exe)
		return 0;
	// The hooks are already attached; what they recorded is newer.
	if (bpf_task_storage_get(&exec_tasks, task, 0, 0))
		return 0;
	e = bpf_map_lookup_elem(&seed_scratch, &zero);
	if (!e)
		return 0;
	e->start_ns = task->start_boottime;
	e->exit_ns = 0;
	e->len = bpf_d_path(&exe->f_path, e->path, sizeof(e->path));
	bpf_task_storage_get(&exec_tasks, task, e,
			     BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

char _license[] SEC("license") = "GPL";
