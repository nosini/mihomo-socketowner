// Private publication protocol for the diagnostic send observer, not a public
// ABI. The single control value is preallocated and updated only by atomics;
// invalidating a failed LRU update does not need another allocation or insertion.
#define PUBLICATION_FAILED (1ULL << 63)
#define PUBLICATION_WRITERS 0xffffULL
#define PUBLICATION_STEP (1ULL << 16)
#define PUBLICATION_GENERATION (~(PUBLICATION_FAILED | PUBLICATION_WRITERS))

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY); // userspace cannot clear a failed observer
	__type(key, __u32);
	__type(value, __u64);
} publication_state SEC(".maps");

static __always_inline void publication_fail(__u64 *state)
{
	__sync_fetch_and_or(state, PUBLICATION_FAILED);
}

static __always_inline __u64 *publication_begin(void)
{
	__u32 zero = 0;
	__u64 *state = bpf_map_lookup_elem(&publication_state, &zero);
	if (!state)
		return 0; // key 0 of a live preallocated array cannot be absent
	for (int i = 0; i < 16; i++) {
		__u64 old = *(volatile __u64 *)state;
		if (old & PUBLICATION_FAILED)
			return 0;
		if ((old & PUBLICATION_WRITERS) == PUBLICATION_WRITERS ||
		    (old & PUBLICATION_GENERATION) == PUBLICATION_GENERATION) {
			publication_fail(state); // never wrap either field
			return 0;
		}
		if (__sync_val_compare_and_swap(state, old,
					old + PUBLICATION_STEP + 1) == old)
			return state;
	}
	// Bounded contention is an availability limit, never permission to read
	// an unguarded record. Existing writers still release their own counts.
	publication_fail(state);
	return 0;
}

static __always_inline void publication_end(__u64 *state)
{
	// A successful begin owns one count. Only the count changes at exit;
	// generation and the sticky failure bit survive every writer's exit.
	__sync_fetch_and_sub(state, 1);
}

#ifdef HOSTNAME_PUBLICATION_TEST
// Compiled only into the opt-in fault object. NOEXIST on a key that already
// exists produces a real kernel update error and leaves the old value behind.
// Invalid scope flags likewise exercise the socket-storage failure path.
#define FAULT_SEND 1
#define FAULT_FLOW 2
#define FAULT_SCOPE 4
#define FAULT_SEND_INSERT 8
#define FAULT_FLOW_INSERT 16
#define FAULT_GUARD_INSERT 32
#define FAULT_HOLD_FLOW 64
#define FAULT_STATE_FLAGS 128
#define FAULT_GUARD_DELETE 256
struct publication_fault {
	__u64 mask;
	__u64 initial_state;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct publication_fault);
} publication_faults SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s64);
} publication_error SEC(".maps");

static __always_inline __u64 fault_mask(void)
{
	__u32 zero = 0;
	struct publication_fault *fault = bpf_map_lookup_elem(&publication_faults, &zero);
	return fault ? fault->mask : 0;
}
static __always_inline void save_publication_error(long error)
{
	__u32 zero = 0;
	__s64 *slot = bpf_map_lookup_elem(&publication_error, &zero);
	if (slot)
		*slot = error;
}

// TestRun commands use a synthetic packet's first byte: 1 enters and leaves
// an active count for the test to hold, 2 releases it, 3 seeds boundary states.
// None of these commands exists in the ordinary observer object.
SEC("socket")
int test_publication(struct __sk_buff *skb)
{
	__u8 command;
	__u32 zero = 0;
	__u64 *state;
	if (bpf_skb_load_bytes(skb, 0, &command, 1))
		return 0;
	if (command == 1)
		return publication_begin() != 0;
	state = bpf_map_lookup_elem(&publication_state, &zero);
	if (!state)
		return 0;
	if (command == 2 && (*state & PUBLICATION_WRITERS)) {
		publication_end(state);
		return 1;
	}
	if (command == 3) {
		struct publication_fault *fault = bpf_map_lookup_elem(&publication_faults, &zero);
		if (!fault)
			return 0;
		__sync_lock_test_and_set(state, fault->initial_state);
		return 1;
	}
	return 0;
}
#else
#define fault_mask() 0
#define save_publication_error(error) ((void)0)
#define FAULT_SEND 1
#define FAULT_FLOW 2
#define FAULT_SCOPE 4
#define FAULT_SEND_INSERT 8
#define FAULT_FLOW_INSERT 16
#define FAULT_GUARD_INSERT 32
#define FAULT_HOLD_FLOW 64
#define FAULT_STATE_FLAGS 128
#define FAULT_GUARD_DELETE 256
#endif
