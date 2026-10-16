// Private bounded byte/sequence evidence. No TLS/SNI parsing is used here.
#define SEND_BYTES_MAX 4096

struct send_evidence {
	__u32 sequence;
	__u32 len; // published last by the sole eligible LSM writer
	__u8 bytes[SEND_BYTES_MAX];
};
struct flow_key {
	__u64 netns;
	__u8 source[16], destination[16];
	__u16 source_port, destination_port;
	__u32 pad;
};
struct packet_info {
	struct flow_key key;
	__u32 sequence, payload_offset, payload_len;
	__u8 flags;
};

static __always_inline __u32 packet_u32(const __u8 *bytes)
{
	return ((__u32)bytes[0] << 24) | ((__u32)bytes[1] << 16) |
	       ((__u32)bytes[2] << 8) | bytes[3];
}

static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *p)
{
	__u8 header[40];
	__u32 offset, total, tcp_len;
	if (bpf_skb_load_bytes(skb, 0, header, 20))
		return 0;
	if ((header[0] >> 4) == 4) {
		// Reject fragments, reserved flags, truncation and non-TCP packets.
		if (header[9] != IPPROTO_TCP || (header[6] & 0xbf) || header[7])
			return 0;
		offset = (header[0] & 15) * 4;
		total = ((__u32)header[2] << 8) | header[3];
		if (offset < 20)
			return 0;
		p->key.source[10] = p->key.destination[10] = 0xff;
		p->key.source[11] = p->key.destination[11] = 0xff;
		__builtin_memcpy(&p->key.source[12], &header[12], 4);
		__builtin_memcpy(&p->key.destination[12], &header[16], 4);
	} else if ((header[0] >> 4) == 6) {
		// Extension headers and jumbograms remain outside this profile.
		if (header[6] != IPPROTO_TCP || bpf_skb_load_bytes(skb, 0, header, 40))
			return 0;
		offset = 40;
		total = 40 + (((__u32)header[4] << 8) | header[5]);
		__builtin_memcpy(p->key.source, &header[8], 16);
		__builtin_memcpy(p->key.destination, &header[24], 16);
	} else {
		return 0;
	}
	if (total != skb->len || total < offset + 20 ||
	    bpf_skb_load_bytes(skb, offset, header, 20))
		return 0;
	tcp_len = (header[12] >> 4) * 4;
	if (tcp_len < 20 || total < offset + tcp_len || (header[12] & 15))
		return 0;
	p->key.source_port = ((__u16)header[0] << 8) | header[1];
	p->key.destination_port = ((__u16)header[2] << 8) | header[3];
	p->sequence = packet_u32(&header[4]);
	p->flags = header[13];
	p->payload_offset = offset + tcp_len;
	p->payload_len = total - p->payload_offset;
	return 1;
}

struct match_context {
	struct __sk_buff *skb;
	struct send_evidence *evidence;
	__u32 packet_offset, evidence_offset, len;
	int matched;
};

static long match_chunk(__u32 chunk, void *opaque)
{
	struct match_context *ctx = opaque;
	__u32 offset = chunk * 32;
	if (offset >= ctx->len)
		return 1;
	__u32 count = ctx->len - offset;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 32; i++) {
		if (i >= count)
			break;
		__u8 byte = 0;
		__u32 index = ctx->evidence_offset + offset + i;
		if (index >= SEND_BYTES_MAX ||
		    bpf_skb_load_bytes(ctx->skb, ctx->packet_offset + offset + i, &byte, 1) ||
		    byte != ctx->evidence->bytes[index]) {
			ctx->matched = 0;
			return 1;
		}
	}
	return 0;
}

static __always_inline int packet_matches(struct __sk_buff *skb,
	struct packet_info *p, struct send_evidence *evidence)
{
	__u32 len = evidence->len;
	// Data with ACK set; SYN/FIN/RST/urgent output cannot supply evidence.
	if (!len || len > SEND_BYTES_MAX || !p->payload_len ||
	    !(p->flags & 0x10) || (p->flags & 0x27))
		return 0;
	// Unsigned subtraction supports a small write spanning sequence wrap.
	__u32 offset = p->sequence - evidence->sequence;
	if (offset >= len || p->payload_len > len - offset)
		return 0;
	struct match_context ctx = {
		.skb = skb, .evidence = evidence,
		.packet_offset = p->payload_offset, .evidence_offset = offset,
		.len = p->payload_len, .matched = 1,
	};
	return bpf_loop(SEND_BYTES_MAX / 32, match_chunk, &ctx, 0) >= 0 && ctx.matched;
}

#ifdef HOSTNAME_PUBLICATION_TEST
// Synthetic packets exercise the identical parser/comparator as live egress.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct send_evidence);
} packet_test_evidence SEC(".maps");
SEC("socket")
int test_packet(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct packet_info packet = {};
	struct send_evidence *evidence = bpf_map_lookup_elem(&packet_test_evidence, &zero);
	return evidence && parse_packet(skb, &packet) && packet_matches(skb, &packet, evidence);
}
#endif
