#ifndef __CR_DSA_FLOW_H__
#define __CR_DSA_FLOW_H__

#define DSA_FLOW_MAGIC 0x44534654U
#define DSA_FLOW_VERSION 1U
#define DSA_FLOW_BYTES_DEFAULT (32U * 1024U * 1024U)
#define DSA_FLOW_BYTES_MAX (128U * 1024U * 1024U)
#define DSA_FLOW_COMPLETE 1U
#define DSA_FLOW_HOST 1U
#define DSA_FLOW_PARASITE 2U
#define DSA_FLOW_NO_ID (~0U)

enum dsa_flow_kind {
	DSA_FLOW_BEGIN = 1, DSA_FLOW_FIRST_TASK,
	DSA_FLOW_PUBLISH_PRE, DSA_FLOW_PUBLISH_POST,
	DSA_FLOW_WAIT_SLOT_BEGIN, DSA_FLOW_WAIT_SLOT_END,
	DSA_FLOW_READY, DSA_FLOW_ACCEPT, DSA_FLOW_H_CREATE,
	DSA_FLOW_PREPARE_BEGIN, DSA_FLOW_PREPARE_END,
	DSA_FLOW_SUBMIT_BEGIN, DSA_FLOW_SUBMIT_END,
	DSA_FLOW_COMPLETE_OBSERVED, DSA_FLOW_RECYCLE,
	DSA_FLOW_LOOP_BEGIN, DSA_FLOW_LOOP_END, DSA_FLOW_SNAPSHOT,
	DSA_FLOW_FINISH_PRE, DSA_FLOW_FINISH_POST,
	DSA_FLOW_JOIN_BEGIN, DSA_FLOW_JOIN_END, DSA_FLOW_CLEANUP_BEGIN,
	DSA_FLOW_END,
	DSA_FLOW_EMPTY_INPUT_BEGIN, DSA_FLOW_EMPTY_INPUT_END,
};

/* Two independent single-writer halves in the diagnostic memfd tail. */
struct dsa_flow_header {
	u32 magic, version, header_size, event_size;
	u64 begin_ns, end_ns, event_count, dropped;
	u32 pid, role, clock_valid, flags;
};

/* Point observations. a..e have a kind-specific, versioned interpretation. */
struct dsa_flow_event {
	u64 ns, a, b, c, d, e;
	u32 kind, seq, id, flags;
};

struct dsa_flow_buffer {
	struct dsa_flow_header *header;
	struct dsa_flow_event *events;
	u32 capacity;
};

_Static_assert(sizeof(struct dsa_flow_header) == 64, "DSA flow header layout");
_Static_assert(sizeof(struct dsa_flow_event) == 64, "DSA flow event layout");

static inline int dsa_flow_layout_valid(u32 total, u32 flow, u32 software_max, u32 software_event)
{
	return flow <= DSA_FLOW_BYTES_MAX &&
		(!flow || (flow >= 4096U && !(flow % 128U) && flow < total)) &&
		total - flow <= software_max && !(total % software_event);
}

static inline void dsa_flow_bind(struct dsa_flow_buffer *buffer, void *memory, u32 bytes)
{
	buffer->header = memory;
	buffer->events = (struct dsa_flow_event *)(buffer->header + 1);
	buffer->capacity = (bytes - sizeof(*buffer->header)) / sizeof(*buffer->events);
}

static inline void dsa_flow_push(struct dsa_flow_buffer *buffer, u64 ns, u32 kind,
				u32 seq, u32 id, u32 flags,
				u64 a, u64 b, u64 c, u64 d, u64 e)
{
	struct dsa_flow_header *h = buffer->header;
	struct dsa_flow_event *event;

	if (!h)
		return;
	if (!ns || ns < h->end_ns) {
		h->clock_valid = 0;
		return;
	}
	if (!h->begin_ns)
		h->begin_ns = ns;
	h->end_ns = ns;
	if (h->event_count >= buffer->capacity) {
		h->dropped++;
		return;
	}
	event = &buffer->events[h->event_count++];
	event->ns = ns;
	event->kind = kind;
	event->seq = seq;
	event->id = id;
	event->flags = flags;
	event->a = a;
	event->b = b;
	event->c = c;
	event->d = d;
	event->e = e;
}

#endif
