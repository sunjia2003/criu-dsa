#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <linux/idxd.h>
#include <linux/perf_event.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define HOT_FG_HAVE_X86_SIMD 1
#endif

#undef LOG_PREFIX
#define LOG_PREFIX "page-xfer: "

#include "types.h"
#include "crtools.h"
#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "dsa-memory-service.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "fcntl.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "rst_info.h"
#include "stats.h"
#include "tls.h"
#include "vma.h"
#include "kerndat.h"

#define HOT_APPLY_SCRATCH_PAGES 32
#define HOT_DSA_PORTAL_MAP_SIZE 0x1000UL
#define HOT_DSA_MAX_WQ 16
#define HOT_DSA_COMPARE_INFLIGHT DSA_HW_BATCH_OUTER_DEPTH
#define HOT_DSA_COMPARE_BATCH_CHILDREN DSA_HW_BATCH_CHILDREN
#define HOT_DSA_COMPARE_MAX_CHILDREN \
	(HOT_DSA_COMPARE_INFLIGHT * HOT_DSA_COMPARE_BATCH_CHILDREN)
#define HOT_DSA_MAX_ENQ_RETRY 1000000U
#define HOT_DSA_MAX_POLL_RETRY 1000000U
#define HOT_DSA_COMPLETION_TIMEOUT_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)
#define CDP_DSA_COMPLETION_TIMEOUT_EXIT 124
#define HOT_FG_OUTPUT_META_MAX 256U
#define HOT_FG_OUTPUT_LOGICAL_BYTES (2U * 1024U * 1024U)
#define HOT_FG_OUTPUT_WRITE_BYTES (64U * 1024U)

/* Completion-record fault_info layout for a DSA descriptor with CRAV. */
#define HOT_DSA_FAULT_ADDR_MASKED 0x1U
#define HOT_DSA_FAULT_OPERAND_SHIFT 1U
#define HOT_DSA_FAULT_OPERAND_MASK 0x7U
#define HOT_DSA_FAULT_OPERAND_SRC1 1U
#define HOT_DSA_FAULT_OPERAND_SRC2 2U

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#endif

enum hot_fg_compare_backend {
	HOT_FG_COMPARE_DSA = 0,
	HOT_FG_COMPARE_MEMCMP,
	HOT_FG_COMPARE_SCALAR64,
	HOT_FG_COMPARE_SIMD_AVX2,
	HOT_FG_COMPARE_SIMD_AVX512,
	HOT_FG_COMPARE_VALIDATE,
};

static int page_server_sk = -1;

static bool dsa_debug_enabled(void)
{
	static int enabled = -1;
	const char *value = getenv("CRIU_DSA_DEBUG");

	if (enabled >= 0)
		return enabled;

	enabled = value && (!strcmp(value, "1") || !strcasecmp(value, "true") ||
				    !strcasecmp(value, "yes"));
	return enabled;
}

static bool dsa_profile_enabled(void)
{
	static int enabled = -1;
	const char *value = getenv("CRIU_DSA_PROFILE");

	if (enabled >= 0)
		return enabled;

	enabled = value && (!strcmp(value, "1") || !strcasecmp(value, "true") ||
				    !strcasecmp(value, "yes"));
	return enabled;
}

static bool dsa_page_xfer_dump_enabled(void)
{
	const char *value = getenv("CRIU_DSA_DUMP");

	return value && !strcmp(value, "1");
}

static bool dsa_page_xfer_profile_target(int fd_type, unsigned long img_id)
{
	const char *value = getenv("CRIU_DSA_PROFILE_IMG_ID");
	char *end = NULL;
	unsigned long long parsed;

	if (fd_type != CR_FD_PAGEMAP || !value || !value[0])
		return false;
	errno = 0;
	parsed = strtoull(value, &end, 10);
	return !errno && end && !*end && parsed == img_id;
}

static int dsa_compare_breakdown_mode(void)
{
	static int mode = -2;
	const char *value = getenv("CRIU_DSA_COMPARE_BREAKDOWN");

	if (mode != -2)
		return mode;

	if (!value || !value[0] || !strcmp(value, "0") ||
	    !strcasecmp(value, "false") || !strcasecmp(value, "off"))
		return mode = 0;
	if (!strcmp(value, "1") || !strcasecmp(value, "true") ||
	    !strcasecmp(value, "yes"))
		return mode = 1;
	return mode = -1;
}

/* The fd is inherited only by a short-lived CRIU dump.  The task worker keeps
 * the other endpoint and the persistent service owns the peer; CPU/SIMD and
 * ordinary DSA paths never set this variable. */
static int dsa_memory_service_client_fd(void)
{
	static int cached = -2;
	const char *value;
	char *end = NULL;
	long fd;

	if (cached != -2)
		return cached;
	value = getenv("CRIU_DSA_MEMORY_SERVICE_FD");
	if (!value || !value[0])
		return cached = -1;
	errno = 0;
	fd = strtol(value, &end, 10);
	if (errno || !end || *end || fd < 0 || fd > INT_MAX) {
		pr_err("DSA memory service client fd is invalid\n");
		return cached = -1;
	}
	return cached = (int)fd;
}

static int dsa_memory_service_env_u64(const char *name, u64 *value)
{
	const char *text = getenv(name);
	char *end = NULL;
	unsigned long long parsed;

	if (!text || !text[0])
		return -1;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno || !end || *end)
		return -1;
	*value = parsed;
	return 0;
}

static int dsa_memory_service_client_init(struct page_xfer *xfer,
					  unsigned long img_id)
{
	int fd = dsa_memory_service_client_fd();
	u64 service_img_id;

	if (fd < 0)
		return 0;
	if (dsa_memory_service_env_u64("CRIU_DSA_MEMORY_SERVICE_IMG_ID",
					       &service_img_id)) {
		pr_err("DSA memory service target image environment is missing\n");
		return -1;
	}
	/* A process tree may open non-root pagemaps too.  They retain their
	 * ordinary transfer path; the one task image selected by CDP is the only
	 * participant in this service generation. */
	if (service_img_id != img_id)
		return 0;
	if (dsa_memory_service_env_u64("CRIU_DSA_ARENA_GENERATION",
					       &xfer->dsa_fg_service_generation) ||
	    dsa_memory_service_env_u64("CRIU_DSA_ARENA_PARENT_GENERATION",
					       &xfer->dsa_fg_service_parent_generation) ||
	    dsa_memory_service_env_u64("CRIU_DSA_MEMORY_SERVICE_ARENA_ID",
					       &xfer->dsa_fg_service_arena_id) ||
	    dsa_memory_service_env_u64("CRIU_DSA_ARENA_EPOCH",
					       &xfer->dsa_fg_service_arena_epoch)) {
		pr_err("DSA memory service client identity environment is incomplete\n");
		return -1;
	}
	xfer->dsa_fg_service = true;
	xfer->dsa_fg_service_img_id = img_id;
	return 0;
}

static const char *dsa_ms_failure_stage_name(u32 stage)
{
	switch (stage) {
	case CDP_DSA_MS_STAGE_NONE:
		return "none";
	case CDP_DSA_MS_STAGE_REQUEST_IDENTITY:
		return "request-identity";
	case CDP_DSA_MS_STAGE_COMPARE_BOUNDS:
		return "compare-bounds";
	case CDP_DSA_MS_STAGE_COMPARE_VMA_PLAN:
		return "compare-vma-plan";
	case CDP_DSA_MS_STAGE_COMPARE_ENGINE:
		return "compare-engine";
	case CDP_DSA_MS_STAGE_APPLY_PRECHECK:
		return "apply-precheck";
	case CDP_DSA_MS_STAGE_APPLY_OPEN_MANIFEST:
		return "apply-open-manifest";
	case CDP_DSA_MS_STAGE_APPLY_RESULT_VALIDATE:
		return "apply-result-validate";
	case CDP_DSA_MS_STAGE_APPLY_VMA_MATERIALIZE:
		return "apply-vma-materialize";
	case CDP_DSA_MS_STAGE_APPLY_PAGE_STORE:
		return "apply-page-store";
	case CDP_DSA_MS_STAGE_APPLY_MANIFEST_FINISH:
		return "apply-manifest-finish";
	case CDP_DSA_MS_STAGE_APPLY_MANIFEST_CLOSE:
		return "apply-manifest-close";
	case CDP_DSA_MS_STAGE_SEND_REPLY:
		return "send-reply";
	default:
		return "unknown";
	}
}

static int dsa_ms_status_errno(u32 status)
{
	switch (status) {
	case CDP_DSA_MS_EIDENTITY:
		return ESTALE;
	case CDP_DSA_MS_EBOUNDS:
		return ERANGE;
	case CDP_DSA_MS_ESTATE:
		return EBUSY;
	case CDP_DSA_MS_EIO:
		return EIO;
	case CDP_DSA_MS_EHW:
		return EREMOTEIO;
	case CDP_DSA_MS_EPROTO:
	default:
		return EPROTO;
	}
}

static void dsa_ms_client_error_profile(
	const struct page_xfer *xfer, const char *error_class, u16 request_op,
	const struct cdp_dsa_memory_service_msg *reply,
	const struct cdp_dsa_memory_service_diag *diag, bool diag_valid,
	int saved_errno, short revents)
{
	u32 status = reply ? reply->status : 0;
	u32 stage = diag_valid ? diag->failure_stage : CDP_DSA_MS_STAGE_NONE;
	int primary_errno = diag_valid ? diag->primary_errno : saved_errno;
	int cleanup_errno = diag_valid ? diag->cleanup_errno : 0;
	u64 object_index = diag_valid ? diag->object_index :
		CDP_DSA_MS_DIAG_INVALID_OBJECT;
	u64 object_vaddr = diag_valid ? diag->object_vaddr :
		CDP_DSA_MS_DIAG_INVALID_OBJECT;
	u64 expected = diag_valid ? diag->expected_results : 0;
	u64 completed = diag_valid ? diag->completed_results : 0;

	if (!dsa_profile_enabled())
		return;
	pr_info("DSA_MEMORY_SERVICE_ERROR_PROFILE: diag_version=%u class=%s request_op=%u reply_op=%u service_status=%u failure_stage=%s failure_stage_id=%u primary_errno=%d cleanup_errno=%d generation=%" PRIu64 " arena_epoch=%" PRIu64 " object_index=%" PRIu64 " object_vaddr=%" PRIx64 " expected_results=%" PRIu64 " completed_results=%" PRIu64 " poll_revents=%d apply_validate_wall_us=%" PRIu64 " apply_materialize_wall_us=%" PRIu64 " apply_store_wall_us=%" PRIu64 " apply_manifest_finish_wall_us=%" PRIu64 " apply_manifest_close_wall_us=%" PRIu64 " apply_total_wall_us=%" PRIu64 " apply_total_cpu_us=%" PRIu64 "\n",
		diag_valid ? diag->version : 0, error_class, request_op,
		reply ? reply->op : 0, status, dsa_ms_failure_stage_name(stage),
		stage, primary_errno, cleanup_errno,
		diag_valid ? diag->generation_id : xfer->dsa_fg_service_generation,
		diag_valid ? diag->arena_epoch : xfer->dsa_fg_service_arena_epoch,
		object_index, object_vaddr, expected, completed, (int)revents,
		diag_valid ? diag->apply_validate_wall_us : 0,
		diag_valid ? diag->apply_materialize_wall_us : 0,
		diag_valid ? diag->apply_store_wall_us : 0,
		diag_valid ? diag->apply_manifest_finish_wall_us : 0,
		diag_valid ? diag->apply_manifest_close_wall_us : 0,
		diag_valid ? diag->apply_total_wall_us : 0,
		diag_valid ? diag->apply_total_cpu_us : 0);
}

static bool dsa_ms_diag_valid(const struct cdp_dsa_memory_service_diag *diag,
			      u16 request_op,
			      const struct cdp_dsa_memory_service_msg *reply)
{
	return diag &&
		diag->magic == CDP_DSA_MEMORY_SERVICE_DIAG_MAGIC &&
		diag->version == CDP_DSA_MEMORY_SERVICE_DIAG_VERSION &&
		diag->size == sizeof(*diag) && diag->request_op == request_op &&
		diag->reply_op == reply->op &&
		diag->service_status == reply->status &&
		diag->generation_id == reply->generation_id &&
		diag->arena_epoch == reply->arena_epoch;
}

static int dsa_memory_service_client_exchange(
	struct page_xfer *xfer, struct cdp_dsa_memory_service_msg *msg,
	u16 expect_op, struct cdp_dsa_memory_service_diag *diag)
{
	struct pollfd pfd = { .fd = dsa_memory_service_client_fd(), .events = POLLIN };
	const bool profile = dsa_profile_enabled();
	const u16 request_op = msg ? msg->op : 0;
	ssize_t ret;
	bool diag_valid = false;
	int saved_errno;

	if (!xfer || !msg || !xfer->dsa_fg_service || pfd.fd < 0)
		return -1;
	if (diag) {
		memset(diag, 0, sizeof(*diag));
		diag->object_index = CDP_DSA_MS_DIAG_INVALID_OBJECT;
		diag->object_vaddr = CDP_DSA_MS_DIAG_INVALID_OBJECT;
	}
	msg->magic = CDP_DSA_MEMORY_SERVICE_MAGIC;
	msg->version = CDP_DSA_MEMORY_SERVICE_VERSION;
	msg->generation_id = xfer->dsa_fg_service_generation;
	msg->parent_generation_id = xfer->dsa_fg_service_parent_generation;
	msg->img_id = xfer->dsa_fg_service_img_id;
	msg->arena_id = xfer->dsa_fg_service_arena_id;
	msg->arena_epoch = xfer->dsa_fg_service_arena_epoch;
	ret = send(pfd.fd, msg, sizeof(*msg), MSG_NOSIGNAL);
	if (ret != sizeof(*msg)) {
		if (ret >= 0)
			errno = EPROTO;
		saved_errno = errno;
		dsa_ms_client_error_profile(xfer, "transport_error", request_op,
					    NULL, NULL, false, saved_errno, 0);
		errno = saved_errno;
		return -1;
	}
	ret = poll(&pfd, 1, 30000);
	if (ret != 1 || !(pfd.revents & POLLIN)) {
		if (!ret)
			errno = ETIMEDOUT;
		else if (ret == 1 && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)))
			errno = EPIPE;
		saved_errno = errno;
		dsa_ms_client_error_profile(xfer, "transport_error", request_op,
					    NULL, NULL, false, saved_errno, pfd.revents);
		errno = saved_errno;
		return -1;
	}
	if (profile) {
		struct iovec iov[2] = {
			{ .iov_base = msg, .iov_len = sizeof(*msg) },
			{ .iov_base = diag, .iov_len = diag ? sizeof(*diag) : 0 },
		};
		struct msghdr hdr = {
			.msg_iov = iov,
			.msg_iovlen = ARRAY_SIZE(iov),
		};

		ret = recvmsg(pfd.fd, &hdr, 0);
		if (ret == (ssize_t)(sizeof(*msg) + (diag ? sizeof(*diag) : 0)) &&
		    !(hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
			diag_valid = dsa_ms_diag_valid(diag, request_op, msg);
	} else {
		ret = recv(pfd.fd, msg, sizeof(*msg), 0);
	}
	if (ret < 0) {
		saved_errno = errno;
		dsa_ms_client_error_profile(xfer, "transport_error", request_op,
					    NULL, NULL, false, saved_errno,
					    pfd.revents);
		errno = saved_errno;
		return -1;
	}
	if (!ret) {
		saved_errno = ECONNRESET;
		dsa_ms_client_error_profile(xfer, "transport_error", request_op,
					    NULL, NULL, false, saved_errno, pfd.revents);
		errno = saved_errno;
		return -1;
	}
	if ((!profile && ret != sizeof(*msg)) ||
	    (profile && (ret != (ssize_t)(sizeof(*msg) + sizeof(*diag)) ||
			 !diag_valid)) ||
	    msg->magic != CDP_DSA_MEMORY_SERVICE_MAGIC ||
	    msg->version != CDP_DSA_MEMORY_SERVICE_VERSION ||
	    msg->generation_id != xfer->dsa_fg_service_generation ||
	    msg->arena_id != xfer->dsa_fg_service_arena_id ||
	    msg->arena_epoch != xfer->dsa_fg_service_arena_epoch) {
		saved_errno = EPROTO;
		dsa_ms_client_error_profile(xfer, "malformed_reply", request_op,
					    msg, diag, diag_valid, saved_errno,
					    pfd.revents);
		errno = saved_errno;
		return -1;
	}
	if (msg->op == CDP_DSA_MS_ERROR) {
		saved_errno = diag_valid && diag->primary_errno ?
			diag->primary_errno : dsa_ms_status_errno(msg->status);
		dsa_ms_client_error_profile(xfer, "service_error", request_op,
					    msg, diag, diag_valid, saved_errno,
					    pfd.revents);
		errno = saved_errno;
		return -1;
	}
	if (msg->op != expect_op || msg->status != CDP_DSA_MS_OK) {
		saved_errno = EPROTO;
		dsa_ms_client_error_profile(xfer, "malformed_reply", request_op,
					    msg, diag, diag_valid, saved_errno,
					    pfd.revents);
		errno = saved_errno;
		return -1;
	}
	return 0;
}

struct hot_apply_extent {
	bool valid;
	unsigned long vaddr;
	unsigned long len;
};

/* Built while frozen; opening/mapping backing files is deferred until thaw. */
struct hot_vma_plan {
	unsigned long start;
	unsigned long end;
};

/* Fine-grained raw capture has already materialized hot state before this
 * plan is built.  Keep pagemap records separately so validation and protobuf
 * packing can be done in ordered passes without changing the on-disk wire
 * format. */
struct hot_pagemap_plan_entry {
	unsigned long vaddr;
	unsigned long len;
	u32 flags;
};

struct hot_prq_profile_source {
	char iommu[32];
	int pg_req_fd;
	int irq_task_fd;
	int irq;
	pid_t irq_tid;
};

struct hot_fg_compare_batch;

struct hot_apply_ctx {
	bool enabled;
	bool memstore;
	bool fine_grained;
	bool fine_output;
	bool profile;
	bool compare_breakdown;
	enum hot_fg_compare_backend fg_compare_backend;
	bool finished;
	int pipefd[2];
	int manifest_fd;
	int fg_idx_fd;
	int fg_dat_fd;
	off_t fg_dat_off;
	int fd_type;
	unsigned long img_id;
	u32 pages_id;
	const char *manifest_path;
	const char *memory_manifest_path;
	const char *memory_next_path;
	const char *hot_root;
	unsigned long next_seq;
	size_t nr_entries;
	/* A backing owns the FD/mmap.  Both the committed parent records and this
	 * generation's coverage records only borrow an index into this table. */
	struct hot_memstore_owner *owners;
	size_t nr_owners;
	size_t owners_cap;
	struct hot_memstore_seg *old_memstore;
	size_t nr_old_memstore;
	size_t old_memstore_cursor;
	struct hot_vma_segment *vma_segments;
	size_t nr_vma_segments;
	size_t vma_segments_cap;
	size_t vma_segment_cursor;
	struct hot_vma_plan *vma_plans;
	size_t nr_vma_plans;
	size_t vma_plans_cap;
	struct hot_pagemap_plan_entry *pagemap_plan;
	size_t nr_pagemap_plan;
	size_t pagemap_plan_cap;
	/* Semantic accounting for the deferred pagemap stream.  Keep these on
	 * even without profiling: they guard the sidecar-to-pagemap contract. */
	u64 pagemap_plan_input_records;
	u64 pagemap_plan_present_pages;
	u64 pagemap_plan_fg_pages;
	bool vmas_materialized;
	bool post_thaw_ready;
	bool pre_freeze_ready;
	bool parent_view_loaded;
	uint64_t append_bytes;
	uint64_t memstore_bytes;
	uint64_t memstore_segments;
	uint64_t fg_pages;
	uint64_t fg_patch_pages;
	uint64_t fg_full_pages;
	uint64_t fg_patch_bytes;
	uint64_t fg_compare_ops;
	uint64_t append_time_us;
	uint64_t append_prepare_us;
	uint64_t append_tee_us;
	uint64_t append_splice_us;
	uint64_t append_enqueue_wait_us;
	uint64_t worker_wait_us;
	uint64_t worker_join_us;
	uint64_t worker_queue_max;
	uint64_t worker_pipe_size;
	uint64_t dsa_submit_us;
	uint64_t dsa_poll_us;
	uint64_t dsa_enqcmd;
	int dsa_wq_count;
	int dsa_wq_fds[HOT_DSA_MAX_WQ];
	void *dsa_portals[HOT_DSA_MAX_WQ];
	unsigned long dsa_portal_offset[HOT_DSA_MAX_WQ];
	unsigned int dsa_next_wq;
	u32 dsa_max_transfer_size;
	/* Task-service lifetime pool: descriptor/completion pages remain resident
	 * across generations; individual submissions rewrite only used slots. */
	struct hot_fg_compare_batch *compare_batches;
	struct hot_apply_extent pending;
	/* Aggregate-only profile data.  It is populated only when
	 * CRIU_DSA_PROFILE=1; no timer is read from page/range/descriptor loops. */
	bool profile_started;
	bool profile_emitted;
	u64 profile_total_start_us;
	u64 profile_post_prepare_us;
	u64 profile_materialize_us;
	u64 profile_raw_index_us;
	u64 profile_span_build_us;
	u64 profile_compare_wall_us;
	u64 profile_compare_cpu_us;
	u64 profile_sidecar_emit_us;
	u64 profile_compare_engine_wall_us;
	u64 profile_compare_engine_cpu_us;
	u64 profile_parent_prefault_wall_us;
	u64 profile_parent_prefault_cpu_us;
	u64 profile_compare_core_wall_us;
	u64 profile_compare_core_cpu_us;
	u64 profile_output_wall_us;
	u64 profile_output_start_us;
	u64 profile_hot_apply_us;
	u64 profile_pagemap_us;
	u64 profile_finish_us;
	u64 profile_raw_pages;
	u64 profile_raw_bytes;
	u64 profile_capture_runs;
	u64 profile_span_pages;
	u64 profile_spans;
	u64 profile_max_span_pages;
	u64 profile_compare_enq_retries;
	u64 profile_compare_poll_sweeps;
	u64 profile_compare_not_ready;
	u64 profile_compare_max_active;
	u64 profile_batch_outer_submits;
	u64 profile_batch_child_submits;
	u64 profile_batch_partial_submits;
	u64 profile_batch_single_tail_submits;
	u64 profile_batch_outer_success;
	u64 profile_batch_outer_fail;
	u64 profile_batch_child_success;
	u64 profile_batch_child_nobof;
	u64 profile_batch_max_active_outer;
	u64 profile_batch_max_active_children;
	u64 profile_completions_harvested;
	u64 profile_completion_timeout_count;
	u64 profile_max_completion_age_us;
	u64 profile_write_units;
	u64 profile_write_unit_max_us;
	u64 profile_memcmp_calls;
	u64 profile_memcmp_requested_bytes;
	u64 profile_memcmp_scalar_bytes;
	u64 profile_scalar64_calls;
	u64 profile_scalar64_word_ops;
	u64 profile_scalar64_refine_bytes;
	u64 profile_scalar64_tail_bytes;
	u64 profile_scalar64_bytes_examined;
	u64 profile_simd_vector_ops;
	u64 profile_simd_bytes_examined;
	u64 profile_hybrid_dsa_claim_spans;
	u64 profile_hybrid_dsa_claim_pages;
	u64 profile_hybrid_cpu_claim_spans;
	u64 profile_hybrid_cpu_claim_pages;
	u64 profile_hybrid_cpu_waves;
	u64 profile_hybrid_dsa_to_cpu_handoff_spans;
	u64 profile_hybrid_dsa_to_cpu_handoff_pages;
	u64 profile_hybrid_dsa_to_cpu_handoff_remaining_bytes;
	u64 profile_hybrid_unclaimed_empty_count;
	u64 profile_compare_nobof_faults;
	u64 profile_compare_nobof_fault_source1;
	u64 profile_compare_nobof_fault_source2;
	u64 profile_compare_nobof_equal_prefix_bytes;
	u64 profile_compare_fault_handoff_spans;
	u64 profile_compare_fault_handoff_pages;
	u64 profile_compare_fault_handoff_remaining_bytes;
	u64 profile_compare_fault_queue_max;
	u64 profile_compare_fresh_claim_throttles;
	u64 profile_compare_cpu_fault_waves;
	u64 profile_dsa_logical_progress_bytes;
	u64 profile_simd_logical_progress_bytes;
	u64 profile_normal_simd_logical_progress_bytes;
	u64 profile_fault_simd_logical_progress_bytes;
	u64 profile_dsa_fresh_submit_ops;
	u64 profile_dsa_continuation_submit_ops;
	u64 profile_dsa_submitted_bytes;
	u64 profile_simd_progress_while_dsa_active_bytes;
	u64 profile_simd_quanta_while_dsa_active;
	u64 profile_dsa_fresh_claim_bytes;
	u64 profile_dsa_active_zero_while_normal_cpu_work;
	u64 profile_ready_completions_before_simd;
	u64 profile_ready_completions_after_simd;
	u64 profile_scheduler_iterations;
	u64 profile_dsa_refill_samples;
	u64 profile_post_refill_active_sum;
	u64 profile_post_refill_active_lt_32;
	u64 profile_post_refill_active_lt_64;
	u64 profile_post_refill_active_lt_96;
	u64 profile_fresh_refill_spans;
	u64 profile_fresh_refill_batches;
	u64 profile_fresh_refill_blocked_fault_debt;
	u64 profile_dsa_empty_with_claimable_fresh;
	/* Set only after this service has promoted a locally staged generation.
	 * It is a scheduling input, not merely a reporting label. */
	bool service_parent_mapping_warm;
	struct hot_prq_profile_source profile_prq_sources[HOT_DSA_MAX_WQ];
	u32 profile_nr_prq_sources;
	bool profile_prq_available;
	bool profile_prq_active;
	u64 profile_prq_pg_requests;
	u64 profile_prq_thread_cpu_us;
	int profile_prq_setup_errno;
	u64 profile_prefault_spans;
	u64 profile_prefault_pages;
	u64 profile_parent_pages;
	u64 profile_patch_ranges;
	u64 profile_idx_writes;
	u64 profile_dat_writes;
	u64 profile_dat_writevs;
	u64 profile_hot_pwrite_ops;
	u64 profile_hot_pwrite_bytes;
	u64 profile_hot_mprotect_ops;
	u64 profile_hot_memcpy_bytes;
	u64 profile_pagemap_iovs;
	u64 profile_pagemap_flushes;
	u64 profile_pagemap_bytes;
	u64 profile_pagemap_plan_us;
	u64 profile_parent_validate_us;
	u64 profile_pagemap_pack_us;
};

/* There is exactly one DSA checkpoint in a daemon arena lease.  The context is
 * built before collect_pstree and transferred to its page_xfer after pages_id
 * becomes known; it never contains target-VMA-dependent output state. */
static struct hot_apply_ctx *hot_apply_prepared;

static void hot_apply_abort(struct page_xfer *xfer);

struct hot_old_range {
	unsigned long vaddr;
	unsigned long len;
	off_t off;
};

struct hot_move_range {
	off_t src_page;
	off_t dst_page;
	size_t nr_pages;
	bool pending;
	bool scratch;
	bool patch;
};

struct hot_page_source {
	off_t src_page;
	bool patch;
};

struct hot_vma_segment {
	unsigned long start;
	unsigned long end;
	unsigned long vma_start;
	off_t off;
	size_t owner;
};

static uint64_t hot_now_us(void)
{
	struct timespec ts;

	if (!dsa_debug_enabled())
		return 0;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_wall_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_thread_now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static u64 dsa_profile_delta_us(u64 begin, u64 end)
{
	return begin && end >= begin ? end - begin : 0;
}

static bool dsa_hot_apply_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_HOT_APPLY");
	const char *current = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *root = getenv("CRIU_DSA_HOT_ROOT");
	const char *dsa = getenv("CRIU_DSA_DUMP");

	return enabled && strcmp(enabled, "1") == 0 &&
	       ((current && current[0]) || (root && root[0])) &&
	       dsa && strcmp(dsa, "1") == 0;
}

static inline int hot_dsa_enqcmd(void *portal_slot, const void *desc)
{
#if defined(__x86_64__)
	unsigned char retry = 0;

	asm volatile(
		".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\n\t"
		"setz %0\n\t"
		: "=r"(retry)
		: "a"(portal_slot), "d"(desc)
		: "memory", "cc");

	return (int)retry;
#else
	(void)portal_slot;
	(void)desc;
	return 1;
#endif
}

static inline void hot_dsa_release_descriptors(void)
{
#if defined(__x86_64__)
	asm volatile("sfence" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

static inline void hot_dsa_cpu_relax(void)
{
#if defined(__x86_64__)
	asm volatile("pause" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

static u64 hot_dsa_watchdog_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void hot_dsa_prefault_range(void *addr, unsigned long bytes, bool write)
{
	volatile char *p = addr;
	unsigned long i;
	volatile char sink = 0;

	if (!addr || !bytes)
		return;

	for (i = 0; i < bytes; i += PAGE_SIZE) {
		sink ^= p[i];
		if (write)
			p[i] = p[i];
	}
	sink ^= p[bytes - 1];
	if (write)
		p[bytes - 1] = p[bytes - 1];

	(void)sink;
}

static int hot_read_small_file(const char *path, char *buf, size_t len)
{
	int fd;
	ssize_t ret;

	if (!len)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, len - 1);
	close(fd);
	if (ret <= 0)
		return -1;

	buf[ret] = '\0';
	return 0;
}

static void hot_trim_line(char *value)
{
	size_t len;

	if (!value)
		return;
	len = strlen(value);
	while (len && (value[len - 1] == '\n' || value[len - 1] == '\r' ||
		       value[len - 1] == ' ' || value[len - 1] == '\t'))
		value[--len] = '\0';
}

static int hot_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, -1,
		       PERF_FLAG_FD_CLOEXEC);
}

static void hot_prq_profile_init(struct hot_apply_ctx *ctx)
{
	size_t i;

	ctx->profile_nr_prq_sources = 0;
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	ctx->profile_prq_setup_errno = 0;
	for (i = 0; i < ARRAY_SIZE(ctx->profile_prq_sources); i++) {
		ctx->profile_prq_sources[i].pg_req_fd = -1;
		ctx->profile_prq_sources[i].irq_task_fd = -1;
		ctx->profile_prq_sources[i].irq = -1;
		ctx->profile_prq_sources[i].irq_tid = -1;
	}
}

static void hot_prq_profile_close(struct hot_apply_ctx *ctx)
{
	size_t i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (source->pg_req_fd >= 0) {
			if (ctx->profile_prq_active)
				ioctl(source->pg_req_fd, PERF_EVENT_IOC_DISABLE, 0);
			close(source->pg_req_fd);
			source->pg_req_fd = -1;
		}
		if (source->irq_task_fd >= 0) {
			if (ctx->profile_prq_active)
				ioctl(source->irq_task_fd, PERF_EVENT_IOC_DISABLE, 0);
			close(source->irq_task_fd);
			source->irq_task_fd = -1;
		}
	}
	ctx->profile_prq_active = false;
	ctx->profile_prq_available = false;
}

static int hot_prq_profile_wq_iommu(const char *path, char *iommu,
				    size_t iommu_len)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char resolved[PATH_MAX];
	char iommu_link[PATH_MAX];
	char iommu_real[PATH_MAX];
	char *slash;
	const char *base;

	if (!name || !name[1] || !iommu || iommu_len < 6)
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs), "/sys/bus/dsa/devices/%s", name) >=
		    (int)sizeof(sysfs) ||
	    !realpath(sysfs, resolved))
		return -1;

	/* .../<PCI BDF>/dsaN/wqN.M -> .../<PCI BDF> */
	slash = strrchr(resolved, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	slash = strrchr(resolved, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (snprintf(iommu_link, sizeof(iommu_link), "%s/iommu", resolved) >=
		    (int)sizeof(iommu_link) ||
	    !realpath(iommu_link, iommu_real))
		return -1;
	base = strrchr(iommu_real, '/');
	base = base ? base + 1 : iommu_real;
	if (strncmp(base, "dmar", 4) || !base[4] ||
	    snprintf(iommu, iommu_len, "%s", base) >= (int)iommu_len)
		return -1;
	return 0;
}

static int hot_prq_profile_find_irq(const char *iommu)
{
	char expected[64];
	char *line = NULL;
	size_t cap = 0;
	FILE *file;
	int irq = -1;

	if (snprintf(expected, sizeof(expected), "%s-prq", iommu) >=
	    (int)sizeof(expected))
		return -1;
	file = fopen("/proc/interrupts", "r");
	if (!file)
		return -1;
	while (getline(&line, &cap, file) >= 0) {
		char *end = line + strlen(line);
		char *token;
		char *colon;
		char *parsed_end;
		long parsed;

		while (end > line && (end[-1] == '\n' || end[-1] == '\r' ||
				      end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		token = end;
		while (token > line && token[-1] != ' ' && token[-1] != '\t')
			token--;
		if (strcmp(token, expected))
			continue;
		colon = strchr(line, ':');
		if (!colon)
			continue;
		errno = 0;
		parsed = strtol(line, &parsed_end, 10);
		if (errno || parsed_end != colon || parsed < 0 || parsed > INT_MAX)
			continue;
		irq = (int)parsed;
		break;
	}
	free(line);
	fclose(file);
	return irq;
}

static pid_t hot_prq_profile_find_irq_tid(int irq, const char *iommu)
{
	char expected[64];
	char truncated[16];
	DIR *dir;
	struct dirent *de;
	pid_t found = -1;

	if (snprintf(expected, sizeof(expected), "irq/%d-%s-prq", irq, iommu) >=
	    (int)sizeof(expected))
		return -1;
	memcpy(truncated, expected, sizeof(truncated) - 1);
	truncated[sizeof(truncated) - 1] = '\0';
	dir = opendir("/proc");
	if (!dir)
		return -1;
	while ((de = readdir(dir))) {
		char comm_path[PATH_MAX];
		char comm[64];
		char *end;
		long tid;

		if (!de->d_name[0] ||
		    strspn(de->d_name, "0123456789") != strlen(de->d_name))
			continue;
		errno = 0;
		tid = strtol(de->d_name, &end, 10);
		if (errno || *end || tid <= 0 || tid > INT_MAX)
			continue;
		if (snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm",
			     de->d_name) >= (int)sizeof(comm_path) ||
		    hot_read_small_file(comm_path, comm, sizeof(comm)))
			continue;
		hot_trim_line(comm);
		/* Current kernels retain the complete 16-character IRQ name;
		 * older TASK_COMM_LEN layouts may expose only its first 15. */
		if (strcmp(comm, expected) && strcmp(comm, truncated))
			continue;
		found = (pid_t)tid;
		break;
	}
	closedir(dir);
	return found;
}

static int hot_prq_profile_parse_pmu(const char *iommu, u32 *type, int *cpu,
				     u64 *config)
{
	char path[PATH_MAX];
	char value[128];
	char *end;
	char *event_group;
	char *event;
	unsigned long parsed_type;
	unsigned long parsed_cpu;
	unsigned long long parsed_group;
	unsigned long long parsed_event;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/format/event", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	hot_trim_line(value);
	if (strcmp(value, "config:0-27"))
		return -1;
	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/format/event_group",
		     iommu) >= (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	hot_trim_line(value);
	if (strcmp(value, "config:28-31"))
		return -1;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/type", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	errno = 0;
	parsed_type = strtoul(value, &end, 0);
	if (errno || end == value || parsed_type > UINT_MAX)
		return -1;
	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/cpumask", iommu) >=
		    (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	errno = 0;
	parsed_cpu = strtoul(value, &end, 10);
	if (errno || end == value || parsed_cpu > INT_MAX)
		return -1;

	if (snprintf(path, sizeof(path),
		     "/sys/bus/event_source/devices/%s/events/pg_req_posted",
		     iommu) >= (int)sizeof(path) ||
	    hot_read_small_file(path, value, sizeof(value)))
		return -1;
	event_group = strstr(value, "event_group=");
	event = strstr(value, "event=");
	if (!event_group || !event)
		return -1;
	errno = 0;
	parsed_group = strtoull(event_group + strlen("event_group="), &end, 0);
	if (errno || end == event_group + strlen("event_group=") ||
	    parsed_group > 0xf)
		return -1;
	errno = 0;
	parsed_event = strtoull(event + strlen("event="), &end, 0);
	if (errno || end == event + strlen("event=") ||
	    parsed_event > 0x0fffffffULL)
		return -1;

	*type = (u32)parsed_type;
	*cpu = (int)parsed_cpu;
	*config = (parsed_group << 28) | parsed_event;
	return 0;
}

static int hot_prq_profile_add_source(struct hot_apply_ctx *ctx,
				      const char *iommu)
{
	struct hot_prq_profile_source *source;
	struct perf_event_attr attr = {};
	u32 type;
	u64 config;
	int cpu;
	size_t i;

	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		if (!strcmp(ctx->profile_prq_sources[i].iommu, iommu))
			return 0;
	}
	if (ctx->profile_nr_prq_sources >= ARRAY_SIZE(ctx->profile_prq_sources)) {
		errno = E2BIG;
		return -1;
	}
	if (hot_prq_profile_parse_pmu(iommu, &type, &cpu, &config)) {
		errno = ENODEV;
		return -1;
	}

	source = &ctx->profile_prq_sources[ctx->profile_nr_prq_sources];
	if (snprintf(source->iommu, sizeof(source->iommu), "%s", iommu) >=
	    (int)sizeof(source->iommu)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	source->irq = hot_prq_profile_find_irq(iommu);
	if (source->irq < 0) {
		errno = ENODEV;
		return -1;
	}
	source->irq_tid = hot_prq_profile_find_irq_tid(source->irq, iommu);
	if (source->irq_tid < 0) {
		errno = ESRCH;
		return -1;
	}

	attr.type = type;
	attr.size = sizeof(attr);
	attr.config = config;
	attr.disabled = 1;
	source->pg_req_fd = hot_perf_event_open(&attr, -1, cpu);
	if (source->pg_req_fd < 0)
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_TASK_CLOCK;
	attr.disabled = 1;
	source->irq_task_fd = hot_perf_event_open(&attr, source->irq_tid, -1);
	if (source->irq_task_fd < 0) {
		int saved_errno = errno;

		close(source->pg_req_fd);
		source->pg_req_fd = -1;
		errno = saved_errno;
		return -1;
	}
	ctx->profile_nr_prq_sources++;
	return 0;
}

static void hot_prq_profile_setup(struct hot_apply_ctx *ctx,
				  char paths[HOT_DSA_MAX_WQ][64], int nr)
{
	char iommu[32];
	int i;

	if (!ctx->profile || !ctx->fine_output)
		return;
	for (i = 0; i < nr; i++) {
		if (hot_prq_profile_wq_iommu(paths[i], iommu, sizeof(iommu)) ||
		    hot_prq_profile_add_source(ctx, iommu)) {
			int saved_errno = errno ? errno : ENODEV;

			pr_warn("DSA PRQ profile unavailable stage=setup wq=%s errno=%d\n",
				paths[i], saved_errno);
			ctx->profile_prq_setup_errno = saved_errno;
			hot_prq_profile_close(ctx);
			ctx->profile_nr_prq_sources = 0;
			return;
		}
	}
	if (!ctx->profile_nr_prq_sources) {
		ctx->profile_prq_setup_errno = ENODEV;
		pr_warn("DSA PRQ profile unavailable stage=setup errno=%d\n",
			ctx->profile_prq_setup_errno);
		return;
	}
	ctx->profile_prq_available = true;
}

static int hot_prq_profile_start(struct hot_apply_ctx *ctx)
{
	size_t i;

	if (!ctx->profile_prq_available)
		return 0;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (ioctl(source->pg_req_fd, PERF_EVENT_IOC_RESET, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_RESET, 0) ||
		    ioctl(source->pg_req_fd, PERF_EVENT_IOC_ENABLE, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_ENABLE, 0))
			goto err;
	}
	ctx->profile_prq_active = true;
	return 0;
err:
	ctx->profile_prq_setup_errno = errno ? errno : EIO;
	pr_warn("DSA PRQ profile unavailable stage=start errno=%d\n",
		ctx->profile_prq_setup_errno);
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		ioctl(ctx->profile_prq_sources[i].pg_req_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
		ioctl(ctx->profile_prq_sources[i].irq_task_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
	}
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	return -1;
}

static int hot_prq_profile_stop(struct hot_apply_ctx *ctx)
{
	u64 pg_requests = 0;
	u64 task_ns = 0;
	size_t i;

	if (!ctx->profile_prq_available || !ctx->profile_prq_active)
		return 0;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];

		if (ioctl(source->pg_req_fd, PERF_EVENT_IOC_DISABLE, 0) ||
		    ioctl(source->irq_task_fd, PERF_EVENT_IOC_DISABLE, 0))
			goto err;
	}
	ctx->profile_prq_active = false;
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		struct hot_prq_profile_source *source =
			&ctx->profile_prq_sources[i];
		u64 value;

		if (read(source->pg_req_fd, &value, sizeof(value)) !=
		    (ssize_t)sizeof(value))
			goto err;
		pg_requests += value;
		if (read(source->irq_task_fd, &value, sizeof(value)) !=
		    (ssize_t)sizeof(value))
			goto err;
		task_ns += value;
	}
	ctx->profile_prq_pg_requests = pg_requests;
	ctx->profile_prq_thread_cpu_us = task_ns / 1000ULL;
	return 0;
err:
	ctx->profile_prq_setup_errno = errno ? errno : EIO;
	pr_warn("DSA PRQ profile unavailable stage=stop errno=%d\n",
		ctx->profile_prq_setup_errno);
	for (i = 0; i < ctx->profile_nr_prq_sources; i++) {
		ioctl(ctx->profile_prq_sources[i].pg_req_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
		ioctl(ctx->profile_prq_sources[i].irq_task_fd,
		      PERF_EVENT_IOC_DISABLE, 0);
	}
	ctx->profile_prq_available = false;
	ctx->profile_prq_active = false;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	return -1;
}

static int hot_dsa_collect_workqueues(char paths[HOT_DSA_MAX_WQ][64])
{
	DIR *dir;
	struct dirent *de;
	int nr = 0;
	int i;

	for (i = 0; i < HOT_DSA_MAX_WQ; i++)
		paths[i][0] = '\0';

	dir = opendir("/dev/dsa");
	if (!dir)
		return 0;

	while ((de = readdir(dir)) && nr < HOT_DSA_MAX_WQ) {
		char type_path[160];
		char state_path[160];
		char mode_path[160];
		char type_buf[32];
		char state_buf[32];
		char mode_buf[32];
		int n;

		if (strncmp(de->d_name, "wq", 2))
			continue;

		n = snprintf(type_path, sizeof(type_path),
			     "/sys/bus/dsa/devices/%s/type", de->d_name);
		if (n < 0 || n >= (int)sizeof(type_path))
			continue;
		n = snprintf(state_path, sizeof(state_path),
			     "/sys/bus/dsa/devices/%s/state", de->d_name);
		if (n < 0 || n >= (int)sizeof(state_path))
			continue;
		n = snprintf(mode_path, sizeof(mode_path),
			     "/sys/bus/dsa/devices/%s/mode", de->d_name);
		if (n < 0 || n >= (int)sizeof(mode_path))
			continue;

		if (hot_read_small_file(type_path, type_buf, sizeof(type_buf)))
			continue;
		if (strncmp(type_buf, "user", 4))
			continue;
		if (hot_read_small_file(state_path, state_buf, sizeof(state_buf)))
			continue;
		if (strncmp(state_buf, "enabled", 7))
			continue;
		if (hot_read_small_file(mode_path, mode_buf, sizeof(mode_buf)))
			continue;
		if (strncmp(mode_buf, "shared", 6))
			continue;

		n = snprintf(paths[nr], sizeof(paths[nr]), "/dev/dsa/%s", de->d_name);
		if (n < 0 || n >= (int)sizeof(paths[nr]))
			continue;
		nr++;
	}

	closedir(dir);
	return nr;
}

static int hot_dsa_wq_batch_capability(const char *path)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char value[512];
	char *last_word;
	char *end = NULL;
	unsigned long ops;
	unsigned long max_batch;

	if (!name || !name[1])
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/op_config", name) >=
		    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value)))
		return -1;
	last_word = strrchr(value, ',');
	last_word = last_word ? last_word + 1 : value;
	errno = 0;
	ops = strtoul(last_word, &end, 16);
	if (errno || end == last_word ||
	    !(ops & (1UL << DSA_OPCODE_BATCH)) ||
	    !(ops & (1UL << DSA_OPCODE_COMPARE)))
		return -1;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/max_batch_size", name) >=
		    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value)))
		return -1;
	errno = 0;
	max_batch = strtoul(value, &end, 0);
	if (errno || end == value || max_batch < HOT_DSA_COMPARE_BATCH_CHILDREN)
		return -1;
	return 0;
}

static int hot_dsa_wq_max_transfer(const char *path, u32 *max_xfer)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char value[64];
	char device[64];
	char *end = NULL;
	unsigned long long parsed;
	const char *suffix;
	size_t suffix_len;

	if (!name || !name[1] || !max_xfer)
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/max_transfer_size", name) >=
	    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value))) {
		/* WQ attributes are inherited from the device on older accel-config
		 * layouts.  This is the same WQ capability, not an alternate path. */
		if (strncmp(name, "wq", 2))
			return -1;
		suffix = name + 2;
		suffix_len = strcspn(suffix, ".");
		if (!suffix_len || suffix_len >= sizeof(device) - 4)
			return -1;
		if (snprintf(device, sizeof(device), "dsa%.*s", (int)suffix_len,
			     suffix) >= (int)sizeof(device) ||
		    snprintf(sysfs, sizeof(sysfs),
			     "/sys/bus/dsa/devices/%s/max_transfer_size", device) >=
		    (int)sizeof(sysfs) || hot_read_small_file(sysfs, value, sizeof(value)))
			return -1;
	}

	errno = 0;
	parsed = strtoull(value, &end, 0);
	if (errno || end == value || parsed < PAGE_SIZE || parsed > UINT_MAX)
		return -1;
	*max_xfer = (u32)parsed;
	return 0;
}

static int hot_dsa_wq_supports_compare(const char *path)
{
	const char *name = strrchr(path, '/');
	const char *suffix;
	size_t suffix_len;
	char device[64];
	char sysfs[PATH_MAX];
	char value[512];
	char *last_word;
	char *end = NULL;
	unsigned long op_cap;

	if (!name || !name[1])
		return -1;
	name++;
	if (strncmp(name, "wq", 2))
		return -1;
	suffix = name + 2;
	suffix_len = strcspn(suffix, ".");
	if (!suffix_len || suffix_len >= sizeof(device) - 4 ||
	    snprintf(device, sizeof(device), "dsa%.*s", (int)suffix_len,
		     suffix) >= (int)sizeof(device) ||
	    snprintf(sysfs, sizeof(sysfs), "/sys/bus/dsa/devices/%s/op_cap",
		     device) >= (int)sizeof(sysfs) ||
	    hot_read_small_file(sysfs, value, sizeof(value)))
		return -1;

	/* accel-config prints op_cap most-significant word first; BATCH and
	 * COMPARE both live in the final (least-significant) word. */
	last_word = strrchr(value, ',');
	last_word = last_word ? last_word + 1 : value;
	errno = 0;
	op_cap = strtoul(last_word, &end, 16);
	if (errno || end == last_word ||
	    !(op_cap & (1UL << DSA_OPCODE_BATCH)) ||
	    !(op_cap & (1UL << DSA_OPCODE_COMPARE)))
		return -1;
	return 0;
}

/* no-BOF descriptors still require SVA/ATS so a source translation fault is
 * returned in the completion record.  Unlike the BOF baseline they do not
 * require the work queue to block on that fault. */
static int hot_dsa_wq_supports_ats(const char *path)
{
	const char *name = strrchr(path, '/');
	char sysfs[PATH_MAX];
	char value[32];

	if (!name || !name[1])
		return -1;
	name++;
	if (snprintf(sysfs, sizeof(sysfs),
		     "/sys/bus/dsa/devices/%s/ats_disable", name) >=
		    (int)sizeof(sysfs) ||
	    hot_read_small_file(sysfs, value, sizeof(value)) || value[0] != '0')
		return -1;
	return 0;
}

static void hot_dsa_close(struct hot_apply_ctx *ctx)
{
	int i;

	hot_prq_profile_close(ctx);
	for (i = 0; i < ctx->dsa_wq_count; i++) {
		if (ctx->dsa_portals[i] && ctx->dsa_portals[i] != MAP_FAILED)
			munmap(ctx->dsa_portals[i], HOT_DSA_PORTAL_MAP_SIZE);
		ctx->dsa_portals[i] = MAP_FAILED;

		if (ctx->dsa_wq_fds[i] >= 0)
			close(ctx->dsa_wq_fds[i]);
		ctx->dsa_wq_fds[i] = -1;
	}

	ctx->dsa_wq_count = 0;
}

static int hot_dsa_open(struct hot_apply_ctx *ctx)
{
	char paths[HOT_DSA_MAX_WQ][64];
	int nr;
	int i;
	u32 max_xfer = UINT_MAX;

	for (i = 0; i < HOT_DSA_MAX_WQ; i++) {
		ctx->dsa_wq_fds[i] = -1;
		ctx->dsa_portals[i] = MAP_FAILED;
		ctx->dsa_portal_offset[i] = 0;
	}

	nr = hot_dsa_collect_workqueues(paths);
	if (nr <= 0) {
		pr_err("DSA fine-grained compare setup has no enabled user WQ\n");
		return -1;
	}

	for (i = 0; i < nr; i++) {
		u32 wq_max_xfer;

		if (hot_dsa_wq_supports_compare(paths[i])) {
			pr_err("DSA hot apply WQ/device doesn't advertise BATCH+COMPARE: %s\n",
			       paths[i]);
			goto err;
		}
		if (hot_dsa_wq_batch_capability(paths[i])) {
			pr_err("DSA hot apply WQ does not provide shared BATCH(32)+COMPARE: %s\n",
			       paths[i]);
			goto err;
		}
		if ((ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
		     ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE) &&
		    hot_dsa_wq_supports_ats(paths[i])) {
			pr_err("DSA no-BOF compare requires ats_disable=0: %s\n", paths[i]);
			goto err;
		}
		if (hot_dsa_wq_max_transfer(paths[i], &wq_max_xfer)) {
			pr_err("DSA hot apply can't determine max transfer size for %s\n",
			       paths[i]);
			goto err;
		}
		if (wq_max_xfer < max_xfer)
			max_xfer = wq_max_xfer;
		ctx->dsa_wq_fds[i] = open(paths[i], O_RDWR | O_CLOEXEC);
		if (ctx->dsa_wq_fds[i] < 0) {
			pr_perror("DSA hot apply can't open workqueue %s", paths[i]);
			goto err;
		}

		ctx->dsa_portals[i] = mmap(NULL, HOT_DSA_PORTAL_MAP_SIZE,
					   PROT_WRITE, MAP_SHARED | MAP_POPULATE,
					   ctx->dsa_wq_fds[i], 0);
		if (ctx->dsa_portals[i] == MAP_FAILED) {
			pr_perror("DSA hot apply can't mmap workqueue portal %s", paths[i]);
			goto err;
		}
	}

	ctx->dsa_wq_count = nr;
	ctx->dsa_next_wq = 0;
	ctx->dsa_max_transfer_size = max_xfer;
	hot_prq_profile_setup(ctx, paths, nr);
	pr_info("DSA hot apply opened %d DSA workqueues max_xfer=%u\n", nr,
		ctx->dsa_max_transfer_size);
	return 0;

err:
	ctx->dsa_wq_count = nr;
	hot_dsa_close(ctx);
	return -1;
}



static int hot_dsa_submit_ptr(struct hot_apply_ctx *ctx, uint8_t opcode,
			      const void *src, const void *src2, void *dst,
			      unsigned int bytes, uint8_t *result,
			      uint32_t *bytes_completed)
{
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	uint32_t retry_count;
	uint32_t poll_count;
	unsigned int wq_idx;
	unsigned long off;
	unsigned long portal_mask;
	void *slot;
	uint64_t start_us;
	uint64_t end_us;

	if (!bytes || ctx->dsa_wq_count <= 0) {
		pr_err("DSA fine-grained op has no DSA workqueue or zero length\n");
		return -1;
	}
	if (opcode != DSA_OPCODE_COMPARE && opcode != DSA_OPCODE_MEMMOVE) {
		pr_err("DSA fine-grained unsupported opcode=%u\n", opcode);
		return -1;
	}

	wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
	portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;

	memset(&desc, 0, sizeof(desc));
	memset((void *)&comp, 0, sizeof(comp));

	desc.opcode = opcode;
	desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_BOF;
	desc.src_addr = (uint64_t)(unsigned long)src;
	desc.xfer_size = bytes;
	desc.completion_addr = (uint64_t)(unsigned long)&comp;
	if (opcode == DSA_OPCODE_COMPARE) {
		desc.src2_addr = (uint64_t)(unsigned long)src2;
		hot_dsa_prefault_range((void *)src, bytes, false);
		hot_dsa_prefault_range((void *)src2, bytes, false);
	} else {
		desc.dst_addr = (uint64_t)(unsigned long)dst;
		hot_dsa_prefault_range((void *)src, bytes, false);
		hot_dsa_prefault_range(dst, bytes, true);
	}

	start_us = hot_now_us();
	hot_dsa_release_descriptors();
	for (retry_count = 0; retry_count < HOT_DSA_MAX_ENQ_RETRY; retry_count++) {
		off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
		slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(slot, &desc) == 0) {
			ctx->dsa_enqcmd++;
			break;
		}
		hot_dsa_cpu_relax();
	}
	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_submit_us += end_us - start_us;

	if (retry_count == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA fine-grained enqcmd timed out opcode=%u\n", opcode);
		return -1;
	}

	start_us = hot_now_us();
	for (poll_count = 0; poll_count < HOT_DSA_MAX_POLL_RETRY; poll_count++) {
		uint8_t status = comp.status;
		uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

		if (status != 0 && code != DSA_COMP_NONE) {
			end_us = hot_now_us();
			if (end_us > start_us)
				ctx->dsa_poll_us += end_us - start_us;
			if (code == DSA_COMP_SUCCESS || code == DSA_COMP_SUCCESS_PRED) {
				if (result)
					*result = comp.result;
				if (bytes_completed)
					*bytes_completed = comp.bytes_completed;
				return 0;
			}
			pr_err("DSA fine-grained completion failed opcode=%u status=%u code=%u\n",
			       opcode, status, code);
			return -1;
		}
		hot_dsa_cpu_relax();
	}

	end_us = hot_now_us();
	if (end_us > start_us)
		ctx->dsa_poll_us += end_us - start_us;
	pr_err("DSA fine-grained completion timed out opcode=%u\n", opcode);
	return -1;
}

static int hot_dsa_compare_first_diff(struct hot_apply_ctx *ctx,
				      const void *a, const void *b,
				      unsigned int bytes,
				      bool *equal,
				      unsigned int *first_diff)
{
	uint8_t result = 0;
	uint32_t completed = 0;

	if (hot_dsa_submit_ptr(ctx, DSA_OPCODE_COMPARE, a, b, NULL, bytes,
			       &result, &completed))
		return -1;
	if (ctx->profile)
		ctx->fg_compare_ops++;
	if (result == 0) {
		*equal = true;
		*first_diff = bytes;
		return 0;
	}
	if (completed >= bytes) {
		pr_err("DSA fine-grained compare returned invalid first_diff=%u bytes=%u\n",
		       completed, bytes);
		return -1;
	}
	*equal = false;
	*first_diff = completed;
	return 0;
}


static int write_full_fd(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t ret = write(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		p += ret;
		len -= ret;
	}

	return 0;
}

static int read_full_fd(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len) {
		ssize_t ret = read(fd, p, len);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		p += ret;
		len -= ret;
	}

	return 0;
}

/* Physical backing.  This is the only object allowed to own an FD or mmap.
 * A manifest line is deliberately not an owner: one backing may be referenced
 * by several address views after a VMA split or merge. */
struct hot_memstore_owner {
	int fd;
	void *map;
	size_t map_size;
	bool map_writable;
	bool created;
	dev_t dev;
	ino_t ino;
	char file[PATH_MAX];
};

/* Logical address coverage from the hot memory manifest. */
struct hot_memstore_seg {
	unsigned long img_id;
	unsigned long vaddr;
	unsigned long len;
	off_t off;
	size_t owner;
};

#define DSA_FG_PATCH_SIZE	128U
#define DSA_FG_MAX_PATCHES	8U
#define DSA_FG_MAX_BYTES	1024U
#define HOT_FG_WRITEV_MAX	1024U

static bool hot_mode_is_memstore(void)
{
	const char *mode = getenv("CRIU_DSA_HOT_MODE");

	return mode && strcmp(mode, "memstore") == 0;
}

static bool dsa_fine_grained_enabled(void)
{
	const char *enabled = getenv("CRIU_DSA_FINE_GRAINED");

	if (!enabled || !enabled[0])
		enabled = getenv("CRIU_DSA_WRITE_SIDE_FINE_GRAINED");

	return enabled && (!strcmp(enabled, "1") || !strcasecmp(enabled, "true") ||
			   !strcasecmp(enabled, "yes") || !strcasecmp(enabled, "on"));
}

static bool dsa_aligned_full_enabled(void)
{
	const char *format = getenv("CRIU_DSA_OUTPUT_FORMAT");

	return format && !strcasecmp(format, "full");
}

static bool dsa_direct_output_enabled_for_img(unsigned long img_id)
{
	const char *io = getenv("CRIU_DSA_OUTPUT_IO");
	const char *target = getenv("CRIU_DSA_MEMORY_SERVICE_IMG_ID");
	char *end = NULL;
	unsigned long long parsed;

	/* direct-sync is the default for the aligned full/fine comparison paths;
	 * an explicit buffered value is retained solely for old-image debugging. */
	if (io && strcasecmp(io, "direct-sync"))
		return false;
	if (!dsa_fine_grained_enabled() && !dsa_aligned_full_enabled())
		return false;
	if (!target || !target[0])
		return false;
	errno = 0;
	parsed = strtoull(target, &end, 10);
	return !errno && end && !*end && parsed == img_id;
}

static const char *hot_fg_compare_backend_name(enum hot_fg_compare_backend backend)
{
	switch (backend) {
	case HOT_FG_COMPARE_DSA:
		return "dsa";
	case HOT_FG_COMPARE_MEMCMP:
		return "memcmp";
	case HOT_FG_COMPARE_SCALAR64:
		return "scalar64";
	case HOT_FG_COMPARE_SIMD_AVX2:
		return "simd-avx2";
	case HOT_FG_COMPARE_SIMD_AVX512:
		return "simd-avx512";
	case HOT_FG_COMPARE_VALIDATE:
		return "validate";
	default:
		return "invalid";
	}
}

static bool hot_fg_cpu_supports_avx2(void)
{
#ifdef HOT_FG_HAVE_X86_SIMD
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx2");
#else
	return false;
#endif
}

static bool hot_fg_cpu_supports_avx512(void)
{
#ifdef HOT_FG_HAVE_X86_SIMD
	__builtin_cpu_init();
	return __builtin_cpu_supports("avx512f") &&
		__builtin_cpu_supports("avx512bw") &&
		__builtin_cpu_supports("avx512vl");
#else
	return false;
#endif
}

static int hot_fg_select_compare_backend(struct hot_apply_ctx *ctx)
{
	const char *value = getenv("CRIU_DSA_FG_COMPARE_BACKEND");
	enum hot_fg_compare_backend backend = HOT_FG_COMPARE_DSA;

	if (value && value[0]) {
		if (!strcasecmp(value, "dsa"))
			backend = HOT_FG_COMPARE_DSA;
		else if (!strcasecmp(value, "memcmp"))
			backend = HOT_FG_COMPARE_MEMCMP;
		else if (!strcasecmp(value, "scalar64"))
			backend = HOT_FG_COMPARE_SCALAR64;
		else if (!strcasecmp(value, "simd-avx2"))
			backend = HOT_FG_COMPARE_SIMD_AVX2;
		else if (!strcasecmp(value, "simd-avx512"))
			backend = HOT_FG_COMPARE_SIMD_AVX512;
		else if (!strcasecmp(value, "validate"))
			backend = HOT_FG_COMPARE_VALIDATE;
		else {
			pr_err("DSA fine-grained compare backend is invalid: %s\n", value);
			return -1;
		}
	}

	if (backend == HOT_FG_COMPARE_SIMD_AVX2 && !hot_fg_cpu_supports_avx2()) {
		pr_err("DSA fine-grained simd-avx2 backend requires AVX2\n");
		return -1;
	}
	if ((backend == HOT_FG_COMPARE_DSA ||
	     backend == HOT_FG_COMPARE_SIMD_AVX512 ||
	     backend == HOT_FG_COMPARE_VALIDATE) && !hot_fg_cpu_supports_avx512()) {
		pr_err("DSA fine-grained %s backend requires AVX-512F/BW/VL\n",
		       hot_fg_compare_backend_name(backend));
		return -1;
	}

	ctx->fg_compare_backend = backend;
	return 0;
}

static int hot_fg_open_sidecar(struct hot_apply_ctx *ctx)
{
	char path[64];
	int dfd = get_service_fd(IMG_FD_OFF);

	snprintf(path, sizeof(path), "pages-fg-%u.idx", ctx->pages_id);
	ctx->fg_idx_fd = openat(dfd, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				CR_FD_PERM);
	if (ctx->fg_idx_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", path);
		return -1;
	}

	snprintf(path, sizeof(path), "pages-fg-%u.dat", ctx->pages_id);
	ctx->fg_dat_fd = openat(dfd, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				CR_FD_PERM);
	if (ctx->fg_dat_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", path);
		close(ctx->fg_idx_fd);
		ctx->fg_idx_fd = -1;
		return -1;
	}
	ctx->fg_dat_off = 0;

	return 0;
}

static int hot_memstore_seg_cmp(const void *a, const void *b)
{
	const struct hot_memstore_seg *left = a;
	const struct hot_memstore_seg *right = b;

	if (left->img_id != right->img_id)
		return left->img_id < right->img_id ? -1 : 1;
	if (left->vaddr != right->vaddr)
		return left->vaddr < right->vaddr ? -1 : 1;
	return 0;
}

static size_t hot_memstore_lower_bound(struct hot_memstore_seg *segs, size_t nr,
				       unsigned long img_id, unsigned long vaddr)
{
	size_t lo = 0;
	size_t hi = nr;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		struct hot_memstore_seg *seg = &segs[mid];

		if (seg->img_id < img_id ||
		    (seg->img_id == img_id && seg->vaddr <= vaddr))
			lo = mid + 1;
		else
			hi = mid;
	}

	return lo;
}

static int hot_memstore_owner_add_fd(struct hot_apply_ctx *ctx, int fd,
				    const char *file, bool created, size_t *owner_out)
{
	struct stat st;
	struct hot_memstore_owner *owners;
	size_t i;

	if (fstat(fd, &st)) {
		pr_perror("DSA hot memstore backing fstat failed %s", file);
		return -1;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    (uint64_t)st.st_size > (uint64_t)(size_t)-1) {
		pr_err("DSA hot memstore backing is not a nonempty regular file %s\n", file);
		return -1;
	}
	for (i = 0; i < ctx->nr_owners; i++) {
		struct hot_memstore_owner *owner = &ctx->owners[i];

		if (owner->dev != st.st_dev || owner->ino != st.st_ino)
			continue;
		if (owner->map_size != (size_t)st.st_size) {
			pr_err("DSA hot memstore backing size changed while loading %s\n", file);
			return -1;
		}
		close(fd);
		*owner_out = i;
		return 0;
	}
	if (ctx->nr_owners == ctx->owners_cap) {
		size_t cap = ctx->owners_cap ? ctx->owners_cap * 2 : 128;

		owners = xrealloc(ctx->owners, cap * sizeof(*owners));
		if (!owners)
			return -1;
		ctx->owners = owners;
		ctx->owners_cap = cap;
	}
	ctx->owners[ctx->nr_owners] = (struct hot_memstore_owner) {
		.fd = fd,
		.map = MAP_FAILED,
		.map_size = (size_t)st.st_size,
		.created = created,
		.dev = st.st_dev,
		.ino = st.st_ino,
	};
	if (snprintf(ctx->owners[ctx->nr_owners].file,
		     sizeof(ctx->owners[ctx->nr_owners].file), "%s", file) >=
	    (int)sizeof(ctx->owners[ctx->nr_owners].file)) {
		pr_err("DSA hot memstore backing path too long\n");
		return -1;
	}
	*owner_out = ctx->nr_owners++;
	return 0;
}

static int hot_memstore_owner_open_existing(struct hot_apply_ctx *ctx,
					    const char *file, size_t *owner_out)
{
	int fd = open(file, O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		pr_perror("DSA hot memstore can't open backing %s", file);
		return -1;
	}
	if (hot_memstore_owner_add_fd(ctx, fd, file, false, owner_out)) {
		close(fd);
		return -1;
	}
	return 0;
}

static struct hot_memstore_owner *hot_memstore_owner_get(struct hot_apply_ctx *ctx,
							 size_t index)
{
	if (index >= ctx->nr_owners) {
		pr_err("DSA hot memstore invalid backing owner index=%zu count=%zu\n",
		       index, ctx->nr_owners);
		return NULL;
	}
	return &ctx->owners[index];
}

static void *hot_memstore_owner_map(struct hot_apply_ctx *ctx, size_t index)
{
	struct hot_memstore_owner *owner = hot_memstore_owner_get(ctx, index);

	if (!owner)
		return MAP_FAILED;
	if (owner->map && owner->map != MAP_FAILED)
		return owner->map;
	owner->map = mmap(NULL, owner->map_size, PROT_READ, MAP_SHARED, owner->fd, 0);
	if (owner->map == MAP_FAILED)
		pr_perror("DSA hot memstore can't mmap backing %s", owner->file);
	return owner->map;
}

static int hot_memstore_owner_make_writable(struct hot_apply_ctx *ctx, size_t index)
{
	struct hot_memstore_owner *owner = hot_memstore_owner_get(ctx, index);

	if (!owner || hot_memstore_owner_map(ctx, index) == MAP_FAILED)
		return -1;
	if (owner->map_writable)
		return 0;
	if (mprotect(owner->map, owner->map_size, PROT_READ | PROT_WRITE)) {
		pr_perror("DSA hot memstore can't make backing writable %s", owner->file);
		return -1;
	}
	owner->map_writable = true;
	if (ctx->profile)
		ctx->profile_hot_mprotect_ops++;
	return 0;
}

static int hot_memstore_load(struct hot_apply_ctx *ctx, const char *path,
			     struct hot_memstore_seg **segs_out, size_t *nr_out)
{
	FILE *fp;
	struct hot_memstore_seg *segs = NULL;
	size_t nr = 0, cap = 0;
	char line[PATH_MAX + 128];

	*segs_out = NULL;
	*nr_out = 0;
	if (!path || !path[0])
		return 0;

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT)
			return 0;
		pr_perror("DSA hot memstore can't open old manifest %s", path);
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		struct hot_memstore_seg seg;
		char file[PATH_MAX];
		unsigned long long off;
		int n;

		memset(&seg, 0, sizeof(seg));
		n = sscanf(line, "seg %lu %lx %lu %4095s %llu",
			   &seg.img_id, &seg.vaddr, &seg.len, file, &off);
		if (n != 5)
			continue;
		seg.off = (off_t)off;
		if (!seg.len || seg.vaddr > ULONG_MAX - seg.len ||
		    seg.vaddr & (PAGE_SIZE - 1) || seg.len & (PAGE_SIZE - 1) ||
		    seg.off < 0 || (seg.off & (PAGE_SIZE - 1)) ||
		    hot_memstore_owner_open_existing(ctx, file, &seg.owner))
			goto err;
		if ((uint64_t)seg.off > (uint64_t)ctx->owners[seg.owner].map_size ||
		    seg.len > ctx->owners[seg.owner].map_size - (size_t)seg.off) {
			pr_err("DSA hot memstore manifest extent exceeds backing %s\n", file);
			goto err;
		}

		if (nr == cap) {
			size_t new_cap = cap ? cap * 2 : 256;
			void *new_segs = xrealloc(segs, new_cap * sizeof(segs[0]));

			if (!new_segs)
				goto err;
			segs = new_segs;
			cap = new_cap;
		}
		segs[nr++] = seg;
	}

	fclose(fp);
	if (nr) {
		qsort(segs, nr, sizeof(segs[0]), hot_memstore_seg_cmp);
		for (cap = 1; cap < nr; cap++) {
			struct hot_memstore_seg *prev = &segs[cap - 1];
			struct hot_memstore_seg *cur = &segs[cap];

			if (prev->img_id == cur->img_id &&
			    (prev->vaddr + prev->len < prev->vaddr ||
			     prev->vaddr + prev->len > cur->vaddr)) {
				pr_err("DSA hot memstore manifest has overlapping views\n");
				xfree(segs);
				return -1;
			}
		}
	}
	*segs_out = segs;
	*nr_out = nr;
	return 0;

err:
	fclose(fp);
	xfree(segs);
	return -1;
}

static int hot_memstore_emit_line_fd(int fd, unsigned long img_id,
				     unsigned long vaddr, unsigned long len,
				     const char *file, off_t off)
{
	char line[PATH_MAX + 128];
	int n;

	n = snprintf(line, sizeof(line), "seg %lu %lx %lu %s %llu\n",
		     img_id, vaddr, len, file, (unsigned long long)off);
	if (n < 0 || n >= (int)sizeof(line)) {
		pr_err("DSA hot memstore manifest line overflow\n");
		return -1;
	}
	if (write_full_fd(fd, line, n)) {
		pr_perror("DSA hot memstore manifest append failed");
		return -1;
	}
	return 0;
}

static int hot_apply_mkdir_root(const char *root)
{
	if (mkdir(root, 0755) && errno != EEXIST) {
		pr_perror("DSA hot apply can't create %s", root);
		return -1;
	}

	return 0;
}

static int hot_memstore_mkdir_image(struct hot_apply_ctx *ctx, char *dir,
				    size_t dir_len)
{
	char memstore[PATH_MAX];

	if (snprintf(memstore, sizeof(memstore), "%s/memstore", ctx->hot_root) >=
	    (int)sizeof(memstore)) {
		pr_err("DSA hot memstore path too long\n");
		return -1;
	}
	if (hot_apply_mkdir_root(memstore))
		return -1;
	if (snprintf(dir, dir_len, "%s/image-%lu", memstore, ctx->img_id) >=
	    (int)dir_len) {
		pr_err("DSA hot memstore image path too long\n");
		return -1;
	}
	return hot_apply_mkdir_root(dir);
}

static int hot_memstore_create_vma_backing(struct hot_apply_ctx *ctx,
					   unsigned long start, unsigned long end,
					   size_t *owner_out)
{
	char dir[PATH_MAX];
	char path[PATH_MAX];
	unsigned long len = end - start;
	int fd;
	unsigned int attempt;

	if (hot_memstore_mkdir_image(ctx, dir, sizeof(dir)))
		return -1;
	for (attempt = 0; attempt < 1024; attempt++) {
		if (snprintf(path, sizeof(path), "%s/vma-%lx-%lx-%lu.mem", dir,
			     start, end, ctx->next_seq++) >= (int)sizeof(path)) {
			pr_err("DSA hot memstore VMA backing path too long\n");
			return -1;
		}
		fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
		if (fd >= 0)
			break;
		if (errno != EEXIST) {
			pr_perror("DSA hot memstore can't create VMA backing %s", path);
			return -1;
		}
	}
	if (attempt == 1024) {
		pr_err("DSA hot memstore couldn't allocate unique VMA backing\n");
		return -1;
	}
	if (ftruncate(fd, len)) {
		pr_perror("DSA hot memstore can't size VMA backing %s", path);
		close(fd);
		unlink(path);
		return -1;
	}
	if (hot_memstore_owner_add_fd(ctx, fd, path, true, owner_out)) {
		close(fd);
		unlink(path);
		return -1;
	}
	return 0;
}

static int hot_memstore_register_view(struct hot_apply_ctx *ctx,
					  unsigned long start, unsigned long end,
					  unsigned long vma_start, size_t owner, off_t off)
{
	struct hot_vma_segment seg;
	void *new_segments;

	if (start >= end || owner >= ctx->nr_owners || off < 0 ||
	    (uint64_t)off > (uint64_t)ctx->owners[owner].map_size ||
	    end - start > ctx->owners[owner].map_size - (size_t)off)
		return -1;
	if (ctx->nr_vma_segments) {
		struct hot_vma_segment *prev = &ctx->vma_segments[ctx->nr_vma_segments - 1];

		if (prev->end == start && prev->vma_start == vma_start &&
		    prev->owner == owner && prev->off + (off_t)(prev->end - prev->start) == off) {
			prev->end = end;
			return 0;
		}
	}

	if (ctx->nr_vma_segments == ctx->vma_segments_cap) {
		size_t new_cap = ctx->vma_segments_cap ? ctx->vma_segments_cap * 2 : 128;

		new_segments = xrealloc(ctx->vma_segments,
					new_cap * sizeof(ctx->vma_segments[0]));
		if (!new_segments)
			return -1;
		ctx->vma_segments = new_segments;
		ctx->vma_segments_cap = new_cap;
	}
	seg = (struct hot_vma_segment) {
		.start = start,
		.end = end,
		.vma_start = vma_start,
		.off = off,
		.owner = owner,
	};
	ctx->vma_segments[ctx->nr_vma_segments++] = seg;
	return 0;
}

static int hot_memstore_plan_segment(struct hot_apply_ctx *ctx,
				    unsigned long start, unsigned long end)
{
	struct hot_vma_plan *plans;
	size_t cap;

	if (start >= end || start & (PAGE_SIZE - 1) || end & (PAGE_SIZE - 1)) {
		pr_err("DSA hot memstore has invalid VMA plan %lx-%lx\n", start, end);
		return -1;
	}
	if (ctx->nr_vma_plans && start < ctx->vma_plans[ctx->nr_vma_plans - 1].end) {
		pr_err("DSA hot memstore VMA plan is not ordered/non-overlapping prev=%lx-%lx next=%lx-%lx\n",
		       ctx->vma_plans[ctx->nr_vma_plans - 1].start,
		       ctx->vma_plans[ctx->nr_vma_plans - 1].end, start, end);
		return -1;
	}
	if (ctx->nr_vma_plans == ctx->vma_plans_cap) {
		cap = ctx->vma_plans_cap ? ctx->vma_plans_cap * 2 : 128;
		plans = xrealloc(ctx->vma_plans, cap * sizeof(*plans));
		if (!plans)
			return -1;
		ctx->vma_plans = plans;
		ctx->vma_plans_cap = cap;
	}
	ctx->vma_plans[ctx->nr_vma_plans++] = (struct hot_vma_plan) {
		.start = start,
		.end = end,
	};
	return 0;
}

static struct hot_memstore_seg *hot_memstore_find_old_cover(struct hot_apply_ctx *ctx,
						    unsigned long start,
						    unsigned long end)
{
	size_t i = ctx->old_memstore_cursor;

	if (i >= ctx->nr_old_memstore ||
	    (i < ctx->nr_old_memstore &&
	     (ctx->old_memstore[i].img_id != ctx->img_id ||
	      start < ctx->old_memstore[i].vaddr))) {
		i = hot_memstore_lower_bound(ctx->old_memstore,
					    ctx->nr_old_memstore, ctx->img_id, start);
		if (i)
			i--;
	}

	for (; i < ctx->nr_old_memstore; i++) {
		struct hot_memstore_seg *old = &ctx->old_memstore[i];
		unsigned long old_end;

		if (old->img_id < ctx->img_id)
			continue;
		if (old->img_id > ctx->img_id)
			break;
		old_end = old->vaddr + old->len;
		if (old_end <= start)
			continue;
		if (old->vaddr <= start && old_end >= end) {
			ctx->old_memstore_cursor = i;
			return old;
		}
		if (old->vaddr > start)
			break;
	}
	ctx->old_memstore_cursor = i;
	return NULL;
}

static int hot_memstore_materialize_vmas(struct hot_apply_ctx *ctx,
					 size_t *failure_index,
					 unsigned long *failure_vaddr)
{
	size_t i;
	size_t old_i = 0;

	if (failure_index)
		*failure_index = SIZE_MAX;
	if (failure_vaddr)
		*failure_vaddr = ULONG_MAX;
	if (ctx->vmas_materialized)
		return 0;
	if (!ctx->nr_vma_plans) {
		pr_err("DSA hot memstore has no VMA plan for img_id=%lu\n", ctx->img_id);
		return -1;
	}
	if (!ctx->parent_view_loaded) {
		if (hot_memstore_load(ctx, ctx->memory_manifest_path, &ctx->old_memstore,
				       &ctx->nr_old_memstore))
			return -1;
		ctx->parent_view_loaded = true;
	}

	for (i = 0; i < ctx->nr_vma_plans; i++) {
		struct hot_vma_plan *plan = &ctx->vma_plans[i];
		unsigned long pos = plan->start;
		size_t gap_owner = (size_t)-1;

		while (old_i < ctx->nr_old_memstore &&
		       (ctx->old_memstore[old_i].img_id < ctx->img_id ||
			ctx->old_memstore[old_i].vaddr + ctx->old_memstore[old_i].len <= pos))
			old_i++;
		while (pos < plan->end) {
			struct hot_memstore_seg *old = NULL;
			unsigned long end;

			if (old_i < ctx->nr_old_memstore &&
			    ctx->old_memstore[old_i].img_id == ctx->img_id &&
			    ctx->old_memstore[old_i].vaddr <= pos &&
			    pos < ctx->old_memstore[old_i].vaddr + ctx->old_memstore[old_i].len)
				old = &ctx->old_memstore[old_i];
			if (old) {
				end = old->vaddr + old->len;
				if (end > plan->end)
					end = plan->end;
				if (hot_memstore_register_view(ctx, pos, end, plan->start,
							      old->owner,
							      old->off + (off_t)(pos - old->vaddr))) {
					if (failure_index)
						*failure_index = i;
					if (failure_vaddr)
						*failure_vaddr = plan->start;
					return -1;
				}
				pos = end;
				if (pos == old->vaddr + old->len)
					old_i++;
				continue;
			}
			end = plan->end;
			if (old_i < ctx->nr_old_memstore &&
			    ctx->old_memstore[old_i].img_id == ctx->img_id &&
			    ctx->old_memstore[old_i].vaddr > pos &&
			    ctx->old_memstore[old_i].vaddr < end)
				end = ctx->old_memstore[old_i].vaddr;
			if (gap_owner == (size_t)-1 &&
			    hot_memstore_create_vma_backing(ctx, plan->start, plan->end,
							     &gap_owner)) {
				if (failure_index)
					*failure_index = i;
				if (failure_vaddr)
					*failure_vaddr = plan->start;
				return -1;
			}
			if (hot_memstore_register_view(ctx, pos, end, plan->start,
						      gap_owner, (off_t)(pos - plan->start))) {
				if (failure_index)
					*failure_index = i;
				if (failure_vaddr)
					*failure_vaddr = plan->start;
				return -1;
			}
			pos = end;
		}
	}
	ctx->vmas_materialized = true;
	pr_info("DSA hot memstore VMA views materialized img_id=%lu views=%zu old_views=%zu owners=%zu\n",
		ctx->img_id, ctx->nr_vma_segments, ctx->nr_old_memstore, ctx->nr_owners);
	return 0;
}

static void *hot_memstore_old_map(struct hot_apply_ctx *ctx,
					  const struct hot_memstore_seg *old)
{
	struct hot_memstore_owner *owner = hot_memstore_owner_get(ctx, old->owner);
	void *map;

	if (!owner)
		return MAP_FAILED;
	map = hot_memstore_owner_map(ctx, old->owner);
	if (map == MAP_FAILED)
		return MAP_FAILED;
	return (char *)map + old->off;
}

static struct hot_apply_ctx *hot_apply_alloc_ctx(int fd_type,
						  unsigned long img_id, u32 pages_id)
{
	const char *root = getenv("CRIU_DSA_HOT_CURRENT_DIR");
	const char *hot_root = getenv("CRIU_DSA_HOT_ROOT");
	const char *manifest = getenv("CRIU_DSA_HOT_MANIFEST");
	const char *memory_manifest = getenv("CRIU_DSA_HOT_MEMORY_MANIFEST");
	const char *memory_next = getenv("CRIU_DSA_HOT_MEMORY_NEXT");
	struct hot_apply_ctx *ctx;
	int compare_breakdown = dsa_compare_breakdown_mode();

	if (compare_breakdown < 0) {
		pr_err("Invalid CRIU_DSA_COMPARE_BREAKDOWN (use unset/0/off or 1/true)\n");
		return NULL;
	}

	ctx = xzalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	hot_prq_profile_init(ctx);
	ctx->enabled = true;
	ctx->pipefd[0] = -1;
	ctx->pipefd[1] = -1;
	ctx->manifest_fd = -1;
	ctx->fg_idx_fd = -1;
	ctx->fg_dat_fd = -1;
	ctx->fd_type = fd_type;
	ctx->img_id = img_id;
	ctx->pages_id = pages_id;
	ctx->hot_root = hot_root && hot_root[0] ? hot_root : root;
	ctx->manifest_path = manifest;
	ctx->memory_manifest_path = memory_manifest;
	ctx->memory_next_path = memory_next;
	ctx->memstore = hot_mode_is_memstore();
	ctx->fine_output = ctx->memstore && dsa_fine_grained_enabled();
	/* Full-output control uses the same memstore transaction as fine output,
	 * but it never creates PARENT/PATCH/FULL compare results. */
	ctx->fine_grained = ctx->memstore &&
		(ctx->fine_output || dsa_aligned_full_enabled());
	ctx->profile = dsa_profile_enabled();
	ctx->compare_breakdown = compare_breakdown == 1;
	if (ctx->compare_breakdown && (!ctx->fine_output || !ctx->profile)) {
		pr_err("DSA compare breakdown requires fine-grained mode and CRIU_DSA_PROFILE=1\n");
		xfree(ctx);
		return NULL;
	}
	if (ctx->fine_output && hot_fg_select_compare_backend(ctx)) {
		xfree(ctx);
		return NULL;
	}
	return ctx;
}

void page_xfer_hot_cleanup_before_freeze(void)
{
	struct page_xfer xfer = {};

	if (!hot_apply_prepared)
		return;
	xfer.hot_apply = hot_apply_prepared;
	hot_apply_prepared = NULL;
	hot_apply_abort(&xfer);
}

int page_xfer_hot_prepare_before_freeze(unsigned long img_id)
{
	struct hot_apply_ctx *ctx;
	size_t i;
	u64 total_start_us = 0;
	u64 manifest_us = 0;
	u64 map_us = 0;
	u64 wq_us = 0;
	u64 parent_bytes = 0;
	u64 phase_start_us = 0;

	/* In task-service mode CDP has already completed SESSION_PREPARE and the
	 * service owns parent maps/WQ.  Recreating a local context here would both
	 * duplicate PTE population and undermine the long-lived mapping. */
	if (dsa_memory_service_client_fd() >= 0)
		return 0;
	if (!dsa_hot_apply_enabled() || !hot_mode_is_memstore() ||
	    !dsa_fine_grained_enabled())
		return 0;
	if (hot_apply_prepared) {
		pr_err("DSA fine-grained pre-freeze context already exists\n");
		return -1;
	}

	ctx = hot_apply_alloc_ctx(CR_FD_PAGEMAP, img_id, 0);
	if (!ctx)
		return -1;
	if (ctx->profile)
		total_start_us = dsa_profile_wall_now_us();
	if (ctx->fd_type != CR_FD_PAGEMAP || !ctx->hot_root || !ctx->hot_root[0]) {
		pr_err("DSA fine-grained pre-freeze context has no hot root\n");
		goto err;
	}

	/* The manifest describes the stable parent, not the target VMA.  Open and
	 * map it now, but deliberately do not touch all mapped parent pages. */
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (hot_memstore_load(ctx, ctx->memory_manifest_path, &ctx->old_memstore,
			       &ctx->nr_old_memstore))
		goto err;
	if (ctx->profile)
		manifest_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	ctx->parent_view_loaded = true;
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	for (i = 0; i < ctx->nr_old_memstore; i++) {
		if (hot_memstore_old_map(ctx, &ctx->old_memstore[i]) == MAP_FAILED)
			goto err;
		parent_bytes += ctx->old_memstore[i].len;
	}
	if (ctx->profile)
		map_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	/* WQ FDs/portals are immutable per round and must not be opened while the
	 * target is stopped.  The raw capture path has already validated MEMMOVE;
	 * this context owns the COMPARE portals used after thaw. */
	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if ((ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
	     ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE) &&
	    hot_dsa_open(ctx))
		goto err;
	if (ctx->profile)
		wq_us = dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	ctx->pre_freeze_ready = true;
	hot_apply_prepared = ctx;
	pr_info("DSA fine-grained pre-freeze parent view ready img_id=%lu segments=%zu wqs=%d backend=%s\n",
		img_id, ctx->nr_old_memstore, ctx->dsa_wq_count,
		hot_fg_compare_backend_name(ctx->fg_compare_backend));
	if (ctx->profile)
		pr_info("DSA_PRE_FREEZE_PROFILE: version=2 img_id=%lu backend=%s ret=0 total_us=%" PRIu64 " manifest_us=%" PRIu64 " parent_map_us=%" PRIu64 " wq_open_us=%" PRIu64 " parent_segments=%zu parent_bytes=%" PRIu64 " wqs=%d\n",
			img_id, hot_fg_compare_backend_name(ctx->fg_compare_backend),
			dsa_profile_delta_us(total_start_us, dsa_profile_wall_now_us()),
			manifest_us, map_us, wq_us, ctx->nr_old_memstore, parent_bytes,
			ctx->dsa_wq_count);
	return 0;

	err:
	if (ctx->profile)
		pr_info("DSA_PRE_FREEZE_PROFILE: version=2 img_id=%lu backend=%s ret=-1 total_us=%" PRIu64 " manifest_us=%" PRIu64 " parent_map_us=%" PRIu64 " wq_open_us=%" PRIu64 " parent_segments=%zu parent_bytes=%" PRIu64 " wqs=%d\n",
			img_id, hot_fg_compare_backend_name(ctx->fg_compare_backend),
			dsa_profile_delta_us(total_start_us, dsa_profile_wall_now_us()),
			manifest_us, map_us, wq_us, ctx->nr_old_memstore, parent_bytes,
			ctx->dsa_wq_count);
	{
		struct page_xfer xfer = {};

		xfer.hot_apply = ctx;
		hot_apply_abort(&xfer);
	}
	return -1;
}

static struct hot_vma_segment *hot_memstore_find_vma_segment(struct hot_apply_ctx *ctx,
							     unsigned long vaddr,
							     unsigned long len)
{
	size_t i = ctx->vma_segment_cursor;
	unsigned long end = vaddr + len;

	if (i >= ctx->nr_vma_segments ||
	    (i < ctx->nr_vma_segments && vaddr < ctx->vma_segments[i].start)) {
		size_t lo = 0;
		size_t hi = ctx->nr_vma_segments;

		while (lo < hi) {
			size_t mid = lo + (hi - lo) / 2;

			if (ctx->vma_segments[mid].start <= vaddr)
				lo = mid + 1;
			else
				hi = mid;
		}
		i = lo ? lo - 1 : 0;
	}

	for (; i < ctx->nr_vma_segments; i++) {
		struct hot_vma_segment *seg = &ctx->vma_segments[i];

		if (vaddr >= seg->start && end <= seg->end) {
			ctx->vma_segment_cursor = i;
			return seg;
		}
		if (seg->start > vaddr)
			break;
	}
	ctx->vma_segment_cursor = i;
	return NULL;
}

static int hot_memstore_map_segment_writable(struct hot_apply_ctx *ctx,
					     struct hot_vma_segment *seg)
{
	return hot_memstore_owner_make_writable(ctx, seg->owner);
}

static int hot_memstore_write_to_segments(struct hot_apply_ctx *ctx,
					  const void *buf,
					  unsigned long vaddr,
					  unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long cur = vaddr + done;
		unsigned long chunk;
		struct hot_vma_segment *seg;

		seg = hot_memstore_find_vma_segment(ctx, cur, 1);
		if (!seg) {
			pr_err("DSA hot memstore can't find VMA segment for write img_id=%lu vaddr=%lx len=%lu\n",
			       ctx->img_id, cur, len - done);
			return -1;
		}

		chunk = seg->end - cur;
		if (chunk > len - done)
			chunk = len - done;
		if (hot_memstore_map_segment_writable(ctx, seg))
			return -1;
		memcpy((char *)hot_memstore_owner_map(ctx, seg->owner) + seg->off +
		       (cur - seg->start),
		       (const char *)buf + done, chunk);
		if (ctx->profile) {
			ctx->profile_hot_memcpy_bytes += chunk;
		}
		done += chunk;
	}

	return 0;
}

/* The definition follows the shared batch sink.  Service mode consumes only
 * the release-published result array; it never rebuilds a compare plan. */
static int page_xfer_dsa_fg_write_sidecar_results(struct page_xfer *xfer,
						  const void *shared_ptr);

/* The frozen scanner leaves a compact VMA list in CRIU memory.  Service mode
 * copies that small control plane into the reserved tail of the same arena as
 * the raw capture, then places canonical results immediately after it.  Thus
 * neither VMA topology nor classified pages need a second shared mapping. */
static int dsa_memory_service_publish_vma_plan(struct page_xfer *xfer)
{
	const struct dsa_fg_vma_plan_record *plans = xfer->dsa_fg_vma_plan_local;
	u32 base = xfer->dsa_fg_result_meta_base;
	u64 bytes;
	u32 result_base;

	if (!xfer || !xfer->dsa_fg_service || !xfer->dsa_fg_shared ||
	    !plans || !xfer->dsa_fg_vma_plan_count)
		return -1;
	bytes = (u64)xfer->dsa_fg_vma_plan_count * sizeof(*plans);
	if (bytes > UINT_MAX || base > xfer->dsa_fg_result_meta_limit ||
	    bytes > xfer->dsa_fg_result_meta_limit - base)
		return -1;
	result_base = (base + (u32)bytes + 7U) & ~7U;
	if (result_base < base || result_base > xfer->dsa_fg_result_meta_limit ||
	    xfer->dsa_fg_result_meta_limit - result_base <
		sizeof(struct parasite_dsa_fg_result))
		return -1;
	memcpy((unsigned char *)xfer->dsa_fg_shared + base, plans, (size_t)bytes);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	xfer->dsa_fg_vma_plan_base = base;
	xfer->dsa_fg_vma_plan_head = base + (u32)bytes;
	xfer->dsa_fg_vma_plan_limit = result_base;
	xfer->dsa_fg_result_meta_base = result_base;
	xfer->dsa_fg_result_meta_head = result_base;
	return 0;
}

static int dsa_memory_service_compare(struct page_xfer *xfer)
{
	struct cdp_dsa_memory_service_msg msg = {
		.op = CDP_DSA_MS_COMPARE_REQ,
	};
	u64 phase_start_us = 0;
	bool profile = dsa_profile_enabled();
	int exchange_ret;

	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (dsa_memory_service_publish_vma_plan(xfer)) {
		pr_err("DSA memory service cannot publish VMA plan into raw arena\n");
		return -1;
	}
	if (profile) {
		xfer->dsa_fg_profile_request_publish_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
		phase_start_us = dsa_profile_wall_now_us();
	}
	msg.desc_off = xfer->dsa_fg_desc_area_off;
	msg.desc_head = xfer->dsa_fg_desc_head;
	msg.raw_off = xfer->dsa_fg_raw_payload_base;
	msg.raw_head = xfer->dsa_fg_raw_payload_head;
	msg.vma_plan_off = xfer->dsa_fg_vma_plan_base;
	msg.vma_plan_head = xfer->dsa_fg_vma_plan_head;
	msg.vma_plan_count = xfer->dsa_fg_vma_plan_count;
	msg.result_off = xfer->dsa_fg_result_meta_base;
	msg.result_limit = xfer->dsa_fg_result_meta_limit;
	exchange_ret = dsa_memory_service_client_exchange(
		xfer, &msg, CDP_DSA_MS_COMPARE_DONE, &xfer->dsa_fg_service_diag);
	if (profile)
		xfer->dsa_fg_profile_ipc_compare_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	if (exchange_ret) {
		pr_perror("DSA memory service COMPARE request failed");
		return -1;
	}
	if (msg.result_head < xfer->dsa_fg_result_meta_base ||
	    msg.result_head > xfer->dsa_fg_result_meta_limit ||
	    (msg.result_head - xfer->dsa_fg_result_meta_base) %
		sizeof(struct parasite_dsa_fg_result)) {
		pr_err("DSA memory service returned invalid compare result bounds\n");
		return -1;
	}
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	xfer->dsa_fg_result_meta_head = msg.result_head;
	xfer->dsa_fg_service_profile = msg.profile;
	return 0;
}

/* The frozen parasite has release-published descriptor and payload heads.
 * This is a small control-plane acknowledgement, not a copy or a second
 * scan: it makes the producer/consumer boundary explicit before post-thaw
 * compare or full materialisation starts. */
static int dsa_memory_service_raw_sealed(struct page_xfer *xfer)
{
	struct cdp_dsa_memory_service_msg msg = {
		.op = CDP_DSA_MS_RAW_SEALED,
		.desc_off = xfer->dsa_fg_desc_area_off,
		.desc_head = xfer->dsa_fg_desc_head,
		.raw_off = xfer->dsa_fg_raw_payload_base,
		.raw_head = xfer->dsa_fg_raw_payload_head,
	};

	__atomic_thread_fence(__ATOMIC_RELEASE);
	if (dsa_memory_service_client_exchange(xfer, &msg, CDP_DSA_MS_RAW_READY,
					       &xfer->dsa_fg_service_diag)) {
		pr_perror("DSA memory service RAW_SEALED request failed");
		return -1;
	}
	return 0;
}

static int dsa_memory_service_full_apply(struct page_xfer *xfer)
{
	struct cdp_dsa_memory_service_msg msg = {
		.op = CDP_DSA_MS_FULL_APPLY_REQ,
	};
	u64 phase_start_us = 0;
	bool profile = dsa_profile_enabled();

	if (dsa_memory_service_publish_vma_plan(xfer)) {
		pr_err("DSA memory service cannot publish full-output VMA plan\n");
		return -1;
	}
	msg.desc_off = xfer->dsa_fg_desc_area_off;
	msg.desc_head = xfer->dsa_fg_desc_head;
	msg.raw_off = xfer->dsa_fg_raw_payload_base;
	msg.raw_head = xfer->dsa_fg_raw_payload_head;
	msg.vma_plan_off = xfer->dsa_fg_vma_plan_base;
	msg.vma_plan_head = xfer->dsa_fg_vma_plan_head;
	msg.vma_plan_count = xfer->dsa_fg_vma_plan_count;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (dsa_memory_service_client_exchange(xfer, &msg,
					       CDP_DSA_MS_FULL_APPLY_DONE,
					       &xfer->dsa_fg_service_diag)) {
		pr_perror("DSA memory service FULL_APPLY request failed");
		return -1;
	}
	if (profile) {
		xfer->dsa_fg_profile_ipc_apply_us +=
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
		xfer->dsa_fg_service_profile = msg.profile;
	}
	return 0;
}

static int dsa_memory_service_apply(struct page_xfer *xfer)
{
	struct cdp_dsa_memory_service_msg msg = {
		.op = CDP_DSA_MS_APPLY_REQ,
		.desc_off = xfer->dsa_fg_desc_area_off,
		.desc_head = xfer->dsa_fg_desc_head,
		.raw_off = xfer->dsa_fg_raw_payload_base,
		.raw_head = xfer->dsa_fg_raw_payload_head,
		.result_off = xfer->dsa_fg_result_meta_base,
		.result_head = xfer->dsa_fg_result_meta_head,
		.result_limit = xfer->dsa_fg_result_meta_limit,
	};
	u64 phase_start_us = 0;
	bool profile = dsa_profile_enabled();
	int exchange_ret;

	msg.profile = xfer->dsa_fg_service_profile;
	if (profile)
		msg.result_count = (xfer->dsa_fg_result_meta_head -
				    xfer->dsa_fg_result_meta_base) /
				   sizeof(struct parasite_dsa_fg_result);
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	exchange_ret = dsa_memory_service_client_exchange(
		xfer, &msg, CDP_DSA_MS_APPLY_DONE, &xfer->dsa_fg_service_diag);
	if (profile) {
		xfer->dsa_fg_profile_ipc_apply_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
		if (xfer->dsa_fg_service_diag.magic ==
		    CDP_DSA_MEMORY_SERVICE_DIAG_MAGIC) {
			msg.profile.hot_apply_us =
				xfer->dsa_fg_service_diag.apply_total_wall_us;
			msg.profile.hot_apply_cpu_us =
				xfer->dsa_fg_service_diag.apply_total_cpu_us;
			xfer->dsa_fg_service_profile = msg.profile;
		}
	}
	if (exchange_ret) {
		pr_perror("DSA memory service APPLY request failed");
		return -1;
	}
	if (profile)
		xfer->dsa_fg_service_profile = msg.profile;
	return 0;
}

static int splice_exact_at(int in, int out, off_t off, unsigned long len);

static bool hot_memstore_should_track_vma(struct vma_area *vma)
{
	VmaEntry *e = vma->e;

	if (vma_area_is(vma, VMA_AREA_GUARD))
		return false;
	if (vma_entry_is(e, VMA_AREA_VSYSCALL))
		return false;
	if (e->flags & MAP_HUGETLB)
		return false;
	if (e->start >= kdat.task_size || e->end > kdat.task_size)
		return false;
	return true;
}

static int hot_memstore_splice_to_segments(struct hot_apply_ctx *ctx, int pipefd,
					   unsigned long vaddr,
					   unsigned long len)
{
	unsigned long done = 0;

	while (done < len) {
		unsigned long cur = vaddr + done;
		unsigned long chunk;
		struct hot_vma_segment *seg;

		seg = hot_memstore_find_vma_segment(ctx, cur, 1);
		if (!seg) {
			pr_err("DSA hot memstore can't find VMA segment img_id=%lu vaddr=%lx len=%lu range=%lx-%lx\n",
			       ctx->img_id, cur, len - done, vaddr, vaddr + len);
			return -1;
		}

		chunk = seg->end - cur;
		if (chunk > len - done)
			chunk = len - done;
		if (splice_exact_at(pipefd, ctx->owners[seg->owner].fd,
				    seg->off + (cur - seg->start), chunk))
			return -1;
		done += chunk;
	}

	return 0;
}

static int splice_exact_at(int in, int out, off_t off, unsigned long len)
{
	unsigned long curr = 0;

	while (curr < len) {
		loff_t pos = off + curr;
		ssize_t ret = splice(in, NULL, out, &pos, len - curr, SPLICE_F_MOVE);

		if (ret == -1) {
			pr_perror("Unable to splice pages data at offset");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
	}

	return 0;
}

static int hot_apply_write_manifest(const char *path, const char *state)
{
	char tmp[PATH_MAX];
	char body[256];
	int fd;
	int n;

	if (!path || !path[0])
		return 0;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
		pr_err("DSA hot apply manifest path is too long: %s\n", path);
		return -1;
	}

	fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		pr_perror("DSA hot apply can't open manifest %s", tmp);
		return -1;
	}

	n = snprintf(body, sizeof(body), "{\n  \"state\": \"%s\"\n}\n", state);
	if (n < 0 || n >= (int)sizeof(body)) {
		close(fd);
		unlink(tmp);
		pr_err("DSA hot apply manifest body overflow\n");
		return -1;
	}
	if (write_full_fd(fd, body, n)) {
		pr_perror("DSA hot apply manifest write failed");
		close(fd);
		unlink(tmp);
		return -1;
	}
	if (close(fd)) {
		pr_perror("DSA hot apply manifest close failed");
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path)) {
		pr_perror("DSA hot apply manifest rename failed");
		unlink(tmp);
		return -1;
	}

	return 0;
}


static void hot_apply_abort(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	size_t i;

	if (!ctx)
		return;

	if (ctx->pipefd[1] >= 0) {
		close(ctx->pipefd[1]);
		ctx->pipefd[1] = -1;
	}
	if (!ctx->finished)
		(void)hot_apply_write_manifest(ctx->manifest_path, "failed");
	hot_dsa_close(ctx);
	if (ctx->pipefd[0] >= 0)
		close(ctx->pipefd[0]);
	if (ctx->manifest_fd >= 0)
		close(ctx->manifest_fd);
	if (ctx->fg_idx_fd >= 0)
		close(ctx->fg_idx_fd);
	if (ctx->fg_dat_fd >= 0)
		close(ctx->fg_dat_fd);
	for (i = 0; i < ctx->nr_owners; i++) {
		if (ctx->owners[i].map && ctx->owners[i].map != MAP_FAILED)
			munmap(ctx->owners[i].map, ctx->owners[i].map_size);
		if (ctx->owners[i].fd >= 0)
			close(ctx->owners[i].fd);
	}

	xfree(ctx->owners);
	xfree(ctx->old_memstore);
	xfree(ctx->vma_segments);
	xfree(ctx->vma_plans);
	xfree(ctx->pagemap_plan);
	free(ctx->compare_batches);
	xfree(ctx);
	xfer->hot_apply = NULL;
}

static int hot_memstore_finish(struct hot_apply_ctx *ctx)
{
	size_t i;
	int ret = -1;
	uint64_t producer_time_us;
	uint64_t total_hot_work_us;

	if (ctx->manifest_fd < 0) {
		pr_err("DSA hot memstore manifest fd is not open\n");
		goto out;
	}
	if (!ctx->nr_vma_segments) {
		pr_err("DSA hot memstore has no VMA segments for img_id=%lu\n",
		       ctx->img_id);
		goto out;
	}

	for (i = 0; i < ctx->nr_vma_segments; i++) {
		struct hot_vma_segment *seg = &ctx->vma_segments[i];
		struct hot_memstore_owner *owner = hot_memstore_owner_get(ctx, seg->owner);

		if (!owner)
			goto out;
		if (hot_memstore_emit_line_fd(ctx->manifest_fd, ctx->img_id,
					      seg->start, seg->end - seg->start,
					      owner->file, seg->off))
			goto out;
	}

	ctx->memstore_segments = ctx->nr_vma_segments;
	producer_time_us = ctx->append_time_us;
	total_hot_work_us = ctx->append_time_us;
	if (dsa_debug_enabled())
		pr_info("DSA hot memstore updated img_id=%lu entries=%zu bytes=%" PRIu64 " vma_segments=%" PRIu64 " append_time_us=%" PRIu64 " producer_time_us=%" PRIu64 " tee_us=%" PRIu64 " write_us=%" PRIu64 " fg_pages=%" PRIu64 " fg_patch_pages=%" PRIu64 " fg_full_pages=%" PRIu64 " fg_patch_bytes=%" PRIu64 " fg_compare_ops=%" PRIu64 " enqueue_wait_us=%" PRIu64 " worker_wait_us=%" PRIu64 " worker_join_us=%" PRIu64 " queue_max=%" PRIu64 " pipe_size=%" PRIu64 "\n",
		ctx->img_id, ctx->nr_entries, ctx->memstore_bytes,
		ctx->memstore_segments, total_hot_work_us, producer_time_us,
		ctx->append_tee_us, ctx->append_splice_us,
		ctx->fg_pages, ctx->fg_patch_pages, ctx->fg_full_pages,
		ctx->fg_patch_bytes, ctx->fg_compare_ops,
		ctx->append_enqueue_wait_us,
		ctx->worker_wait_us, ctx->worker_join_us,
		ctx->worker_queue_max, ctx->worker_pipe_size);
	ret = 0;

out:
	return ret;
}

static int hot_apply_prepare_post_thaw(struct hot_apply_ctx *ctx)
{
	int dfd;
	u64 materialize_start_us = 0;

	if (ctx->post_thaw_ready)
		return 0;
	if (hot_apply_mkdir_root(ctx->hot_root))
		return -1;
	if (ctx->pipefd[0] < 0 && pipe2(ctx->pipefd, O_CLOEXEC)) {
		pr_perror("DSA hot apply can't create pipe");
		return -1;
	}
	/* Fine-grained output has a compare/sidecar barrier and materializes only
	 * immediately before hot apply below.  Preserve the ordinary memstore
	 * splice path, which needs its destination views before it can consume the
	 * pipe. */
	if (!ctx->fine_grained) {
		if (ctx->profile)
			materialize_start_us = dsa_profile_wall_now_us();
		if (hot_memstore_materialize_vmas(ctx, NULL, NULL))
			return -1;
		if (ctx->profile)
			ctx->profile_materialize_us += dsa_profile_delta_us(materialize_start_us,
								      dsa_profile_wall_now_us());
	}
	if (ctx->fine_output) {
		if (hot_fg_open_sidecar(ctx))
			return -1;
		if (!ctx->pre_freeze_ready &&
		    (ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
		     ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE) &&
		    hot_dsa_open(ctx))
			return -1;
	}
	if (!ctx->memory_next_path || !ctx->memory_next_path[0]) {
		pr_err("DSA hot memstore requires CRIU_DSA_HOT_MEMORY_NEXT\n");
		return -1;
	}
	dfd = get_service_fd(IMG_FD_OFF);
	ctx->manifest_fd = openat(dfd, ctx->memory_next_path,
				  O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, CR_FD_PERM);
	if (ctx->manifest_fd < 0) {
		pr_perror("DSA hot memstore can't open next manifest %s",
			  ctx->memory_next_path);
		return -1;
	}
	ctx->post_thaw_ready = true;
	return 0;
}

static int hot_fg_validate_sidecar(struct hot_apply_ctx *ctx)
{
	struct stat idx_st;
	struct stat dat_st;
	u64 idx_expected;

	if (!ctx->fine_output)
		return 0;
	if (ctx->fg_idx_fd < 0 || ctx->fg_dat_fd < 0 || ctx->fg_dat_off < 0)
		return -1;
	if (fstat(ctx->fg_idx_fd, &idx_st) || fstat(ctx->fg_dat_fd, &dat_st)) {
		pr_perror("DSA fine-grained sidecar fstat failed");
		return -1;
	}
	idx_expected = ctx->fg_pages * sizeof(struct dsa_fg_page_meta);
	if ((u64)idx_st.st_size != idx_expected ||
	    (u64)dat_st.st_size != (u64)ctx->fg_dat_off) {
		pr_err("DSA fine-grained sidecar size mismatch idx=%" PRIu64 "/%" PRIu64
		       " dat=%" PRIu64 "/%" PRIu64 "\n",
		       (u64)idx_st.st_size, idx_expected, (u64)dat_st.st_size,
		       (u64)ctx->fg_dat_off);
		return -1;
	}
	return 0;
}

static int hot_apply_finish(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	int ret = 0;

	if (!ctx || ctx->finished)
		return 0;

	ctx->finished = true;

	if (ctx->pipefd[1] >= 0) {
		close(ctx->pipefd[1]);
		ctx->pipefd[1] = -1;
	}
	if (ctx->pipefd[0] >= 0) {
		close(ctx->pipefd[0]);
		ctx->pipefd[0] = -1;
	}
	if (ret == 0 && hot_fg_validate_sidecar(ctx))
		ret = -1;
	if (ret == 0 && hot_memstore_finish(ctx))
		ret = -1;
	if (ctx->manifest_fd >= 0) {
		if (close(ctx->manifest_fd)) {
			pr_perror("DSA hot memstore manifest close failed");
			ret = -1;
		}
		ctx->manifest_fd = -1;
	}
	if (ctx->fg_idx_fd >= 0) {
		if (close(ctx->fg_idx_fd)) {
			pr_perror("DSA fine-grained index close failed");
			ret = -1;
		}
		ctx->fg_idx_fd = -1;
	}
	if (ctx->fg_dat_fd >= 0) {
		if (close(ctx->fg_dat_fd)) {
			pr_perror("DSA fine-grained data close failed");
			ret = -1;
		}
		ctx->fg_dat_fd = -1;
	}
	return ret;
}

static void hot_profile_begin(struct hot_apply_ctx *ctx)
{
	if (!ctx || !ctx->profile || ctx->profile_started)
		return;
	ctx->profile_started = true;
	ctx->profile_total_start_us = dsa_profile_wall_now_us();
}

/*
 * A task-scoped service reuses one hot_apply_ctx for every generation, unlike
 * the legacy CRIU path which allocates a fresh context per dump.  Reset only
 * generation-local accounting here; WQ mappings, parent mappings and PRQ perf
 * fds are deliberately retained.
 */
static void hot_service_profile_reset_generation(struct hot_apply_ctx *ctx)
{
	if (!ctx || !ctx->profile)
		return;

	ctx->profile_started = false;
	ctx->profile_emitted = false;
	ctx->profile_total_start_us = 0;
	ctx->profile_post_prepare_us = 0;
	ctx->profile_materialize_us = 0;
	ctx->profile_raw_index_us = 0;
	ctx->profile_span_build_us = 0;
	ctx->profile_compare_wall_us = 0;
	ctx->profile_compare_cpu_us = 0;
	ctx->profile_sidecar_emit_us = 0;
	ctx->profile_compare_engine_wall_us = 0;
	ctx->profile_compare_engine_cpu_us = 0;
	ctx->profile_parent_prefault_wall_us = 0;
	ctx->profile_parent_prefault_cpu_us = 0;
	ctx->profile_compare_core_wall_us = 0;
	ctx->profile_compare_core_cpu_us = 0;
	ctx->profile_output_wall_us = 0;
	ctx->profile_output_start_us = 0;
	ctx->profile_hot_apply_us = 0;
	ctx->profile_pagemap_us = 0;
	ctx->profile_finish_us = 0;
	ctx->profile_raw_pages = 0;
	ctx->profile_raw_bytes = 0;
	ctx->profile_capture_runs = 0;
	ctx->profile_span_pages = 0;
	ctx->profile_spans = 0;
	ctx->profile_max_span_pages = 0;
	ctx->profile_compare_enq_retries = 0;
	ctx->profile_compare_poll_sweeps = 0;
	ctx->profile_compare_not_ready = 0;
	ctx->profile_compare_max_active = 0;
	ctx->profile_batch_outer_submits = 0;
	ctx->profile_batch_child_submits = 0;
	ctx->profile_batch_partial_submits = 0;
	ctx->profile_batch_single_tail_submits = 0;
	ctx->profile_batch_outer_success = 0;
	ctx->profile_batch_outer_fail = 0;
	ctx->profile_batch_child_success = 0;
	ctx->profile_batch_child_nobof = 0;
	ctx->profile_batch_max_active_outer = 0;
	ctx->profile_batch_max_active_children = 0;
	ctx->profile_completions_harvested = 0;
	ctx->profile_completion_timeout_count = 0;
	ctx->profile_max_completion_age_us = 0;
	ctx->profile_write_units = 0;
	ctx->profile_write_unit_max_us = 0;
	ctx->profile_memcmp_calls = 0;
	ctx->profile_memcmp_requested_bytes = 0;
	ctx->profile_memcmp_scalar_bytes = 0;
	ctx->profile_scalar64_calls = 0;
	ctx->profile_scalar64_word_ops = 0;
	ctx->profile_scalar64_refine_bytes = 0;
	ctx->profile_scalar64_tail_bytes = 0;
	ctx->profile_scalar64_bytes_examined = 0;
	ctx->profile_simd_vector_ops = 0;
	ctx->profile_simd_bytes_examined = 0;
	ctx->profile_hybrid_dsa_claim_spans = 0;
	ctx->profile_hybrid_dsa_claim_pages = 0;
	ctx->profile_hybrid_cpu_claim_spans = 0;
	ctx->profile_hybrid_cpu_claim_pages = 0;
	ctx->profile_hybrid_cpu_waves = 0;
	ctx->profile_hybrid_dsa_to_cpu_handoff_spans = 0;
	ctx->profile_hybrid_dsa_to_cpu_handoff_pages = 0;
	ctx->profile_hybrid_dsa_to_cpu_handoff_remaining_bytes = 0;
	ctx->profile_hybrid_unclaimed_empty_count = 0;
	ctx->profile_compare_nobof_faults = 0;
	ctx->profile_compare_nobof_fault_source1 = 0;
	ctx->profile_compare_nobof_fault_source2 = 0;
	ctx->profile_compare_nobof_equal_prefix_bytes = 0;
	ctx->profile_compare_fault_handoff_spans = 0;
	ctx->profile_compare_fault_handoff_pages = 0;
	ctx->profile_compare_fault_handoff_remaining_bytes = 0;
	ctx->profile_compare_fault_queue_max = 0;
	ctx->profile_compare_fresh_claim_throttles = 0;
	ctx->profile_compare_cpu_fault_waves = 0;
	ctx->profile_dsa_logical_progress_bytes = 0;
	ctx->profile_simd_logical_progress_bytes = 0;
	ctx->profile_normal_simd_logical_progress_bytes = 0;
	ctx->profile_fault_simd_logical_progress_bytes = 0;
	ctx->profile_dsa_fresh_submit_ops = 0;
	ctx->profile_dsa_continuation_submit_ops = 0;
	ctx->profile_dsa_submitted_bytes = 0;
	ctx->profile_simd_progress_while_dsa_active_bytes = 0;
	ctx->profile_simd_quanta_while_dsa_active = 0;
	ctx->profile_dsa_fresh_claim_bytes = 0;
	ctx->profile_dsa_active_zero_while_normal_cpu_work = 0;
	ctx->profile_ready_completions_before_simd = 0;
	ctx->profile_ready_completions_after_simd = 0;
	ctx->profile_scheduler_iterations = 0;
	ctx->profile_dsa_refill_samples = 0;
	ctx->profile_post_refill_active_sum = 0;
	ctx->profile_post_refill_active_lt_32 = 0;
	ctx->profile_post_refill_active_lt_64 = 0;
	ctx->profile_post_refill_active_lt_96 = 0;
	ctx->profile_fresh_refill_spans = 0;
	ctx->profile_fresh_refill_batches = 0;
	ctx->profile_fresh_refill_blocked_fault_debt = 0;
	ctx->profile_dsa_empty_with_claimable_fresh = 0;
	ctx->profile_prq_pg_requests = 0;
	ctx->profile_prq_thread_cpu_us = 0;
	ctx->profile_prefault_spans = 0;
	ctx->profile_prefault_pages = 0;
	ctx->profile_parent_pages = 0;
	ctx->profile_patch_ranges = 0;
	ctx->profile_idx_writes = 0;
	ctx->profile_dat_writes = 0;
	ctx->profile_dat_writevs = 0;
	ctx->profile_hot_pwrite_ops = 0;
	ctx->profile_hot_pwrite_bytes = 0;
	ctx->profile_hot_mprotect_ops = 0;
	ctx->profile_hot_memcpy_bytes = 0;

	ctx->fg_pages = 0;
	ctx->fg_patch_pages = 0;
	ctx->fg_full_pages = 0;
	ctx->fg_patch_bytes = 0;
	ctx->fg_compare_ops = 0;
	ctx->dsa_enqcmd = 0;
}

static void hot_service_profile_snapshot(
	struct hot_apply_ctx *ctx, struct cdp_dsa_memory_service_profile *profile)
{
	if (!ctx || !profile)
		return;

	profile->enabled = ctx->profile ? 1 : 0;
	profile->backend = ctx->fg_compare_backend;
	profile->prq_profile_available = ctx->profile_prq_available ? 1 : 0;
	profile->prq_profile_sources = ctx->profile_nr_prq_sources;
	profile->prq_setup_errno = ctx->profile_prq_setup_errno;
	if (!ctx->profile)
		return;

	profile->raw_index_us = ctx->profile_raw_index_us;
	profile->span_build_us = ctx->profile_span_build_us;
	profile->compare_wall_us = ctx->profile_compare_wall_us;
	profile->compare_cpu_us = ctx->profile_compare_cpu_us;
	profile->compare_engine_wall_us = ctx->profile_compare_engine_wall_us;
	profile->compare_engine_cpu_us = ctx->profile_compare_engine_cpu_us;
	profile->result_publish_us = ctx->profile_sidecar_emit_us;
	profile->parent_prefault_wall_us = ctx->profile_parent_prefault_wall_us;
	profile->parent_prefault_cpu_us = ctx->profile_parent_prefault_cpu_us;
	profile->compare_core_wall_us = ctx->profile_compare_core_wall_us;
	profile->compare_core_cpu_us = ctx->profile_compare_core_cpu_us;
	profile->raw_pages = ctx->profile_raw_pages;
	profile->raw_bytes = ctx->profile_raw_bytes;
	profile->capture_runs = ctx->profile_capture_runs;
	profile->spans = ctx->profile_spans;
	profile->span_pages = ctx->profile_span_pages;
	profile->max_span_pages = ctx->profile_max_span_pages;
	profile->compare_ops = ctx->fg_compare_ops;
	profile->enq_retries = ctx->profile_compare_enq_retries;
	profile->poll_sweeps = ctx->profile_compare_poll_sweeps;
	profile->not_ready = ctx->profile_compare_not_ready;
	profile->max_active = ctx->profile_compare_max_active;
	profile->batch_outer_submits = ctx->profile_batch_outer_submits;
	profile->batch_child_submits = ctx->profile_batch_child_submits;
	profile->batch_partial_submits = ctx->profile_batch_partial_submits;
	profile->batch_single_tail_submits =
		ctx->profile_batch_single_tail_submits;
	profile->batch_outer_success = ctx->profile_batch_outer_success;
	profile->batch_outer_fail = ctx->profile_batch_outer_fail;
	profile->batch_child_success = ctx->profile_batch_child_success;
	profile->batch_child_nobof = ctx->profile_batch_child_nobof;
	profile->batch_max_active_outer = ctx->profile_batch_max_active_outer;
	profile->batch_max_active_children = ctx->profile_batch_max_active_children;
	profile->completions_harvested = ctx->profile_completions_harvested;
	profile->completion_timeout_count = ctx->profile_completion_timeout_count;
	profile->max_completion_age_us = ctx->profile_max_completion_age_us;
	profile->prefault_spans = ctx->profile_prefault_spans;
	profile->prefault_pages = ctx->profile_prefault_pages;
	profile->parent_pages = ctx->profile_parent_pages;
	profile->patch_pages = ctx->fg_patch_pages;
	profile->full_pages = ctx->fg_full_pages;
	profile->patch_ranges = ctx->profile_patch_ranges;
	profile->patch_bytes = ctx->fg_patch_bytes;
	profile->prq_pg_requests = ctx->profile_prq_pg_requests;
	profile->prq_thread_cpu_us = ctx->profile_prq_thread_cpu_us;
	profile->memcmp_calls = ctx->profile_memcmp_calls;
	profile->memcmp_requested_bytes = ctx->profile_memcmp_requested_bytes;
	profile->memcmp_scalar_bytes = ctx->profile_memcmp_scalar_bytes;
	profile->scalar64_calls = ctx->profile_scalar64_calls;
	profile->scalar64_word_ops = ctx->profile_scalar64_word_ops;
	profile->scalar64_refine_bytes = ctx->profile_scalar64_refine_bytes;
	profile->scalar64_tail_bytes = ctx->profile_scalar64_tail_bytes;
	profile->scalar64_bytes_examined = ctx->profile_scalar64_bytes_examined;
	profile->simd_vector_ops = ctx->profile_simd_vector_ops;
	profile->simd_bytes_examined = ctx->profile_simd_bytes_examined;
	profile->hybrid_dsa_claim_spans = ctx->profile_hybrid_dsa_claim_spans;
	profile->hybrid_dsa_claim_pages = ctx->profile_hybrid_dsa_claim_pages;
	profile->hybrid_cpu_claim_spans = ctx->profile_hybrid_cpu_claim_spans;
	profile->hybrid_cpu_claim_pages = ctx->profile_hybrid_cpu_claim_pages;
	profile->hybrid_cpu_waves = ctx->profile_hybrid_cpu_waves;
	profile->hybrid_dsa_to_cpu_handoff_spans =
		ctx->profile_hybrid_dsa_to_cpu_handoff_spans;
	profile->hybrid_dsa_to_cpu_handoff_pages =
		ctx->profile_hybrid_dsa_to_cpu_handoff_pages;
	profile->hybrid_dsa_to_cpu_handoff_remaining_bytes =
		ctx->profile_hybrid_dsa_to_cpu_handoff_remaining_bytes;
	profile->hybrid_unclaimed_empty_count =
		ctx->profile_hybrid_unclaimed_empty_count;
	profile->compare_nobof_faults = ctx->profile_compare_nobof_faults;
	profile->compare_nobof_fault_source1 = ctx->profile_compare_nobof_fault_source1;
	profile->compare_nobof_fault_source2 = ctx->profile_compare_nobof_fault_source2;
	profile->compare_nobof_equal_prefix_bytes =
		ctx->profile_compare_nobof_equal_prefix_bytes;
	profile->compare_fault_handoff_spans = ctx->profile_compare_fault_handoff_spans;
	profile->compare_fault_handoff_pages = ctx->profile_compare_fault_handoff_pages;
	profile->compare_fault_handoff_remaining_bytes =
		ctx->profile_compare_fault_handoff_remaining_bytes;
	profile->compare_fault_queue_max = ctx->profile_compare_fault_queue_max;
	profile->compare_fresh_claim_throttles =
		ctx->profile_compare_fresh_claim_throttles;
	profile->compare_cpu_fault_waves = ctx->profile_compare_cpu_fault_waves;
	profile->dsa_logical_progress_bytes =
		ctx->profile_dsa_logical_progress_bytes;
	profile->simd_logical_progress_bytes =
		ctx->profile_simd_logical_progress_bytes;
	profile->normal_simd_logical_progress_bytes =
		ctx->profile_normal_simd_logical_progress_bytes;
	profile->fault_simd_logical_progress_bytes =
		ctx->profile_fault_simd_logical_progress_bytes;
	profile->dsa_fresh_submit_ops = ctx->profile_dsa_fresh_submit_ops;
	profile->dsa_continuation_submit_ops =
		ctx->profile_dsa_continuation_submit_ops;
	profile->dsa_submitted_bytes = ctx->profile_dsa_submitted_bytes;
	profile->simd_progress_while_dsa_active_bytes =
		ctx->profile_simd_progress_while_dsa_active_bytes;
	profile->simd_quanta_while_dsa_active =
		ctx->profile_simd_quanta_while_dsa_active;
	profile->dsa_fresh_claim_bytes = ctx->profile_dsa_fresh_claim_bytes;
	profile->dsa_active_zero_while_normal_cpu_work =
		ctx->profile_dsa_active_zero_while_normal_cpu_work;
	profile->ready_completions_before_simd =
		ctx->profile_ready_completions_before_simd;
	profile->ready_completions_after_simd =
		ctx->profile_ready_completions_after_simd;
	profile->scheduler_iterations = ctx->profile_scheduler_iterations;
	profile->dsa_refill_samples = ctx->profile_dsa_refill_samples;
	profile->post_refill_active_sum = ctx->profile_post_refill_active_sum;
	profile->post_refill_active_lt_32 = ctx->profile_post_refill_active_lt_32;
	profile->post_refill_active_lt_64 = ctx->profile_post_refill_active_lt_64;
	profile->post_refill_active_lt_96 = ctx->profile_post_refill_active_lt_96;
	profile->fresh_refill_spans = ctx->profile_fresh_refill_spans;
	profile->fresh_refill_batches = ctx->profile_fresh_refill_batches;
	profile->fresh_refill_blocked_fault_debt =
		ctx->profile_fresh_refill_blocked_fault_debt;
	profile->dsa_empty_with_claimable_fresh =
		ctx->profile_dsa_empty_with_claimable_fresh;
}

static void hot_profile_emit(struct hot_apply_ctx *ctx, int ret)
{
	const char *backend;
	u64 total_us;
	u64 accounted_us;
	u64 unaccounted_us;
	u64 idx_bytes;
	u64 dat_bytes;

	if (!ctx || !ctx->profile || !ctx->profile_started || ctx->profile_emitted)
		return;
	backend = hot_fg_compare_backend_name(ctx->fg_compare_backend);

	total_us = dsa_profile_delta_us(ctx->profile_total_start_us,
					 dsa_profile_wall_now_us());
	accounted_us = ctx->profile_post_prepare_us + ctx->profile_raw_index_us +
		ctx->profile_span_build_us + ctx->profile_compare_wall_us +
		ctx->profile_hot_apply_us + ctx->profile_pagemap_us +
		ctx->profile_finish_us;
	unaccounted_us = total_us >= accounted_us ? total_us - accounted_us : 0;
	idx_bytes = ctx->fg_pages * sizeof(struct dsa_fg_page_meta);
	dat_bytes = ctx->fg_dat_off >= 0 ? (u64)ctx->fg_dat_off : 0;

	ctx->profile_emitted = true;
	pr_info("DSA_POST_THAW_PROFILE_TIME: version=5 pages_id=%u backend=%s ret=%d total_us=%" PRIu64 " post_prepare_us=%" PRIu64 " materialize_us=%" PRIu64 " raw_index_us=%" PRIu64 " span_build_us=%" PRIu64 " compare_output_pipeline_wall_us=%" PRIu64 " compare_engine_wall_us=%" PRIu64 " compare_engine_cpu_us=%" PRIu64 " compare_breakdown=%u parent_prefault_wall_us=%" PRIu64 " parent_prefault_cpu_us=%" PRIu64 " compare_core_wall_us=%" PRIu64 " compare_core_cpu_us=%" PRIu64 " control_thread_cpu_us=%" PRIu64 " output_wall_us=%" PRIu64 " hot_apply_us=%" PRIu64 " pagemap_us=%" PRIu64 " pagemap_plan_us=%" PRIu64 " parent_validate_us=%" PRIu64 " pagemap_pack_us=%" PRIu64 " finish_us=%" PRIu64 " accounted_us=%" PRIu64 " unaccounted_us=%" PRIu64 " ledger_overrun=%u\n",
		ctx->pages_id, backend, ret, total_us, ctx->profile_post_prepare_us,
		ctx->profile_materialize_us, ctx->profile_raw_index_us,
		ctx->profile_span_build_us, ctx->profile_compare_wall_us,
		ctx->profile_compare_engine_wall_us,
		ctx->profile_compare_engine_cpu_us,
		ctx->compare_breakdown ? 1 : 0,
		ctx->profile_parent_prefault_wall_us,
		ctx->profile_parent_prefault_cpu_us,
		ctx->profile_compare_core_wall_us,
		ctx->profile_compare_core_cpu_us, ctx->profile_compare_cpu_us,
		ctx->profile_output_wall_us, ctx->profile_hot_apply_us,
		ctx->profile_pagemap_us, ctx->profile_pagemap_plan_us,
		ctx->profile_parent_validate_us, ctx->profile_pagemap_pack_us,
		ctx->profile_finish_us, accounted_us,
		unaccounted_us, accounted_us > total_us ? 1 : 0);
	pr_info("DSA_POST_THAW_PROFILE_COUNT: version=5 pages_id=%u backend=%s ret=%d raw_pages=%" PRIu64 " raw_bytes=%" PRIu64 " capture_runs=%" PRIu64 " spans=%" PRIu64 " span_pages=%" PRIu64 " max_span_pages=%" PRIu64 " compare_ops=%" PRIu64 " memcmp_calls=%" PRIu64 " memcmp_requested_bytes=%" PRIu64 " memcmp_scalar_bytes=%" PRIu64 " scalar64_calls=%" PRIu64 " scalar64_word_ops=%" PRIu64 " scalar64_refine_bytes=%" PRIu64 " scalar64_tail_bytes=%" PRIu64 " scalar64_bytes_examined=%" PRIu64 " simd_vector_ops=%" PRIu64 " simd_bytes_examined=%" PRIu64 " hybrid_dsa_claim_spans=%" PRIu64 " hybrid_dsa_claim_pages=%" PRIu64 " hybrid_cpu_claim_spans=%" PRIu64 " hybrid_cpu_claim_pages=%" PRIu64 " hybrid_cpu_waves=%" PRIu64 " hybrid_dsa_to_cpu_handoff_spans=%" PRIu64 " hybrid_dsa_to_cpu_handoff_pages=%" PRIu64 " hybrid_dsa_to_cpu_handoff_remaining_bytes=%" PRIu64 " hybrid_unclaimed_empty_count=%" PRIu64 " prq_profile_available=%u prq_profile_sources=%u prq_pg_requests=%" PRIu64 " prq_thread_cpu_us=%" PRIu64 " prq_setup_errno=%d enq_retries=%" PRIu64 " poll_sweeps=%" PRIu64 " not_ready=%" PRIu64 " max_active=%" PRIu64 " completions_harvested=%" PRIu64 " completion_timeout_count=%" PRIu64 " max_completion_age_us=%" PRIu64 " write_units=%" PRIu64 " write_unit_max_us=%" PRIu64 " prefault_spans=%" PRIu64 " prefault_pages=%" PRIu64 " parent_pages=%" PRIu64 " patch_pages=%" PRIu64 " full_pages=%" PRIu64 " patch_ranges=%" PRIu64 " patch_bytes=%" PRIu64 " idx_write_calls=%" PRIu64 " idx_bytes=%" PRIu64 " dat_write_calls=%" PRIu64 " dat_writev_calls=%" PRIu64 " dat_bytes=%" PRIu64 " hot_pwrite_ops=%" PRIu64 " hot_pwrite_bytes=%" PRIu64 " hot_mprotect_ops=%" PRIu64 " hot_memcpy_bytes=%" PRIu64 " pagemap_iovs=%" PRIu64 " pagemap_input_records=%" PRIu64 " pagemap_records=%zu pagemap_merged_records=%" PRIu64 " pagemap_present_pages=%" PRIu64 " pagemap_fg_pages=%" PRIu64 " pagemap_bytes=%" PRIu64 " pagemap_flushes=%" PRIu64 "\n",
		ctx->pages_id, backend, ret, ctx->profile_raw_pages, ctx->profile_raw_bytes,
		ctx->profile_capture_runs, ctx->profile_spans,
		ctx->profile_span_pages, ctx->profile_max_span_pages,
		ctx->fg_compare_ops, ctx->profile_memcmp_calls,
		ctx->profile_memcmp_requested_bytes,
		ctx->profile_memcmp_scalar_bytes, ctx->profile_scalar64_calls,
		ctx->profile_scalar64_word_ops, ctx->profile_scalar64_refine_bytes,
		ctx->profile_scalar64_tail_bytes, ctx->profile_scalar64_bytes_examined,
		ctx->profile_simd_vector_ops,
		ctx->profile_simd_bytes_examined,
		ctx->profile_hybrid_dsa_claim_spans,
		ctx->profile_hybrid_dsa_claim_pages,
		ctx->profile_hybrid_cpu_claim_spans,
		ctx->profile_hybrid_cpu_claim_pages,
		ctx->profile_hybrid_cpu_waves,
		ctx->profile_hybrid_dsa_to_cpu_handoff_spans,
		ctx->profile_hybrid_dsa_to_cpu_handoff_pages,
		ctx->profile_hybrid_dsa_to_cpu_handoff_remaining_bytes,
		ctx->profile_hybrid_unclaimed_empty_count,
		ctx->profile_prq_available ? 1 : 0,
		ctx->profile_nr_prq_sources,
		ctx->profile_prq_pg_requests,
		ctx->profile_prq_thread_cpu_us,
		ctx->profile_prq_setup_errno,
		ctx->profile_compare_enq_retries,
		ctx->profile_compare_poll_sweeps, ctx->profile_compare_not_ready,
		ctx->profile_compare_max_active, ctx->profile_completions_harvested,
		ctx->profile_completion_timeout_count,
		ctx->profile_max_completion_age_us,
		ctx->profile_write_units, ctx->profile_write_unit_max_us,
		ctx->profile_prefault_spans,
		ctx->profile_prefault_pages, ctx->profile_parent_pages,
		ctx->fg_patch_pages, ctx->fg_full_pages, ctx->profile_patch_ranges,
		ctx->fg_patch_bytes, ctx->profile_idx_writes, idx_bytes,
		ctx->profile_dat_writes, ctx->profile_dat_writevs, dat_bytes,
		ctx->profile_hot_pwrite_ops, ctx->profile_hot_pwrite_bytes,
		ctx->profile_hot_mprotect_ops, ctx->profile_hot_memcpy_bytes,
		ctx->profile_pagemap_iovs, ctx->pagemap_plan_input_records,
		ctx->nr_pagemap_plan,
		ctx->pagemap_plan_input_records >= ctx->nr_pagemap_plan ?
			ctx->pagemap_plan_input_records - ctx->nr_pagemap_plan : 0,
		ctx->pagemap_plan_present_pages, ctx->pagemap_plan_fg_pages,
		ctx->profile_pagemap_bytes, ctx->profile_pagemap_flushes);
}

static void dsa_memory_service_profile_emit(struct page_xfer *xfer, int ret)
{
	struct cdp_dsa_memory_service_profile *p;
	enum hot_fg_compare_backend backend_id;
	const char *backend;
	u64 total_us;
	u64 accounted_us;
	u64 unaccounted_us;
	u64 ipc_compare_overhead_us;
	u64 ipc_apply_overhead_us;

	if (!xfer || !xfer->dsa_fg_service || !dsa_profile_enabled() ||
	    !xfer->dsa_fg_profile_total_start_us)
		return;
	p = &xfer->dsa_fg_service_profile;
	backend_id = p->backend <= HOT_FG_COMPARE_VALIDATE ?
		(enum hot_fg_compare_backend)p->backend : HOT_FG_COMPARE_DSA;
	backend = hot_fg_compare_backend_name(backend_id);
	total_us = dsa_profile_delta_us(xfer->dsa_fg_profile_total_start_us,
					 dsa_profile_wall_now_us());
	accounted_us = xfer->dsa_fg_profile_request_publish_us +
		xfer->dsa_fg_profile_ipc_compare_us +
		xfer->dsa_fg_profile_sidecar_us +
		xfer->dsa_fg_profile_pagemap_us +
		xfer->dsa_fg_profile_finish_us +
		xfer->dsa_fg_profile_ipc_apply_us;
	unaccounted_us = total_us >= accounted_us ? total_us - accounted_us : 0;
	ipc_compare_overhead_us =
		xfer->dsa_fg_profile_ipc_compare_us >= p->service_compare_wall_us ?
		xfer->dsa_fg_profile_ipc_compare_us - p->service_compare_wall_us : 0;
	ipc_apply_overhead_us =
		xfer->dsa_fg_profile_ipc_apply_us >= p->hot_apply_us ?
		xfer->dsa_fg_profile_ipc_apply_us - p->hot_apply_us : 0;

	pr_info("DSA_POST_THAW_PROFILE_TIME: version=14 pages_id=%u backend=%s ret=%d service_enabled=1 service_profile_enabled=%u service_mapping_warm=%u total_us=%" PRIu64 " result_request_publish_us=%" PRIu64 " ipc_compare_us=%" PRIu64 " ipc_compare_overhead_us=%" PRIu64 " service_compare_wall_us=%" PRIu64 " service_compare_cpu_us=%" PRIu64 " service_hot_reconcile_us=%" PRIu64 " service_raw_index_us=%" PRIu64 " service_span_build_us=%" PRIu64 " raw_index_us=%" PRIu64 " span_build_us=%" PRIu64 " service_cold_prepare_us=0 compare_wall_us=%" PRIu64 " compare_thread_cpu_us=%" PRIu64 " compare_engine_wall_us=%" PRIu64 " compare_engine_cpu_us=%" PRIu64 " service_result_publish_us=%" PRIu64 " compare_breakdown=%u parent_prefault_wall_us=%" PRIu64 " parent_prefault_cpu_us=%" PRIu64 " compare_core_wall_us=%" PRIu64 " compare_core_cpu_us=%" PRIu64 " sidecar_us=%" PRIu64 " output_wall_us=%" PRIu64 " sidecar_preflight_us=%" PRIu64 " sidecar_serialize_us=%" PRIu64 " sidecar_idx_write_us=%" PRIu64 " sidecar_dat_write_us=%" PRIu64 " pagemap_us=%" PRIu64 " finish_us=%" PRIu64 " ipc_apply_us=%" PRIu64 " ipc_apply_overhead_us=%" PRIu64 " service_hot_apply_us=%" PRIu64 " service_hot_apply_cpu_us=%" PRIu64 " service_apply_validate_us=%" PRIu64 " service_apply_materialize_us=%" PRIu64 " service_apply_store_us=%" PRIu64 " service_apply_manifest_finish_us=%" PRIu64 " service_apply_manifest_close_us=%" PRIu64 " accounted_us=%" PRIu64 " unaccounted_us=%" PRIu64 " ledger_overrun=%u\n",
		xfer->pages_id, backend, ret, p->enabled, p->mapping_warm, total_us,
		xfer->dsa_fg_profile_request_publish_us,
		xfer->dsa_fg_profile_ipc_compare_us,
		ipc_compare_overhead_us,
		p->service_compare_wall_us, p->service_compare_cpu_us,
		p->hot_reconcile_us, p->raw_index_us, p->span_build_us,
		p->raw_index_us, p->span_build_us,
		p->compare_engine_wall_us, p->compare_engine_cpu_us,
		p->compare_engine_wall_us, p->compare_engine_cpu_us,
		p->result_publish_us,
		dsa_compare_breakdown_mode() == 1 ? 1 : 0,
		p->parent_prefault_wall_us, p->parent_prefault_cpu_us,
		p->compare_core_wall_us, p->compare_core_cpu_us,
		xfer->dsa_fg_profile_sidecar_us,
		xfer->dsa_fg_profile_sidecar_us,
		p->sidecar_preflight_us, p->sidecar_serialize_us,
		p->sidecar_idx_write_us, p->sidecar_dat_write_us,
		xfer->dsa_fg_profile_pagemap_us,
		xfer->dsa_fg_profile_finish_us,
		xfer->dsa_fg_profile_ipc_apply_us,
		ipc_apply_overhead_us,
		p->hot_apply_us, p->hot_apply_cpu_us,
		xfer->dsa_fg_service_diag.apply_validate_wall_us,
		xfer->dsa_fg_service_diag.apply_materialize_wall_us,
		xfer->dsa_fg_service_diag.apply_store_wall_us,
		xfer->dsa_fg_service_diag.apply_manifest_finish_wall_us,
		xfer->dsa_fg_service_diag.apply_manifest_close_wall_us,
		accounted_us, unaccounted_us, accounted_us > total_us ? 1 : 0);
	pr_info("DSA_POST_THAW_PROFILE_COUNT: version=14 pages_id=%u backend=%s ret=%d service_enabled=1 service_profile_enabled=%u service_mapping_warm=%u raw_pages=%" PRIu64 " raw_bytes=%" PRIu64 " capture_runs=%" PRIu64 " spans=%" PRIu64 " span_pages=%" PRIu64 " max_span_pages=%" PRIu64 " compare_ops=%" PRIu64 " dsa_compare_ops=%" PRIu64 " memcmp_calls=%" PRIu64 " memcmp_requested_bytes=%" PRIu64 " memcmp_scalar_bytes=%" PRIu64 " scalar64_calls=%" PRIu64 " scalar64_word_ops=%" PRIu64 " scalar64_refine_bytes=%" PRIu64 " scalar64_tail_bytes=%" PRIu64 " scalar64_bytes_examined=%" PRIu64 " simd_vector_ops=%" PRIu64 " simd_bytes_examined=%" PRIu64 " hybrid_dsa_claim_spans=%" PRIu64 " hybrid_dsa_claim_pages=%" PRIu64 " hybrid_cpu_claim_spans=%" PRIu64 " hybrid_cpu_claim_pages=%" PRIu64 " hybrid_cpu_waves=%" PRIu64 " hybrid_dsa_to_cpu_handoff_spans=%" PRIu64 " hybrid_dsa_to_cpu_handoff_pages=%" PRIu64 " hybrid_dsa_to_cpu_handoff_remaining_bytes=%" PRIu64 " hybrid_unclaimed_empty_count=%" PRIu64 " compare_nobof_faults=%" PRIu64 " compare_nobof_fault_source1=%" PRIu64 " compare_nobof_fault_source2=%" PRIu64 " compare_nobof_equal_prefix_bytes=%" PRIu64 " compare_fault_handoff_spans=%" PRIu64 " compare_fault_handoff_pages=%" PRIu64 " compare_fault_handoff_remaining_bytes=%" PRIu64 " compare_fault_queue_max=%" PRIu64 " compare_fresh_claim_throttles=%" PRIu64 " compare_cpu_fault_waves=%" PRIu64 " dsa_logical_progress_bytes=%" PRIu64 " simd_logical_progress_bytes=%" PRIu64 " normal_simd_logical_progress_bytes=%" PRIu64 " fault_simd_logical_progress_bytes=%" PRIu64 " dsa_fresh_submit_ops=%" PRIu64 " dsa_continuation_submit_ops=%" PRIu64 " dsa_submitted_bytes=%" PRIu64 " simd_progress_while_dsa_active_bytes=%" PRIu64 " simd_quanta_while_dsa_active=%" PRIu64 " dsa_fresh_claim_bytes=%" PRIu64 " dsa_active_zero_while_normal_cpu_work=%" PRIu64 " ready_completions_before_simd=%" PRIu64 " ready_completions_after_simd=%" PRIu64 " scheduler_iterations=%" PRIu64 " dsa_refill_samples=%" PRIu64 " post_refill_active_sum=%" PRIu64 " post_refill_active_lt_32=%" PRIu64 " post_refill_active_lt_64=%" PRIu64 " post_refill_active_lt_96=%" PRIu64 " fresh_refill_spans=%" PRIu64 " fresh_refill_batches=%" PRIu64 " fresh_refill_blocked_fault_debt=%" PRIu64 " dsa_empty_with_claimable_fresh=%" PRIu64 " batch_outer_submits=%" PRIu64 " batch_child_submits=%" PRIu64 " batch_partial_submits=%" PRIu64 " batch_single_tail_submits=%" PRIu64 " batch_outer_success=%" PRIu64 " batch_outer_fail=%" PRIu64 " batch_child_success=%" PRIu64 " batch_child_nobof=%" PRIu64 " batch_max_active_outer=%" PRIu64 " batch_max_active_children=%" PRIu64 " prq_profile_available=%u prq_profile_sources=%u prq_pg_requests=%" PRIu64 " prq_thread_cpu_us=%" PRIu64 " prq_setup_errno=%d enq_retries=%" PRIu64 " poll_sweeps=%" PRIu64 " not_ready=%" PRIu64 " max_active=%" PRIu64 " completions_harvested=%" PRIu64 " completion_timeout_count=%" PRIu64 " max_completion_age_us=%" PRIu64 " prefault_spans=%" PRIu64 " prefault_pages=%" PRIu64 " parent_pages=%" PRIu64 " patch_pages=%" PRIu64 " full_pages=%" PRIu64 " patch_ranges=%" PRIu64 " patch_bytes=%" PRIu64 " idx_write_calls=%" PRIu64 " idx_bytes=%" PRIu64 " dat_write_calls=%" PRIu64 " dat_writev_calls=%" PRIu64 " dat_bytes=%" PRIu64 " idx_write_syscalls=%" PRIu64 " dat_write_syscalls=%" PRIu64 " dat_writev_syscalls=%" PRIu64 " sidecar_lseek_syscalls=%" PRIu64 " pagemap_records=%" PRIu64 " pagemap_bytes=%" PRIu64 "\n",
		xfer->pages_id, backend, ret, p->enabled, p->mapping_warm,
		p->raw_pages, p->raw_bytes, p->capture_runs, p->spans,
		p->span_pages, p->max_span_pages, p->compare_ops, p->compare_ops,
		p->memcmp_calls, p->memcmp_requested_bytes, p->memcmp_scalar_bytes,
		p->scalar64_calls, p->scalar64_word_ops, p->scalar64_refine_bytes,
		p->scalar64_tail_bytes, p->scalar64_bytes_examined,
		p->simd_vector_ops, p->simd_bytes_examined,
		p->hybrid_dsa_claim_spans, p->hybrid_dsa_claim_pages,
		p->hybrid_cpu_claim_spans, p->hybrid_cpu_claim_pages,
		p->hybrid_cpu_waves, p->hybrid_dsa_to_cpu_handoff_spans,
		p->hybrid_dsa_to_cpu_handoff_pages,
		p->hybrid_dsa_to_cpu_handoff_remaining_bytes,
		p->hybrid_unclaimed_empty_count,
		p->compare_nobof_faults, p->compare_nobof_fault_source1,
		p->compare_nobof_fault_source2, p->compare_nobof_equal_prefix_bytes,
		p->compare_fault_handoff_spans, p->compare_fault_handoff_pages,
		p->compare_fault_handoff_remaining_bytes, p->compare_fault_queue_max,
		p->compare_fresh_claim_throttles, p->compare_cpu_fault_waves,
		p->dsa_logical_progress_bytes, p->simd_logical_progress_bytes,
		p->normal_simd_logical_progress_bytes,
		p->fault_simd_logical_progress_bytes,
		p->dsa_fresh_submit_ops, p->dsa_continuation_submit_ops,
		p->dsa_submitted_bytes,
		p->simd_progress_while_dsa_active_bytes,
		p->simd_quanta_while_dsa_active,
		p->dsa_fresh_claim_bytes,
		p->dsa_active_zero_while_normal_cpu_work,
		p->ready_completions_before_simd,
		p->ready_completions_after_simd,
		p->scheduler_iterations, p->dsa_refill_samples,
		p->post_refill_active_sum,
		p->post_refill_active_lt_32,
		p->post_refill_active_lt_64,
		p->post_refill_active_lt_96,
		p->fresh_refill_spans, p->fresh_refill_batches,
		p->fresh_refill_blocked_fault_debt,
		p->dsa_empty_with_claimable_fresh,
		p->batch_outer_submits, p->batch_child_submits,
		p->batch_partial_submits, p->batch_single_tail_submits,
		p->batch_outer_success, p->batch_outer_fail,
		p->batch_child_success, p->batch_child_nobof,
		p->batch_max_active_outer, p->batch_max_active_children,
		p->prq_profile_available,
		p->prq_profile_sources, p->prq_pg_requests,
		p->prq_thread_cpu_us, p->prq_setup_errno, p->enq_retries,
		p->poll_sweeps, p->not_ready, p->max_active,
		p->completions_harvested, p->completion_timeout_count,
		p->max_completion_age_us, p->prefault_spans, p->prefault_pages,
		p->parent_pages, p->patch_pages, p->full_pages,
		p->patch_ranges, p->patch_bytes, p->idx_write_calls,
		p->idx_bytes, p->dat_write_calls, p->dat_writev_calls,
		p->dat_bytes, p->idx_write_syscalls, p->dat_write_syscalls,
		p->dat_writev_syscalls, p->sidecar_lseek_syscalls,
		xfer->write_profile_pagemap_records,
		xfer->write_profile_pagemap_bytes);
	xfer->dsa_fg_profile_total_start_us = 0;
}

static int hot_apply_init_xfer(struct page_xfer *xfer, int fd_type,
			       unsigned long img_id, u32 pages_id)
{
	struct hot_apply_ctx *ctx;

	if (!dsa_hot_apply_enabled())
		return 0;

	if (hot_apply_prepared) {
		ctx = hot_apply_prepared;
		if (ctx->pre_freeze_ready && ctx->fd_type == fd_type &&
		    ctx->img_id == img_id && ctx->fine_grained) {
			hot_apply_prepared = NULL;
			ctx->pages_id = pages_id;
			xfer->hot_apply = ctx;
			pr_info("DSA fine-grained attached pre-freeze parent view img_id=%lu pages_id=%u\n",
				img_id, pages_id);
			return 0;
		}
		/* A process-tree dump can open another task's pagemap first.  It must
		 * not consume the root task's immutable context; that task follows the
		 * ordinary post-thaw setup and the prepared context remains available
		 * for its matching img_id. */
	}

	ctx = hot_apply_alloc_ctx(fd_type, img_id, pages_id);
	if (!ctx)
		return -1;

	if (!ctx->memstore) {
		pr_err("DSA hot apply full-pages image/reorder mode has been removed; use CRIU_DSA_HOT_MODE=memstore\n");
		goto err;
	}

	if (fd_type != CR_FD_PAGEMAP) {
		pr_info("DSA hot memstore skips non-task pagemap fd_type=%d img_id=%lu\n",
			fd_type, img_id);
		xfree(ctx);
		return 0;
	}

	if (!ctx->hot_root || !ctx->hot_root[0]) {
		pr_err("DSA hot apply has no hot root/current dir\n");
		goto err;
	}

	xfer->hot_apply = ctx;
	pr_info("DSA hot memstore plan ready fd_type=%d img_id=%lu pages_id=%u root=%s next=%s old=%s fine_grained=%u\n",
		fd_type, img_id, pages_id, ctx->hot_root,
		ctx->memory_next_path,
		ctx->memory_manifest_path ? ctx->memory_manifest_path : "",
		ctx->fine_grained ? 1 : 0);
	return 0;

err:
	if (xfer->hot_apply) {
		hot_apply_abort(xfer);
	} else {
		xfer->hot_apply = ctx;
		hot_apply_abort(xfer);
	}
	return -1;
}

int page_xfer_hot_set_vmas(struct page_xfer *xfer, struct vm_area_list *vmas)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	struct vma_area *vma;
	struct dsa_fg_vma_plan_record *records = NULL;
	size_t nr = 0, cap = 0;
	bool service_client = !ctx && dsa_memory_service_client_fd() >= 0;

	if ((!ctx || !ctx->memstore) && !service_client)
		return 0;
	if (ctx && ctx->fd_type != CR_FD_PAGEMAP)
		return 0;

	list_for_each_entry(vma, &vmas->h, list) {
		unsigned long start, end;

		if (!hot_memstore_should_track_vma(vma))
			continue;

		start = vma->e->start;
		end = vma->e->end;
		if (ctx) {
			if (hot_memstore_plan_segment(ctx, start, end))
				return -1;
		} else {
			if (nr == cap) {
				size_t new_cap = cap ? cap * 2 : 128;
				void *new_records = xrealloc(records,
							      new_cap * sizeof(*records));

				if (!new_records) {
					xfree(records);
					return -1;
				}
				records = new_records;
				cap = new_cap;
			}
			records[nr++] = (struct dsa_fg_vma_plan_record) {
				.start = start,
				.end = end,
			};
		}
	}
	if (service_client) {
		if (!nr) {
			pr_err("DSA memory service has no target VMA plan\n");
			xfree(records);
			return -1;
		}
		if (nr > UINT_MAX) {
			pr_err("DSA memory service VMA plan has too many records: %zu\n",
			       nr);
			xfree(records);
			return -1;
		}
		xfree(xfer->dsa_fg_vma_plan_local);
		xfer->dsa_fg_vma_plan_local = records;
		xfer->dsa_fg_vma_plan_count = nr;
		return 0;
	}

	pr_info("DSA hot memstore VMA plan ready img_id=%lu segments=%zu\n",
		ctx->img_id, ctx->nr_vma_plans);
	return 0;
}

size_t page_xfer_hot_vma_plan_count(struct vm_area_list *vmas)
{
	struct vma_area *vma;
	size_t nr = 0;

	list_for_each_entry(vma, &vmas->h, list) {
		if (hot_memstore_should_track_vma(vma))
			nr++;
	}
	return nr;
}

static int hot_apply_set_pending(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;

	if (!ctx)
		return 0;

	if (!(flags & (PE_PRESENT | PE_PARENT))) {
		pr_err("DSA hot apply unsupported pagemap flags=%" PRIx32 "\n", flags);
		ctx->pending.valid = false;
		return -1;
	}
	ctx->nr_entries++;

	if (!(flags & PE_PRESENT)) {
		ctx->pending.valid = false;
		return 0;
	}

	ctx->pending.valid = true;
	ctx->pending.vaddr = (unsigned long)iov->iov_base;
	ctx->pending.len = iov->iov_len;
	return 0;
}

static int hot_memstore_log_pending(struct hot_apply_ctx *ctx, unsigned long len,
				    struct hot_apply_extent **entry_out)
{
	struct hot_apply_extent *e = &ctx->pending;

	*entry_out = NULL;
	if (!e->valid || e->len != len) {
		pr_err("DSA hot memstore pending extent mismatch valid=%d pending=%lu write=%lu\n",
		       e->valid, e->len, len);
		return -1;
	}

	*entry_out = e;
	return 0;
}

static int splice_exact(int in, int out, unsigned long len)
{
	unsigned long curr = 0;

	while (curr < len) {
		ssize_t ret = splice(in, NULL, out, NULL, len - curr, SPLICE_F_MOVE);

		if (ret == -1) {
			pr_perror("Unable to splice pages data");
			return -1;
		}
		if (ret == 0) {
			pr_err("A pipe was closed unexpectedly\n");
			return -1;
		}
		curr += ret;
	}

	return 0;
}

struct page_server_iov {
	u32 cmd;
	u64 nr_pages;
	u64 vaddr;
	u64 dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD    1
#define PS_IOV_HOLE   2
#define PS_IOV_OPEN   3
#define PS_IOV_OPEN2  4
#define PS_IOV_PARENT 5
#define PS_IOV_ADD_F  6
#define PS_IOV_GET    7

#define PS_IOV_CLOSE	   0x1023
#define PS_IOV_FORCE_CLOSE 0x1024

#define PS_CMD_BITS 16
#define PS_CMD_MASK ((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS 8
#define PS_TYPE_MASK ((1 << PS_TYPE_BITS) - 1)

#define PS_TYPE_PID   (1)
#define PS_TYPE_SHMEM (2)
/*
 * XXX: When adding new types here check decode_pm for legacy
 * numbers that can be met from older CRIUs
 */

static inline u64 encode_pm(int type, unsigned long id)
{
	if (type == CR_FD_PAGEMAP)
		type = PS_TYPE_PID;
	else if (type == CR_FD_SHMEM_PAGEMAP)
		type = PS_TYPE_SHMEM;
	else {
		BUG();
		return 0;
	}

	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm(u64 dst_id, unsigned long *id)
{
	int type;

	/*
	 * Magic numbers below came from the older CRIU versions that
	 * erroneously used the changing CR_FD_* constants. The
	 * changes were made when we merged images together and moved
	 * the CR_FD_-s at the tail of the enum
	 */
	type = dst_id & PS_TYPE_MASK;
	switch (type) {
	case 10: /* 3.1 3.2 */
	case 11: /* 1.3 1.4 1.5 1.6 1.7 1.8 2.* 3.0 */
	case 16: /* 1.2 */
	case 17: /* 1.0 1.1 */
	case PS_TYPE_PID:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_PAGEMAP;
		break;
	case 27: /* 1.3 */
	case 28: /* 1.4 1.5 */
	case 29: /* 1.6 1.7 */
	case 32: /* 1.2 1.8 */
	case 33: /* 1.0 1.1 3.1 3.2 */
	case 34: /* 2.* 3.0 */
	case PS_TYPE_SHMEM:
		*id = dst_id >> PS_TYPE_BITS;
		type = CR_FD_SHMEM_PAGEMAP;
		break;
	default:
		type = -1;
		break;
	}

	return type;
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

static inline int __send(int sk, const void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_send(buf, sz, fl) : send(sk, buf, sz, fl);
}

static inline int __recv(int sk, void *buf, size_t sz, int fl)
{
	return opts.tls ? tls_recv(buf, sz, fl) : recv(sk, buf, sz, fl);
}

static inline int send_psi_flags(int sk, struct page_server_iov *pi, int flags)
{
	if (__send(sk, pi, sizeof(*pi), flags) != sizeof(*pi)) {
		pr_perror("Can't send PSI %d to server", pi->cmd);
		return -1;
	}
	return 0;
}

static inline int send_psi(int sk, struct page_server_iov *pi)
{
	return send_psi_flags(sk, pi, 0);
}

static void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_CORK=%d", val);
}

static void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val)))
		pr_pwarn("Unable to set TCP_NODELAY=%d", val);
}

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer, int p, unsigned long len)
{
	ssize_t ret, left = len;

	if (opts.tls) {
		pr_debug("Sending %lx bytes\n", len);

		if (tls_send_data_from_fd(p, len))
			return -1;
	} else {
		pr_debug("Splicing %lx bytes into socket\n", len);

		while (left > 0) {
			ret = splice(p, NULL, xfer->sk, NULL, left, SPLICE_F_MOVE);
			if (ret < 0) {
				pr_perror("Can't write pages to socket");
				return -1;
			}

			pr_debug("\tSpliced: %lx bytes sent\n", (unsigned long)ret);
			left -= ret;
		}
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	struct page_server_iov pi = {
		.cmd = encode_ps_cmd(PS_IOV_ADD_F, flags),
		.nr_pages = iov->iov_len / PAGE_SIZE,
		.vaddr = encode_pointer(iov->iov_base),
		.dst_id = xfer->dst_id,
	};

	return send_psi(xfer->sk, &pi);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	char has_parent;
	struct page_server_iov pi = {
		.cmd = PS_IOV_OPEN2,
	};

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm(fd_type, img_id);
	xfer->parent = NULL;

	pi.dst_id = xfer->dst_id;
	if (send_psi(xfer->sk, &pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (__recv(xfer->sk, &has_parent, 1, 0) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *)1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int hot_fg_write_pages_loc(struct page_xfer *xfer, int p,
				  unsigned long len,
				  struct hot_apply_extent *pending_entry);

#define DSA_ALIGNED_FULL_WRITE_BATCH (4U * 1024U * 1024U)

static int dsa_aligned_full_flush(struct page_xfer *xfer)
{
	u32 off;

	if (!xfer || !xfer->dsa_fg_shared ||
	    xfer->dsa_fg_raw_emit_cursor != xfer->dsa_fg_raw_payload_head) {
		errno = ERANGE;
		return -1;
	}
	/* The sealed payload is contiguous even when its capture IOVs were not.
	 * Submit large native chunks after the generic pagemap pass.  This keeps
	 * queue-depth-one DIO setup/completion costs bounded without allocating a
	 * matching staging buffer or copying the payload. */
	for (off = xfer->dsa_fg_raw_payload_base;
	     off < xfer->dsa_fg_raw_payload_head;) {
		u32 left = xfer->dsa_fg_raw_payload_head - off;
		u32 chunk = left > DSA_ALIGNED_FULL_WRITE_BATCH ?
			DSA_ALIGNED_FULL_WRITE_BATCH : left;

		if (write_full_fd(img_raw_fd(xfer->pi),
				  (const unsigned char *)xfer->dsa_fg_shared + off,
				  chunk)) {
			pr_perror("DSA aligned full raw write failed");
			return -1;
		}
		if (xfer->write_profile_enabled)
			xfer->write_profile_pages_emit_calls++;
		off += chunk;
	}
	return 0;
}

static int dsa_aligned_full_write_pages(struct page_xfer *xfer,
					 unsigned long len)
{
	if (!xfer || !xfer->dsa_fg_shared ||
	    xfer->dsa_fg_raw_emit_cursor < xfer->dsa_fg_raw_payload_base ||
	    xfer->dsa_fg_raw_emit_cursor > xfer->dsa_fg_raw_payload_head ||
	    len > xfer->dsa_fg_raw_payload_head - xfer->dsa_fg_raw_emit_cursor) {
		errno = ERANGE;
		return -1;
	}
	/* Advancing the cursor validates that the ordinary pagemap traversal and
	 * the raw capture have the same present-byte geometry; flush() then writes
	 * contiguous chunks. */
	xfer->dsa_fg_raw_emit_cursor += len;
	return 0;
}

static int write_pages_loc(struct page_xfer *xfer, int p, unsigned long len)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	int ret;
	unsigned long curr = 0;
	uint64_t append_prepare_start_us;
	struct hot_apply_extent *pending_entry = NULL;

	if (!ctx) {
		if (xfer->dsa_fg_raw_capture && dsa_aligned_full_enabled()) {
			if (dsa_aligned_full_write_pages(xfer, len))
				return -1;
			if (xfer->write_profile_enabled)
				xfer->write_profile_pages_bytes += len;
			return 0;
		}
		ret = splice_exact(p, img_raw_fd(xfer->pi), len);

		if (!ret && xfer->write_profile_enabled) {
			xfer->write_profile_pages_bytes += len;
			xfer->write_profile_pages_emit_calls++;
		}
		return ret;
	}

	append_prepare_start_us = hot_now_us();
	if (!ctx->memstore ||
	    hot_memstore_log_pending(ctx, len, &pending_entry))
		return -1;
	ctx->append_prepare_us += hot_now_us() - append_prepare_start_us;

	if (ctx->fine_output) {
		uint64_t append_start_us = hot_now_us();

		if (!ctx->memstore || !pending_entry) {
			pr_err("DSA fine-grained write requires hot memstore pending entry\n");
			return -1;
		}
		if (hot_fg_write_pages_loc(xfer, p, len, pending_entry))
			return -1;
		ctx->append_time_us += hot_now_us() - append_start_us;
		ctx->pending.valid = false;
		return 0;
	}

	while (curr < len) {
		uint64_t append_start_us;
		uint64_t append_delta_us;
		ssize_t ret;

		append_start_us = hot_now_us();
		ret = tee(p, ctx->pipefd[1], len - curr, 0);
		append_delta_us = hot_now_us() - append_start_us;
		ctx->append_tee_us += append_delta_us;
		ctx->append_time_us += append_delta_us;
		if (ret < 0) {
			pr_perror("DSA hot apply tee failed");
			return -1;
		}
		if (ret == 0) {
			pr_err("DSA hot apply tee returned 0\n");
			return -1;
		}

		if (splice_exact(p, img_raw_fd(xfer->pi), ret))
			return -1;

		append_start_us = hot_now_us();
		if (hot_memstore_splice_to_segments(ctx, ctx->pipefd[0],
						    pending_entry->vaddr + curr,
						    ret))
			return -1;
		append_delta_us = hot_now_us() - append_start_us;
		ctx->append_splice_us += append_delta_us;
		ctx->append_time_us += append_delta_us;
		ctx->append_bytes += ret;
		ctx->memstore_bytes += ret;

		curr += ret;
	}

	ctx->pending.valid = false;
	if (xfer->write_profile_enabled) {
		xfer->write_profile_pages_bytes += len;
		xfer->write_profile_pages_emit_calls++;
	}
	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p - %p hole\n", iov->iov_base, iov->iov_base + iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		unsigned long pend;

		ret = p->seek_pagemap(p, off);
		if (ret <= 0 || !p->pe) {
			pr_err("Missing %lx in parent pagemap\n", off);
			return -1;
		}

		pr_debug("\tFound %" PRIx64 " - %" PRIx64 "\n",
			 p->pe->vaddr, p->pe->vaddr + pagemap_len(p->pe));

		/*
		 * The pagemap entry in parent may happen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = p->pe->vaddr + pagemap_len(p->pe);
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static u32 page_xfer_effective_flags(struct page_xfer *xfer, u32 flags)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;

	if (((ctx && ctx->fine_output) || xfer->dsa_fine_grained) &&
	    (flags & PE_PRESENT))
		flags |= PE_DSA_FG;

	return flags;
}

static bool hot_fg_defer_pagemap(const struct page_xfer *xfer)
{
	const struct hot_apply_ctx *ctx = xfer->hot_apply;

	return ctx && ctx->memstore && ctx->fine_output &&
		xfer->dsa_fg_raw_capture && xfer->dsa_fg_materialized;
}

static int hot_fg_pagemap_plan_append(struct hot_apply_ctx *ctx,
				      const struct iovec *iov, u32 flags)
{
	struct hot_pagemap_plan_entry *entries;
	struct hot_pagemap_plan_entry *last;
	unsigned long vaddr = (unsigned long)iov->iov_base;
	unsigned long len = iov->iov_len;
	u64 nr_pages;
	size_t cap;

	if (!len || len % PAGE_SIZE || vaddr % PAGE_SIZE) {
		pr_err("DSA fine-grained pagemap record is not page aligned: %p/%zu\n",
		       iov->iov_base, iov->iov_len);
		return -1;
	}
	if (vaddr > ULONG_MAX - len) {
		pr_err("DSA fine-grained pagemap record overflows address space: %p/%zu\n",
		       iov->iov_base, iov->iov_len);
		return -1;
	}
	nr_pages = len / PAGE_SIZE;
	if (ctx->pagemap_plan_input_records == UINT64_MAX ||
	    ((flags & PE_PRESENT) &&
	     ctx->pagemap_plan_present_pages > UINT64_MAX - nr_pages) ||
	    ((flags & PE_DSA_FG) &&
	     ctx->pagemap_plan_fg_pages > UINT64_MAX - nr_pages)) {
		pr_err("DSA fine-grained pagemap accounting overflow\n");
		return -1;
	}
	if ((flags & PE_DSA_FG) && !(flags & PE_PRESENT)) {
		pr_err("DSA fine-grained pagemap record lacks PE_PRESENT: %p/%zu flags=%#x\n",
		       iov->iov_base, iov->iov_len, flags);
		return -1;
	}

	ctx->pagemap_plan_input_records++;
	if (flags & PE_PRESENT)
		ctx->pagemap_plan_present_pages += nr_pages;
	if (flags & PE_DSA_FG)
		ctx->pagemap_plan_fg_pages += nr_pages;

	if (ctx->nr_pagemap_plan) {
		last = &ctx->pagemap_plan[ctx->nr_pagemap_plan - 1];
		if (last->vaddr > ULONG_MAX - last->len) {
			pr_err("DSA fine-grained pagemap plan has overflowing tail\n");
			return -1;
		}
		if (vaddr < last->vaddr + last->len) {
			pr_err("DSA fine-grained pagemap input is not ordered: %p/%zu after %p/%lu\n",
			       iov->iov_base, iov->iov_len, (void *)last->vaddr,
			       last->len);
			return -1;
		}
		if (vaddr == last->vaddr + last->len && last->flags == flags) {
			if (last->len > ULONG_MAX - len) {
				pr_err("DSA fine-grained pagemap coalesce length overflow\n");
				return -1;
			}
			last->len += len;
			return 0;
		}
	}
	if (ctx->nr_pagemap_plan == ctx->pagemap_plan_cap) {
		cap = ctx->pagemap_plan_cap ? ctx->pagemap_plan_cap * 2 : 1024;
		if (cap < ctx->pagemap_plan_cap ||
		    cap > SIZE_MAX / sizeof(*entries)) {
			pr_err("DSA fine-grained pagemap plan capacity overflow\n");
			return -1;
		}
		entries = xrealloc(ctx->pagemap_plan, cap * sizeof(*entries));
		if (!entries)
			return -1;
		ctx->pagemap_plan = entries;
		ctx->pagemap_plan_cap = cap;
	}
	ctx->pagemap_plan[ctx->nr_pagemap_plan++] =
		(struct hot_pagemap_plan_entry) {
			.vaddr = vaddr,
			.len = len,
			.flags = flags,
		};
	return 0;
}

static int hot_fg_pagemap_validate(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	size_t i;

	if (ctx->pagemap_plan_input_records < ctx->nr_pagemap_plan ||
	    ctx->pagemap_plan_present_pages != ctx->pagemap_plan_fg_pages ||
	    ctx->pagemap_plan_fg_pages != ctx->fg_pages) {
		pr_err("DSA fine-grained pagemap/sidecar mismatch: input_records=%" PRIu64
		       " output_records=%zu present_pages=%" PRIu64
		       " fg_pages=%" PRIu64 " sidecar_pages=%" PRIu64 "\n",
		       ctx->pagemap_plan_input_records, ctx->nr_pagemap_plan,
		       ctx->pagemap_plan_present_pages, ctx->pagemap_plan_fg_pages,
		       ctx->fg_pages);
		return -1;
	}

	for (i = 0; i < ctx->nr_pagemap_plan; i++) {
		const struct hot_pagemap_plan_entry *entry = &ctx->pagemap_plan[i];
		struct iovec iov = {
			.iov_base = (void *)entry->vaddr,
			.iov_len = entry->len,
		};

		if (!(entry->flags & PE_PARENT) || !xfer->parent)
			continue;
		if (check_pagehole_in_parent(xfer->parent, &iov)) {
			pr_err("DSA fine-grained pagemap parent hole %p - %p not found\n",
			       iov.iov_base, iov.iov_base + iov.iov_len);
			return -1;
		}
	}
	return 0;
}

#define HOT_FG_PAGEMAP_PACK_BYTES (64U * 1024U)

static int hot_fg_pagemap_emit(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned char *buf;
	size_t used = 0;
	size_t i;
	int ret = -1;

	if (!ctx->nr_pagemap_plan)
		return 0;
	if (lazy_image(xfer->pmi) && open_image_lazy(xfer->pmi))
		return -1;
	buf = xmalloc(HOT_FG_PAGEMAP_PACK_BYTES);
	if (!buf)
		return -1;

	for (i = 0; i < ctx->nr_pagemap_plan; i++) {
		const struct hot_pagemap_plan_entry *entry = &ctx->pagemap_plan[i];
		PagemapEntry pe = PAGEMAP_ENTRY__INIT;
		size_t packed;
		u32 size;

		pe.vaddr = encode_pointer((void *)entry->vaddr);
		pe.nr_pages = entry->len / PAGE_SIZE;
		pe.has_flags = true;
		pe.flags = entry->flags;
		pe.has_nr_pages = true;
		size = pagemap_entry__get_packed_size(&pe);
		if (size > HOT_FG_PAGEMAP_PACK_BYTES - sizeof(size)) {
			pr_err("DSA fine-grained pagemap record too large size=%u\n", size);
			goto out;
		}
		if (used && used + sizeof(size) + size > HOT_FG_PAGEMAP_PACK_BYTES) {
			if (bwrite(&xfer->pmi->_x, buf, used) != (int)used) {
				pr_perror("DSA fine-grained pagemap batch write failed");
				goto out;
			}
			if (ctx->profile)
				ctx->profile_pagemap_flushes++;
			used = 0;
		}
		memcpy(buf + used, &size, sizeof(size));
		packed = pagemap_entry__pack(&pe, buf + used + sizeof(size));
		if (packed != size) {
			pr_err("DSA fine-grained pagemap pack mismatch packed=%zu size=%u\n",
			       packed, size);
			goto out;
		}
		used += sizeof(size) + size;
		if (xfer->write_profile_enabled) {
			xfer->write_profile_pagemap_records++;
			xfer->write_profile_pagemap_bytes += sizeof(size) + size;
		}
		if (ctx->profile) {
			ctx->profile_pagemap_bytes += sizeof(size) + size;
		}
	}
	if (used) {
		if (bwrite(&xfer->pmi->_x, buf, used) != (int)used) {
			pr_perror("DSA fine-grained pagemap final batch write failed");
			goto out;
		}
		if (ctx->profile)
			ctx->profile_pagemap_flushes++;
	}
	ret = 0;
out:
	xfree(buf);
	return ret;
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	flags = page_xfer_effective_flags(xfer, flags);

	pe.vaddr = encode_pointer(iov->iov_base);
	pe.nr_pages = iov->iov_len / PAGE_SIZE;
	pe.has_flags = true;
	pe.flags = flags;
	pe.has_nr_pages = true;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, pe.vaddr, pagemap_len(&pe));
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if ((flags & PE_PARENT) && !hot_fg_defer_pagemap(xfer)) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p - %p not found in parent\n",
				       iov->iov_base, iov->iov_base + iov->iov_len);
				return -1;
			}
		}
	}
	if (hot_fg_defer_pagemap(xfer))
		return hot_fg_pagemap_plan_append(xfer->hot_apply, iov, flags);

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;
	if (xfer->write_profile_enabled) {
		xfer->write_profile_pagemap_records++;
		xfer->write_profile_pagemap_bytes +=
			sizeof(u32) + pagemap_entry__get_packed_size(&pe);
	}

	if (hot_apply_set_pending(xfer, iov, flags))
		return -1;
	return 0;
}

static int hot_fg_write_meta(struct hot_apply_ctx *ctx,
			     struct dsa_fg_page_meta *meta)
{
	if (write_full_fd(ctx->fg_idx_fd, meta, sizeof(*meta))) {
		pr_perror("DSA fine-grained index write failed");
		return -1;
	}
	return 0;
}

static int hot_fg_writev_full_fd(int fd, struct iovec *iov, unsigned int nr)
{
	unsigned int head = 0;

	if (!nr || nr > HOT_FG_WRITEV_MAX)
		return nr ? -1 : 0;

	while (head < nr) {
		ssize_t ret = writev(fd, &iov[head], nr - head);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}

		while (head < nr && ret >= (ssize_t)iov[head].iov_len) {
			ret -= iov[head].iov_len;
			head++;
		}
		if (head < nr && ret) {
			iov[head].iov_base = (char *)iov[head].iov_base + ret;
			iov[head].iov_len -= ret;
		}
	}

	return 0;
}

/* One sink owns the durable sidecar write mechanics.  The legacy raw-page
 * path and the service canonical-result path differ only in how they expose
 * one classified page; neither path owns a second payload buffer. */
struct dsa_fg_sidecar_stats {
	bool enabled;
	u64 *idx_write_calls;
	u64 *idx_bytes;
	u64 *dat_write_calls;
	u64 *dat_writev_calls;
	u64 *dat_bytes;
	u64 *write_units;
	u64 *write_unit_max_us;
	u64 *idx_write_syscalls;
	u64 *dat_write_syscalls;
	u64 *dat_writev_syscalls;
	u64 *idx_write_us;
	u64 *dat_write_us;
};

/* idx/dat records are deliberately not forced into an artificial on-disk
 * padding format.  The direct stream owns a bounded aligned staging block,
 * emits only full 4 KiB units while records arrive, then zero-pads and
 * truncates at finish so the externally visible file remains byte-identical
 * to the buffered format. */
struct dsa_direct_stream {
	int fd;
	unsigned char *buf;
	size_t used;
	size_t capacity;
	off_t logical;
	bool enabled;
	bool external;
};

static int dsa_direct_stream_init(struct dsa_direct_stream *stream, int fd,
				  bool enabled, size_t capacity, void *external)
{
	memset(stream, 0, sizeof(*stream));
	stream->fd = fd;
	stream->enabled = enabled;
	if (!enabled)
		return 0;
	if (!capacity || capacity % PAGE_SIZE) {
		errno = EINVAL;
		return -1;
	}
	if (external) {
		if ((unsigned long)external % PAGE_SIZE) {
			errno = EINVAL;
			return -1;
		}
		stream->buf = external;
		stream->external = true;
	} else {
		stream->buf = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (stream->buf == MAP_FAILED) {
			stream->buf = NULL;
			return -1;
		}
	}
	stream->capacity = capacity;
	return 0;
}

static int dsa_direct_stream_flush(struct dsa_direct_stream *stream, bool finish,
				   u64 *syscalls)
{
	size_t bytes;

	if (!stream->enabled || !stream->used)
		return 0;
	bytes = finish ? ((stream->used + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) :
		(stream->used & ~(PAGE_SIZE - 1));
	if (!bytes)
		return 0;
	if (bytes > stream->used)
		memset(stream->buf + stream->used, 0, bytes - stream->used);
	if (write_full_fd(stream->fd, stream->buf, bytes))
		return -1;
	if (syscalls)
		(*syscalls)++;
	stream->logical += stream->used < bytes ? stream->used : bytes;
	if (bytes < stream->used)
		memmove(stream->buf, stream->buf + bytes, stream->used - bytes);
	stream->used = bytes < stream->used ? stream->used - bytes : 0;
	return 0;
}

static int dsa_direct_stream_write(struct dsa_direct_stream *stream,
				   const void *buf, size_t len, u64 *syscalls)
{
	const unsigned char *p = buf;

	if (!stream->enabled)
		return -1;
	while (len) {
		size_t room = stream->capacity - stream->used;
		size_t chunk = len < room ? len : room;
		memcpy(stream->buf + stream->used, p, chunk);
		stream->used += chunk;
		p += chunk;
		len -= chunk;
		if (stream->used == stream->capacity &&
		    dsa_direct_stream_flush(stream, false, syscalls))
			return -1;
	}
	return 0;
}

static int dsa_direct_stream_finish(struct dsa_direct_stream *stream, u64 *syscalls)
{
	if (!stream->enabled)
		return 0;
	if (dsa_direct_stream_flush(stream, true, syscalls))
		return -1;
	if (ftruncate(stream->fd, stream->logical) < 0 || fdatasync(stream->fd) < 0)
		return -1;
	return 0;
}

static void dsa_direct_stream_fini(struct dsa_direct_stream *stream)
{
	if (stream->buf && !stream->external)
		munmap(stream->buf, stream->capacity);
	stream->buf = NULL;
	stream->capacity = 0;
}

struct dsa_fg_sidecar_sink {
	int idx_fd;
	int dat_fd;
	off_t dat_off;
	struct dsa_fg_sidecar_stats stats;
	struct dsa_fg_page_meta metas[HOT_FG_OUTPUT_META_MAX];
	struct dsa_fg_patch_entry patches[HOT_FG_OUTPUT_META_MAX * DSA_FG_MAX_PATCHES];
	struct iovec iov[HOT_FG_WRITEV_MAX];
	struct iovec write_iov[HOT_FG_WRITEV_MAX];
	unsigned int nr_metas;
	unsigned int nr_patches;
	unsigned int nr_iov;
	unsigned int iov_head;
	u64 chunk_dat_bytes;
	struct dsa_direct_stream *idx_dio;
	struct dsa_direct_stream *dat_dio;
};

static void dsa_fg_sidecar_stats_add(u64 *counter, u64 value)
{
	if (counter)
		*counter += value;
}

static void dsa_fg_sidecar_sink_reset_chunk(struct dsa_fg_sidecar_sink *sink)
{
	sink->nr_metas = 0;
	sink->nr_patches = 0;
	sink->nr_iov = 0;
	sink->iov_head = 0;
	sink->chunk_dat_bytes = 0;
}

static int dsa_fg_sidecar_sink_append_iov(struct dsa_fg_sidecar_sink *sink,
						 const void *base, size_t len)
{
	struct iovec *last;

	if (!len)
		return 0;
	if (sink->nr_iov) {
		last = &sink->iov[sink->nr_iov - 1];
		if ((const char *)last->iov_base + last->iov_len == base) {
			last->iov_len += len;
			return 0;
		}
	}
	if (sink->nr_iov == HOT_FG_WRITEV_MAX)
		return -1;
	sink->iov[sink->nr_iov].iov_base = (void *)base;
	sink->iov[sink->nr_iov].iov_len = len;
	sink->nr_iov++;
	return 0;
}

static void dsa_fg_sidecar_sink_advance_iov(struct dsa_fg_sidecar_sink *sink,
						      u64 bytes)
{
	while (bytes && sink->iov_head < sink->nr_iov) {
		struct iovec *iov = &sink->iov[sink->iov_head];

		if (bytes >= iov->iov_len) {
			bytes -= iov->iov_len;
			sink->iov_head++;
		} else {
			iov->iov_base = (char *)iov->iov_base + bytes;
			iov->iov_len -= bytes;
			bytes = 0;
		}
	}
}

static int dsa_fg_sidecar_sink_write_full(struct dsa_fg_sidecar_sink *sink,
						  int fd, const void *buf, size_t len,
						  u64 *syscalls)
{
	const char *p = buf;
	struct dsa_direct_stream *dio = fd == sink->idx_fd ? sink->idx_dio : sink->dat_dio;

	if (dio && dio->enabled)
		return dsa_direct_stream_write(dio, buf, len, syscalls);

	while (len) {
		ssize_t ret;

		if (sink->stats.enabled)
			dsa_fg_sidecar_stats_add(syscalls, 1);
		ret = write(fd, p, len);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		p += ret;
		len -= ret;
	}
	return 0;
}

static int dsa_fg_sidecar_sink_writev_full(struct dsa_fg_sidecar_sink *sink,
						   struct iovec *iov, unsigned int nr)
{
	unsigned int head = 0;

	if (sink->dat_dio && sink->dat_dio->enabled) {
		for (head = 0; head < nr; head++)
			if (dsa_direct_stream_write(sink->dat_dio, iov[head].iov_base,
						    iov[head].iov_len,
						    sink->stats.dat_writev_syscalls))
				return -1;
		return 0;
	}

	if (!nr || nr > HOT_FG_WRITEV_MAX) {
		errno = EINVAL;
		return -1;
	}
	while (head < nr) {
		ssize_t ret;

		if (sink->stats.enabled)
			dsa_fg_sidecar_stats_add(sink->stats.dat_writev_syscalls, 1);
		ret = writev(sink->dat_fd, &iov[head], nr - head);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0) {
			errno = EIO;
			return -1;
		}
		while (head < nr && ret >= (ssize_t)iov[head].iov_len) {
			ret -= iov[head].iov_len;
			head++;
		}
		if (head < nr && ret) {
			iov[head].iov_base = (char *)iov[head].iov_base + ret;
			iov[head].iov_len -= ret;
		}
	}
	return 0;
}

static int dsa_fg_sidecar_sink_flush(struct dsa_fg_sidecar_sink *sink)
{
	if (!sink->nr_metas)
		return 0;
	{
		u64 start_us = sink->stats.enabled ? dsa_profile_wall_now_us() : 0;

		if (dsa_fg_sidecar_sink_write_full(sink, sink->idx_fd, sink->metas,
						   sink->nr_metas * sizeof(sink->metas[0]),
						   sink->stats.idx_write_syscalls)) {
			pr_perror("DSA fine-grained bounded index write failed");
			return -1;
		}
		if (sink->stats.enabled)
			dsa_fg_sidecar_stats_add(sink->stats.idx_write_us,
						 dsa_profile_delta_us(start_us,
								      dsa_profile_wall_now_us()));
	}
	if (sink->stats.enabled) {
		dsa_fg_sidecar_stats_add(sink->stats.idx_write_calls, 1);
		dsa_fg_sidecar_stats_add(sink->stats.idx_bytes,
					 sink->nr_metas * sizeof(sink->metas[0]));
		dsa_fg_sidecar_stats_add(sink->stats.write_units, 1);
	}
	while (sink->iov_head < sink->nr_iov) {
		u64 bytes = 0;
		u64 start_us = 0;
		unsigned int nr = 0;
		unsigned int i;

		for (i = sink->iov_head; i < sink->nr_iov &&
		     bytes < HOT_FG_OUTPUT_WRITE_BYTES; i++) {
			u64 len = sink->iov[i].iov_len;

			if (len > HOT_FG_OUTPUT_WRITE_BYTES - bytes)
				len = HOT_FG_OUTPUT_WRITE_BYTES - bytes;
			sink->write_iov[nr] = sink->iov[i];
			sink->write_iov[nr].iov_len = len;
			nr++;
			bytes += len;
		}
		if (!nr) {
			errno = EIO;
			return -1;
		}
		if (sink->stats.enabled)
			start_us = dsa_profile_wall_now_us();
		if (dsa_fg_sidecar_sink_writev_full(sink, sink->write_iov, nr)) {
			pr_perror("DSA fine-grained bounded data write failed");
			return -1;
		}
		dsa_fg_sidecar_sink_advance_iov(sink, bytes);
		if (sink->stats.enabled) {
			u64 elapsed = dsa_profile_delta_us(start_us,
							  dsa_profile_wall_now_us());

			dsa_fg_sidecar_stats_add(sink->stats.dat_writev_calls, 1);
			dsa_fg_sidecar_stats_add(sink->stats.write_units, 1);
			dsa_fg_sidecar_stats_add(sink->stats.dat_write_us, elapsed);
			if (sink->stats.write_unit_max_us &&
			    elapsed > *sink->stats.write_unit_max_us)
				*sink->stats.write_unit_max_us = elapsed;
		}
	}
	dsa_fg_sidecar_sink_reset_chunk(sink);
	return 0;
}

static int dsa_fg_sidecar_sink_append(struct dsa_fg_sidecar_sink *sink,
					      const struct dsa_fg_page_meta *input,
					      const struct dsa_fg_patch_entry *patches,
					      const struct iovec *payload,
					      unsigned int nr_payload)
{
	struct dsa_fg_page_meta *meta;
	u64 data_len = input->data_len;
	u64 payload_bytes = 0;
	unsigned int needed_iov = nr_payload + (input->patch_count ? 1 : 0);
	unsigned int i;

	for (i = 0; i < nr_payload; i++) {
		if (!payload[i].iov_len || payload[i].iov_len > UINT64_MAX - payload_bytes) {
			errno = EINVAL;
			return -1;
		}
		payload_bytes += payload[i].iov_len;
	}
	if (input->patch_count > DSA_FG_MAX_PATCHES ||
	    (input->flags != DSA_FG_PAGE_PARENT &&
	     input->flags != DSA_FG_PAGE_PATCH &&
	     input->flags != DSA_FG_PAGE_FULL) ||
	    (!input->patch_count && patches) ||
	    (input->patch_count && !patches) ||
	    nr_payload > DSA_FG_MAX_PATCHES ||
	    needed_iov > HOT_FG_WRITEV_MAX ||
	    data_len > HOT_FG_OUTPUT_LOGICAL_BYTES ||
	    (input->flags == DSA_FG_PAGE_PATCH && !input->patch_count) ||
	    (input->flags != DSA_FG_PAGE_PATCH && input->patch_count) ||
	    (input->patch_count && nr_payload != input->patch_count) ||
	    (!input->patch_count && input->flags != DSA_FG_PAGE_FULL && nr_payload) ||
	    (input->flags == DSA_FG_PAGE_FULL && nr_payload != 1) ||
	    (input->flags == DSA_FG_PAGE_PARENT && (data_len || nr_payload)) ||
	    (input->flags == DSA_FG_PAGE_FULL &&
	     (data_len != PAGE_SIZE || payload_bytes != PAGE_SIZE)) ||
	    (input->flags == DSA_FG_PAGE_PATCH &&
	     (payload_bytes > UINT64_MAX -
		input->patch_count * sizeof(struct dsa_fg_patch_entry) ||
	      data_len != input->patch_count * sizeof(struct dsa_fg_patch_entry) +
		payload_bytes))) {
		errno = EINVAL;
		return -1;
	}
	if (sink->nr_metas &&
	    (sink->nr_metas == HOT_FG_OUTPUT_META_MAX ||
	     input->patch_count > HOT_FG_OUTPUT_META_MAX * DSA_FG_MAX_PATCHES - sink->nr_patches ||
	     needed_iov > HOT_FG_WRITEV_MAX - sink->nr_iov ||
	     data_len > HOT_FG_OUTPUT_LOGICAL_BYTES - sink->chunk_dat_bytes)) {
		if (dsa_fg_sidecar_sink_flush(sink))
			return -1;
	}
	if (input->patch_count > HOT_FG_OUTPUT_META_MAX * DSA_FG_MAX_PATCHES - sink->nr_patches ||
	    needed_iov > HOT_FG_WRITEV_MAX - sink->nr_iov ||
	    data_len > HOT_FG_OUTPUT_LOGICAL_BYTES - sink->chunk_dat_bytes ||
	    sink->dat_off < 0 || data_len > (u64)LLONG_MAX - (u64)sink->dat_off) {
		errno = EOVERFLOW;
		return -1;
	}

	meta = &sink->metas[sink->nr_metas++];
	*meta = *input;
	meta->data_off = sink->dat_off;
	if (input->patch_count) {
		struct dsa_fg_patch_entry *chunk_patches = &sink->patches[sink->nr_patches];

		memcpy(chunk_patches, patches, input->patch_count * sizeof(*patches));
		sink->nr_patches += input->patch_count;
		if (dsa_fg_sidecar_sink_append_iov(sink, chunk_patches,
						       input->patch_count * sizeof(*patches)))
			return -1;
	}
	for (i = 0; i < nr_payload; i++) {
		if (!payload[i].iov_len ||
		    dsa_fg_sidecar_sink_append_iov(sink, payload[i].iov_base,
						       payload[i].iov_len))
			return -1;
	}
	sink->dat_off += data_len;
	sink->chunk_dat_bytes += data_len;
	if (sink->stats.enabled)
		dsa_fg_sidecar_stats_add(sink->stats.dat_bytes, data_len);
	return 0;
}

static int hot_fg_write_full(struct hot_apply_ctx *ctx, unsigned long vaddr,
			     const void *cur)
{
	struct dsa_fg_page_meta meta = {};
	off_t data_off;

	data_off = ctx->fg_dat_off;
	if (write_full_fd(ctx->fg_dat_fd, cur, PAGE_SIZE)) {
		pr_perror("DSA fine-grained full page write failed");
		return -1;
	}
	ctx->fg_dat_off += PAGE_SIZE;

	meta.vaddr = vaddr;
	meta.data_off = data_off;
	meta.data_len = PAGE_SIZE;
	meta.patch_count = 0;
	meta.flags = DSA_FG_PAGE_FULL;
	if (hot_fg_write_meta(ctx, &meta))
		return -1;

	if (ctx->profile) {
		ctx->fg_pages++;
		ctx->fg_full_pages++;
		ctx->fg_patch_bytes += PAGE_SIZE;
	}
	return 0;
}

static int hot_fg_write_patch(struct hot_apply_ctx *ctx, unsigned long vaddr,
			      const void *cur, const void *old)
{
	struct dsa_fg_patch_entry patches[PAGE_SIZE / DSA_FG_PATCH_SIZE];
	struct iovec data_iov[DSA_FG_MAX_PATCHES];
	unsigned int patch_count = 0;
	unsigned int bytes = 0;
	unsigned int cursor = 0;
	struct dsa_fg_page_meta meta = {};
	off_t data_off;

	while (cursor < PAGE_SIZE) {
		unsigned int diff;
		unsigned int len;
		bool equal;

		if (hot_dsa_compare_first_diff(ctx,
					       (const char *)cur + cursor,
					       (const char *)old + cursor,
					       PAGE_SIZE - cursor,
					       &equal, &diff))
			return -1;
		if (equal)
			break;
		diff += cursor;

		len = PAGE_SIZE - diff;
		if (len > DSA_FG_PATCH_SIZE)
			len = DSA_FG_PATCH_SIZE;
		if (patch_count == sizeof(patches) / sizeof(patches[0]) ||
		    patch_count + 1 > DSA_FG_MAX_PATCHES ||
		    bytes + len > DSA_FG_MAX_BYTES)
			return hot_fg_write_full(ctx, vaddr, cur);

		patches[patch_count].off = diff;
		patches[patch_count].len = len;
		data_iov[patch_count].iov_base = (void *)((const char *)cur + diff);
		data_iov[patch_count].iov_len = len;
		patch_count++;
		bytes += len;
		cursor = diff + len;
	}

	data_off = ctx->fg_dat_off;
	if (patch_count) {
		if (write_full_fd(ctx->fg_dat_fd, patches,
				  patch_count * sizeof(patches[0])) ||
		    hot_fg_writev_full_fd(ctx->fg_dat_fd, data_iov, patch_count)) {
			pr_perror("DSA fine-grained patch write failed");
			return -1;
		}
		ctx->fg_dat_off += patch_count * sizeof(patches[0]) + bytes;
	}

	meta.vaddr = vaddr;
	meta.data_off = data_off;
	meta.data_len = patch_count * sizeof(patches[0]) + bytes;
	meta.patch_count = patch_count;
	meta.flags = patch_count ? DSA_FG_PAGE_PATCH : DSA_FG_PAGE_PARENT;
	if (hot_fg_write_meta(ctx, &meta))
		return -1;

	if (ctx->profile) {
		ctx->fg_pages++;
		if (patch_count) {
			ctx->fg_patch_pages++;
			ctx->fg_patch_bytes += bytes;
		}
	}
	return 0;
}

static int hot_fg_write_page(struct hot_apply_ctx *ctx, unsigned long vaddr,
			     const void *cur)
{
	struct hot_memstore_seg *old;
	void *old_map;

	old = hot_memstore_find_old_cover(ctx, vaddr, vaddr + PAGE_SIZE);
	if (!old)
		return hot_fg_write_full(ctx, vaddr, cur);

	old_map = hot_memstore_old_map(ctx, old);
	if (old_map == MAP_FAILED)
		return -1;

	return hot_fg_write_patch(ctx, vaddr, cur,
			  (const char *)old_map + (vaddr - old->vaddr));
}

enum hot_fg_raw_page_state {
	HOT_FG_RAW_PENDING = 0,
	HOT_FG_RAW_CPU_FAULT,
	HOT_FG_RAW_PARENT,
	HOT_FG_RAW_PATCH,
	HOT_FG_RAW_FULL,
};

struct hot_fg_raw_page {
	unsigned long vaddr;
	const unsigned char *raw;
	const unsigned char *parent;
	u32 cursor;
	u32 patch_bytes;
	u16 patch_count;
	u16 state;
	struct dsa_fg_patch_entry patches[DSA_FG_MAX_PATCHES];
};

struct hot_fg_compare_slot {
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	struct hot_fg_compare_span *span;
	u32 submitted_cursor;
	u32 submitted_len;
	u32 wq_idx;
	u64 submit_sequence;
	u64 submit_ns;
	u64 completion_deadline_ns;
	bool active;
};

struct hot_fg_compare_child_meta {
	struct hot_fg_compare_span *span;
	u32 submitted_cursor;
	u32 submitted_len;
	u64 submit_sequence;
};

struct hot_fg_compare_batch {
	struct dsa_hw_desc child_desc[HOT_DSA_COMPARE_BATCH_CHILDREN]
		__attribute__((aligned(64)));
	volatile struct dsa_completion_record child_comp[HOT_DSA_COMPARE_BATCH_CHILDREN]
		__attribute__((aligned(32)));
	struct hot_fg_compare_child_meta child[HOT_DSA_COMPARE_BATCH_CHILDREN];
	struct dsa_hw_desc outer_desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record outer_comp __attribute__((aligned(32)));
	u32 child_count;
	u32 wq_idx;
	u64 submit_ns;
	u64 completion_deadline_ns;
	bool direct_single;
	bool active;
};

enum hot_fg_compare_span_state {
	HOT_FG_SPAN_UNPREFAULTED = 0,
	HOT_FG_SPAN_READY,
	HOT_FG_SPAN_ACTIVE,
	HOT_FG_SPAN_DONE,
};

struct hot_fg_compare_span {
	const unsigned char *raw;
	const unsigned char *parent;
	size_t first_page;
	size_t page_count;
	u32 length;
	u32 cursor;
	size_t finalized_pages;
	u8 state;
};

struct hot_fg_ready_queue {
	size_t *indices;
	struct hot_fg_compare_span *spans;
	size_t capacity;
	size_t head;
	size_t tail;
	size_t nr;
};

struct hot_fg_output_state {
	struct hot_apply_ctx *ctx;
	struct hot_fg_raw_page *pages;
	size_t nr_pages;
	size_t next_page;
	struct dsa_fg_sidecar_sink sink;
};

static int hot_fg_raw_pages_append(struct hot_apply_ctx *ctx,
				   struct hot_fg_raw_page **pages, size_t *nr,
				   size_t *cap, unsigned long vaddr,
				   const unsigned char *raw)
{
	struct hot_fg_raw_page *page;
	struct hot_memstore_seg *old;
	void *old_map;

	if (*nr == *cap) {
		size_t new_cap = *cap ? *cap * 2 : 4096;
		void *new_pages = xrealloc(*pages, new_cap * sizeof(**pages));

		if (!new_pages)
			return -1;
		*pages = new_pages;
		*cap = new_cap;
	}
	page = &(*pages)[(*nr)++];
	memset(page, 0, sizeof(*page));
	page->vaddr = vaddr;
	page->raw = raw;
	page->state = HOT_FG_RAW_PENDING;

	old = hot_memstore_find_old_cover(ctx, vaddr, vaddr + PAGE_SIZE);
	if (!old) {
		page->state = HOT_FG_RAW_FULL;
		return 0;
	}
	old_map = hot_memstore_old_map(ctx, old);
	if (old_map == MAP_FAILED)
		return -1;
	page->parent = (const unsigned char *)old_map + (vaddr - old->vaddr);
	return 0;
}

static int hot_fg_ready_queue_init(struct hot_fg_ready_queue *queue,
				   struct hot_fg_compare_span *spans,
				   size_t nr_spans)
{
	memset(queue, 0, sizeof(*queue));
	queue->indices = xmalloc(nr_spans * sizeof(*queue->indices));
	if (!queue->indices)
		return -1;
	queue->spans = spans;
	queue->capacity = nr_spans;
	return 0;
}

static void hot_fg_ready_queue_fini(struct hot_fg_ready_queue *queue)
{
	xfree(queue->indices);
	queue->indices = NULL;
}

static int hot_fg_ready_queue_push(struct hot_fg_ready_queue *queue,
				   size_t span_idx)
{
	struct hot_fg_compare_span *span;

	if (span_idx >= queue->capacity || queue->nr >= queue->capacity)
		return -1;
	span = &queue->spans[span_idx];
	if (span->state != HOT_FG_SPAN_READY)
		return -1;
	queue->indices[queue->tail] = span_idx;
	queue->tail = (queue->tail + 1) % queue->capacity;
	queue->nr++;
	return 0;
}

static int hot_fg_ready_queue_pop(struct hot_fg_ready_queue *queue,
				  size_t *span_idx)
{
	if (!queue->nr)
		return 1;
	*span_idx = queue->indices[queue->head];
	queue->head = (queue->head + 1) % queue->capacity;
	queue->nr--;
	return 0;
}

static int hot_fg_output_drain(struct hot_fg_output_state *out)
{
	struct hot_apply_ctx *ctx = out->ctx;

	while (out->next_page < out->nr_pages) {
		struct hot_fg_raw_page *page = &out->pages[out->next_page];
		struct dsa_fg_page_meta meta = {};
		struct iovec payload[DSA_FG_MAX_PATCHES];
		unsigned int nr_payload = 0;
		unsigned int i;

		if (page->state != HOT_FG_RAW_PARENT &&
		    page->state != HOT_FG_RAW_PATCH &&
		    page->state != HOT_FG_RAW_FULL) {
			pr_err("DSA fine-grained output has incomplete page=%zu vaddr=%lx state=%u\n",
			       out->next_page, page->vaddr, page->state);
			return -1;
		}
		meta.vaddr = page->vaddr;
		if (page->state == HOT_FG_RAW_FULL) {
			meta.flags = DSA_FG_PAGE_FULL;
			meta.data_len = PAGE_SIZE;
			payload[nr_payload++] = (struct iovec) {
				.iov_base = (void *)page->raw,
				.iov_len = PAGE_SIZE,
			};
		} else if (page->state == HOT_FG_RAW_PATCH) {
			if (!page->patch_count || page->patch_count > DSA_FG_MAX_PATCHES ||
			    page->patch_bytes > DSA_FG_MAX_BYTES) {
				pr_err("DSA fine-grained sidecar has invalid patch page vaddr=%lx\n",
				       page->vaddr);
				return -1;
			}
			meta.flags = DSA_FG_PAGE_PATCH;
			meta.patch_count = page->patch_count;
			meta.data_len = page->patch_count * sizeof(page->patches[0]) +
				page->patch_bytes;
			for (i = 0; i < page->patch_count; i++) {
				payload[nr_payload++] = (struct iovec) {
					.iov_base = (void *)(page->raw + page->patches[i].off),
					.iov_len = page->patches[i].len,
				};
			}
		} else if (page->state == HOT_FG_RAW_PARENT) {
			meta.flags = DSA_FG_PAGE_PARENT;
		} else {
			pr_err("DSA fine-grained sidecar has invalid final page state=%u\n",
			       page->state);
			return -1;
		}
		if (!ctx->profile_output_start_us && ctx->profile)
			ctx->profile_output_start_us = dsa_profile_wall_now_us();
		if (dsa_fg_sidecar_sink_append(&out->sink, &meta,
					       meta.patch_count ? page->patches : NULL,
					       payload, nr_payload)) {
			pr_perror("DSA fine-grained sidecar chunk append failed");
			return -1;
		}
		ctx->fg_pages++;
		if (page->state == HOT_FG_RAW_FULL) {
			ctx->fg_full_pages++;
			ctx->fg_patch_bytes += PAGE_SIZE;
		} else if (page->state == HOT_FG_RAW_PATCH) {
			ctx->fg_patch_pages++;
			ctx->fg_patch_bytes += page->patch_bytes;
			if (ctx->profile)
				ctx->profile_patch_ranges += page->patch_count;
		} else if (ctx->profile) {
			ctx->profile_parent_pages++;
		}
		out->next_page++;
	}
	if (dsa_fg_sidecar_sink_flush(&out->sink))
		return -1;
	ctx->fg_dat_off = out->sink.dat_off;
	return 0;
}

/* Validate the result against the frozen capture geometry before creating any
 * durable sidecar file.  This is intentionally metadata-only: it neither
 * rereads payload bytes nor reconstructs the legacy raw-page array. */
static int dsa_fg_canonical_preflight(struct page_xfer *xfer,
					     const unsigned char *shared,
					     size_t *nr_results, u64 *dat_bytes)
{
	u32 desc_off;
	u32 raw_off;
	size_t result_index = 0;
	size_t result_count;
	u64 expected_dat = 0;
	u64 previous_vaddr = 0;
	bool have_previous = false;

	if (!xfer || !shared || !nr_results || !dat_bytes ||
	    !xfer->dsa_fg_result_meta_base ||
	    xfer->dsa_fg_result_meta_head < xfer->dsa_fg_result_meta_base ||
	    xfer->dsa_fg_result_meta_head > xfer->dsa_fg_result_meta_limit ||
	    (xfer->dsa_fg_result_meta_head - xfer->dsa_fg_result_meta_base) %
		sizeof(struct parasite_dsa_fg_result) ||
	    xfer->dsa_fg_desc_head < xfer->dsa_fg_desc_area_off ||
	    (xfer->dsa_fg_desc_head - xfer->dsa_fg_desc_area_off) %
		sizeof(struct dsa_dump_descriptor) ||
	    xfer->dsa_fg_raw_payload_head < xfer->dsa_fg_raw_payload_base) {
		pr_err("DSA fine-grained canonical result bounds are invalid\n");
		return -1;
	}
	result_count = (xfer->dsa_fg_result_meta_head -
			xfer->dsa_fg_result_meta_base) /
		sizeof(struct parasite_dsa_fg_result);
	raw_off = xfer->dsa_fg_raw_payload_base;
	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    desc->src_addr & (PAGE_SIZE - 1) ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off) {
			pr_err("DSA fine-grained canonical descriptor is invalid off=%u\n",
			       desc_off);
			return -1;
		}
		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			const struct parasite_dsa_fg_result *res;
			u32 raw_page_off = raw_off + page_off;
			u64 expected_vaddr = desc->src_addr + page_off;
			u32 sum = 0;
			u16 j;
			u16 previous_end = 0;

			if (result_index == result_count || expected_vaddr < desc->src_addr) {
				pr_err("DSA fine-grained canonical result count/vaddr overflow\n");
				return -1;
			}
			res = (const struct parasite_dsa_fg_result *)(shared +
				xfer->dsa_fg_result_meta_base +
				result_index * sizeof(*res));
			if (res->vaddr != expected_vaddr ||
			    (have_previous && res->vaddr <= previous_vaddr)) {
				pr_err("DSA fine-grained canonical result order mismatch idx=%zu vaddr=%" PRIx64 " expected=%" PRIx64 "\n",
				       result_index, res->vaddr, expected_vaddr);
				return -1;
			}
			have_previous = true;
			previous_vaddr = res->vaddr;
			if (res->flags == DSA_FG_PAGE_PARENT) {
				if (res->data_len || res->patch_count)
					goto invalid;
			} else if (res->flags == DSA_FG_PAGE_FULL) {
				if (res->data_len != PAGE_SIZE || res->patch_count ||
				    res->data_off != raw_page_off)
					goto invalid;
				if (expected_dat > UINT64_MAX - PAGE_SIZE)
					goto invalid;
				expected_dat += PAGE_SIZE;
			} else if (res->flags == DSA_FG_PAGE_PATCH) {
				u64 wire_len;

				if (!res->patch_count || res->patch_count > DSA_FG_MAX_PATCHES ||
				    res->data_len > DSA_FG_MAX_BYTES)
					goto invalid;
				for (j = 0; j < res->patch_count; j++) {
					const struct parasite_dsa_fg_result_entry *entry =
						&res->entries[j];

					if (!entry->len || (u32)entry->off + entry->len > PAGE_SIZE ||
					    (j && entry->off < previous_end) ||
					    entry->data_off != raw_page_off + entry->off)
						goto invalid;
					previous_end = entry->off + entry->len;
					sum += entry->len;
				}
				if (sum != res->data_len)
					goto invalid;
				wire_len = (u64)res->patch_count *
					sizeof(struct dsa_fg_patch_entry) + res->data_len;
				if (wire_len > UINT64_MAX - expected_dat)
					goto invalid;
				expected_dat += wire_len;
			} else {
				goto invalid;
			}
			result_index++;
			continue;
invalid:
			pr_err("DSA fine-grained canonical result is invalid idx=%zu vaddr=%" PRIx64 " flags=%u\n",
			       result_index, res->vaddr, res->flags);
			return -1;
		}
		raw_off += desc->copy_len;
	}
	if (raw_off != xfer->dsa_fg_raw_payload_head || result_index != result_count) {
		pr_err("DSA fine-grained canonical result/raw count mismatch results=%zu/%zu raw=%u/%u\n",
		       result_index, result_count, raw_off,
		       xfer->dsa_fg_raw_payload_head);
		return -1;
	}
	*nr_results = result_count;
	*dat_bytes = expected_dat;
	return 0;
}

/* Service mode consumes only the release-published canonical result array.
 * The common sink owns batching, partial-write handling and output offsets;
 * the adapter below only converts its compact PATCH entries to wire entries. */
static int page_xfer_dsa_fg_write_sidecar_results(struct page_xfer *xfer,
						  const void *shared_ptr)
{
	char idx_path[64];
	char dat_path[64];
	const unsigned char *shared = shared_ptr;
	struct dsa_fg_sidecar_sink *sink = NULL;
	struct stat idx_st;
	struct stat dat_st;
	size_t nr_results;
	u64 expected_dat;
	size_t i;
	int idx_fd = -1;
	int dat_fd = -1;
	struct dsa_direct_stream idx_dio = {};
	struct dsa_direct_stream dat_dio = {};
	int dfd = get_service_fd(IMG_FD_OFF);
	int ret = -1;
	bool profile;
	bool direct;
	void *idx_scratch = NULL;
	void *dat_scratch = NULL;
	u64 phase_start_us = 0;
	u64 serialize_start_us = 0;

	profile = xfer && xfer->dsa_fg_service_profile.enabled && dsa_profile_enabled();
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (dsa_fg_canonical_preflight(xfer, shared, &nr_results, &expected_dat))
		return -1;
	if (profile)
		xfer->dsa_fg_service_profile.sidecar_preflight_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	if (expected_dat > LLONG_MAX) {
		pr_err("DSA fine-grained canonical dat size is too large=%" PRIu64 "\n",
		       expected_dat);
		return -1;
	}
	direct = xfer->dsa_output_direct;
	if (direct && xfer->dsa_fg_service) {
		if (!xfer->dsa_fg_shared ||
		    xfer->dsa_dio_idx_scratch_off % PAGE_SIZE ||
		    xfer->dsa_dio_dat_scratch_off !=
			    xfer->dsa_dio_idx_scratch_off +
				    DSA_DIRECT_METADATA_STAGE_BYTES ||
		    xfer->dsa_dio_pagemap_scratch_off !=
			    xfer->dsa_dio_dat_scratch_off +
				    DSA_DIRECT_PAYLOAD_STAGE_BYTES ||
		    xfer->dsa_dio_scratch_limit !=
			    xfer->dsa_dio_pagemap_scratch_off +
				    DSA_DIRECT_METADATA_STAGE_BYTES ||
		    xfer->dsa_dio_scratch_limit > xfer->dsa_fg_result_meta_base ||
		    xfer->dsa_fg_raw_payload_head >
			    xfer->dsa_dio_idx_scratch_off) {
			pr_err("DSA fine-grained direct scratch bounds are invalid idx=%u dat=%u pagemap=%u limit=%u raw_head=%u result=%u\n",
			       xfer->dsa_dio_idx_scratch_off,
			       xfer->dsa_dio_dat_scratch_off,
			       xfer->dsa_dio_pagemap_scratch_off,
			       xfer->dsa_dio_scratch_limit,
			       xfer->dsa_fg_raw_payload_head,
			       xfer->dsa_fg_result_meta_base);
			return -1;
		}
		idx_scratch = (unsigned char *)xfer->dsa_fg_shared +
			xfer->dsa_dio_idx_scratch_off;
		dat_scratch = (unsigned char *)xfer->dsa_fg_shared +
			xfer->dsa_dio_dat_scratch_off;
	}
	if (profile) {
		xfer->dsa_fg_service_profile.idx_write_calls = 0;
		xfer->dsa_fg_service_profile.idx_bytes = 0;
		xfer->dsa_fg_service_profile.dat_write_calls = 0;
		xfer->dsa_fg_service_profile.dat_writev_calls = 0;
		xfer->dsa_fg_service_profile.dat_bytes = 0;
		xfer->dsa_fg_service_profile.sidecar_serialize_us = 0;
		xfer->dsa_fg_service_profile.sidecar_idx_write_us = 0;
		xfer->dsa_fg_service_profile.sidecar_dat_write_us = 0;
		xfer->dsa_fg_service_profile.idx_write_syscalls = 0;
		xfer->dsa_fg_service_profile.dat_write_syscalls = 0;
		xfer->dsa_fg_service_profile.dat_writev_syscalls = 0;
		xfer->dsa_fg_service_profile.sidecar_lseek_syscalls = 0;
	}
	if (profile)
		serialize_start_us = dsa_profile_wall_now_us();

	snprintf(idx_path, sizeof(idx_path), "pages-fg-%u.idx", xfer->pages_id);
	idx_fd = openat(dfd, idx_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC |
			(direct ? O_DIRECT : 0),
			CR_FD_PERM);
	if (idx_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", idx_path);
		goto out;
	}
	snprintf(dat_path, sizeof(dat_path), "pages-fg-%u.dat", xfer->pages_id);
	dat_fd = openat(dfd, dat_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC |
			(direct ? O_DIRECT : 0),
			CR_FD_PERM);
	if (dat_fd < 0) {
		pr_perror("DSA fine-grained can't open %s", dat_path);
		goto out;
	}
	sink = xzalloc(sizeof(*sink));
	if (!sink)
		goto out;
	if (dsa_direct_stream_init(&idx_dio, idx_fd, direct,
				   DSA_DIRECT_METADATA_STAGE_BYTES,
				   idx_scratch) ||
	    dsa_direct_stream_init(&dat_dio, dat_fd, direct,
				   DSA_DIRECT_PAYLOAD_STAGE_BYTES,
				   dat_scratch)) {
		pr_perror("DSA fine-grained direct sidecar staging allocation failed");
		goto out;
	}
	sink->idx_fd = idx_fd;
	sink->dat_fd = dat_fd;
	sink->idx_dio = &idx_dio;
	sink->dat_dio = &dat_dio;
	sink->stats = (struct dsa_fg_sidecar_stats) {
		.enabled = profile,
		.idx_write_calls = &xfer->dsa_fg_service_profile.idx_write_calls,
		.idx_bytes = &xfer->dsa_fg_service_profile.idx_bytes,
		.dat_write_calls = &xfer->dsa_fg_service_profile.dat_write_calls,
		.dat_writev_calls = &xfer->dsa_fg_service_profile.dat_writev_calls,
		.dat_bytes = &xfer->dsa_fg_service_profile.dat_bytes,
		.idx_write_syscalls = &xfer->dsa_fg_service_profile.idx_write_syscalls,
		.dat_write_syscalls = &xfer->dsa_fg_service_profile.dat_write_syscalls,
		.dat_writev_syscalls = &xfer->dsa_fg_service_profile.dat_writev_syscalls,
		.idx_write_us = &xfer->dsa_fg_service_profile.sidecar_idx_write_us,
		.dat_write_us = &xfer->dsa_fg_service_profile.sidecar_dat_write_us,
	};

	for (i = 0; i < nr_results; i++) {
		const struct parasite_dsa_fg_result *res =
			(const struct parasite_dsa_fg_result *)(shared +
				xfer->dsa_fg_result_meta_base + i * sizeof(*res));
		struct dsa_fg_page_meta meta = {
			.vaddr = res->vaddr,
			.patch_count = res->patch_count,
			.flags = res->flags,
		};
		struct dsa_fg_patch_entry patches[DSA_FG_MAX_PATCHES];
		struct iovec payload[DSA_FG_MAX_PATCHES];
		unsigned int nr_payload = 0;
		u16 j;

		if (res->flags == DSA_FG_PAGE_FULL) {
			meta.data_len = PAGE_SIZE;
			payload[nr_payload++] = (struct iovec) {
				.iov_base = (void *)(shared + res->data_off),
				.iov_len = PAGE_SIZE,
			};
		} else if (res->flags == DSA_FG_PAGE_PATCH) {
			meta.data_len = res->patch_count * sizeof(patches[0]) +
				res->data_len;
			for (j = 0; j < res->patch_count; j++) {
				patches[j] = (struct dsa_fg_patch_entry) {
					.off = res->entries[j].off,
					.len = res->entries[j].len,
				};
				payload[nr_payload++] = (struct iovec) {
					.iov_base = (void *)(shared + res->entries[j].data_off),
					.iov_len = res->entries[j].len,
				};
			}
		}
		if (dsa_fg_sidecar_sink_append(sink, &meta,
					       res->flags == DSA_FG_PAGE_PATCH ? patches : NULL,
					       payload, nr_payload)) {
			pr_perror("DSA fine-grained canonical sidecar append failed");
			goto out;
		}
	}
	if (dsa_fg_sidecar_sink_flush(sink))
		goto out;
	if (dsa_direct_stream_finish(&idx_dio,
				     sink->stats.idx_write_syscalls) ||
	    dsa_direct_stream_finish(&dat_dio,
				     sink->stats.dat_writev_syscalls)) {
		pr_perror("DSA fine-grained direct sidecar finish failed");
		goto out;
	}
	if (fstat(idx_fd, &idx_st) || fstat(dat_fd, &dat_st)) {
		pr_perror("DSA fine-grained canonical sidecar fstat failed");
		goto out;
	}
	if ((u64)sink->dat_off != expected_dat ||
	    (u64)idx_st.st_size != nr_results * sizeof(struct dsa_fg_page_meta) ||
	    (u64)dat_st.st_size != expected_dat) {
		pr_err("DSA fine-grained canonical sidecar size mismatch idx=%" PRIu64
		       "/%zu dat=%" PRIu64 "/%" PRIu64 " cursor=%" PRIu64 "\n",
		       (u64)idx_st.st_size, nr_results * sizeof(struct dsa_fg_page_meta),
		       (u64)dat_st.st_size, expected_dat, (u64)sink->dat_off);
		goto out;
	}
	if (profile) {
		u64 elapsed = dsa_profile_delta_us(serialize_start_us,
						  dsa_profile_wall_now_us());
		u64 writes = xfer->dsa_fg_service_profile.sidecar_idx_write_us +
			xfer->dsa_fg_service_profile.sidecar_dat_write_us;

		xfer->dsa_fg_service_profile.sidecar_serialize_us =
			elapsed >= writes ? elapsed - writes : 0;
	}
	ret = 0;
out:
	dsa_direct_stream_fini(&dat_dio);
	dsa_direct_stream_fini(&idx_dio);
	xfree(sink);
	if (dat_fd >= 0 && close(dat_fd))
		ret = -1;
	if (idx_fd >= 0 && close(idx_fd))
		ret = -1;
	return ret;
}

static int hot_fg_compare_submit(struct hot_apply_ctx *ctx,
				  struct hot_fg_compare_slot *slot,
				  struct hot_fg_compare_span *span,
				  u64 submit_sequence, u64 submit_ns)
{
	unsigned int wq_idx;
	unsigned long portal_mask;
	unsigned long off;
	uint32_t retry;

	if (!span->parent || span->state != HOT_FG_SPAN_READY ||
	    span->cursor >= span->length || !ctx->dsa_wq_count ||
	    !ctx->dsa_max_transfer_size)
		return -1;
	wq_idx = ctx->dsa_next_wq++ % (unsigned int)ctx->dsa_wq_count;
	portal_mask = ((unsigned long)ctx->dsa_portals[wq_idx]) & ~0xfffUL;
	memset(&slot->desc, 0, sizeof(slot->desc));
	memset((void *)&slot->comp, 0, sizeof(slot->comp));
	slot->submitted_cursor = span->cursor;
	slot->submitted_len = span->length - span->cursor;
	if (slot->submitted_len > ctx->dsa_max_transfer_size)
		slot->submitted_len = ctx->dsa_max_transfer_size;
	if (!slot->submitted_len)
		return -1;
	slot->wq_idx = wq_idx;
	slot->span = span;
	slot->submit_sequence = submit_sequence;
	slot->submit_ns = submit_ns;
	slot->completion_deadline_ns = submit_ns + HOT_DSA_COMPLETION_TIMEOUT_NS;
	slot->desc.opcode = DSA_OPCODE_COMPARE;
	slot->desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	slot->desc.src_addr = (uint64_t)(unsigned long)(span->raw + span->cursor);
	slot->desc.src2_addr = (uint64_t)(unsigned long)(span->parent + span->cursor);
	slot->desc.xfer_size = slot->submitted_len;
	slot->desc.completion_addr = (uint64_t)(unsigned long)&slot->comp;

	hot_dsa_release_descriptors();
	for (retry = 0; retry < HOT_DSA_MAX_ENQ_RETRY; retry++) {
		void *portal_slot;

		off = ((ctx->dsa_portal_offset[wq_idx]++ << 6) & 0xfffUL);
		portal_slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(portal_slot, &slot->desc) == 0)
			break;
		hot_dsa_cpu_relax();
	}
	if (retry == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA fine-grained compare wavefront enqcmd timed out\n");
		return -1;
	}
	if (ctx->profile) {
		ctx->fg_compare_ops++;
		ctx->dsa_enqcmd++;
		ctx->profile_compare_enq_retries += retry;
		ctx->profile_dsa_submitted_bytes += slot->submitted_len;
		if (slot->submitted_cursor)
			ctx->profile_dsa_continuation_submit_ops++;
		else
			ctx->profile_dsa_fresh_submit_ops++;
	}
	slot->active = true;
	span->state = HOT_FG_SPAN_ACTIVE;
	return 0;
}

static __attribute__((noreturn)) void
hot_fg_completion_timeout_fatal(const struct hot_fg_compare_slot *slot,
				 size_t active, u64 now_ns, const char *stage)
{
	u64 age_us = now_ns >= slot->submit_ns ?
		(now_ns - slot->submit_ns) / 1000ULL : 0;

	pr_err("CDP_DSA_COMPLETION_TIMEOUT: stage=%s exit=%u wq=%u sequence=%" PRIu64
	       " age_us=%" PRIu64 " active=%zu opcode=%u length=%u src=%" PRIx64
	       " dst=%" PRIx64 " status=%u\n",
	       stage, CDP_DSA_COMPLETION_TIMEOUT_EXIT, slot->wq_idx,
	       slot->submit_sequence, age_us, active, slot->desc.opcode,
	       slot->submitted_len, slot->desc.src_addr, slot->desc.src2_addr,
	       (unsigned int)__atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE));
	/* Do not return through page-xfer cleanup while the descriptor may still
	 * reference its completion record or the raw arena.  Process exit closes
	 * the idxd user-WQ fds; the driver drains this PASID before unbinding SVA.
	 */
	_exit(CDP_DSA_COMPLETION_TIMEOUT_EXIT);
}


enum hot_fg_nobof_completion {
	HOT_FG_NOBOF_NOT_READY = 0,
	HOT_FG_NOBOF_EQUAL,
	HOT_FG_NOBOF_DIFFERENT,
	HOT_FG_NOBOF_PAGE_FAULT,
};

/* The caller has acquire-loaded status before using the rest of the record.
 * A page fault completion has result=0; it is not an equal completion. */
static int hot_fg_compare_complete_nobof(struct hot_fg_compare_slot *slot,
					 enum hot_fg_nobof_completion *kind,
					 u32 *first_diff)
{
	uint8_t status = __atomic_load_n(&slot->comp.status, __ATOMIC_ACQUIRE);
	uint8_t code = (uint8_t)DSA_COMP_STATUS(status);

	*kind = HOT_FG_NOBOF_NOT_READY;
	if (status == 0 || code == DSA_COMP_NONE)
		return 0;
	if (code == DSA_COMP_PAGE_FAULT_NOBOF) {
		*kind = HOT_FG_NOBOF_PAGE_FAULT;
		return 0;
	}
	if (code != DSA_COMP_SUCCESS && code != DSA_COMP_SUCCESS_PRED) {
		pr_err("DSA no-BOF compare completion failed status=%u code=%u\n",
		       status, code);
		return -1;
	}
	if (slot->comp.result == 0) {
		*kind = HOT_FG_NOBOF_EQUAL;
		*first_diff = slot->submitted_len;
		return 0;
	}
	if (slot->comp.bytes_completed >= slot->submitted_len) {
		pr_err("DSA no-BOF compare returned invalid first_diff=%u bytes=%u\n",
		       slot->comp.bytes_completed, slot->submitted_len);
		return -1;
	}
	*kind = HOT_FG_NOBOF_DIFFERENT;
	*first_diff = slot->comp.bytes_completed;
	return 0;
}

static int hot_fg_span_finalize(struct hot_fg_compare_span *span,
				struct hot_fg_raw_page *pages, u32 cursor)
{
	while (span->finalized_pages < span->page_count) {
		size_t page_idx = span->finalized_pages;
		struct hot_fg_raw_page *page = &pages[span->first_page + page_idx];

		if ((page_idx + 1) * PAGE_SIZE > cursor)
			break;
		if (page->state == HOT_FG_RAW_PENDING)
			page->state = page->patch_count ? HOT_FG_RAW_PATCH :
				HOT_FG_RAW_PARENT;
		else if (page->state != HOT_FG_RAW_FULL &&
			 page->state != HOT_FG_RAW_PATCH &&
			 page->state != HOT_FG_RAW_PARENT)
			return -1;
		/* page->cursor is transient compare progress, but every finalized
		 * page has one canonical terminal value.  CPU whole-span scans may
		 * otherwise leave it at the end of the last patch while fault-page
		 * SIMD reaches PAGE_SIZE explicitly, causing semantically identical
		 * results to fail strict backend validation. */
		page->cursor = PAGE_SIZE;
		span->finalized_pages++;
	}
	return 0;
}

static int hot_fg_page_record_diff(struct hot_fg_raw_page *page, u32 page_off)
{
	u32 patch_len;

	if (!page || page_off >= PAGE_SIZE || page->cursor > page_off)
		return -1;
	patch_len = PAGE_SIZE - page_off;
	if (patch_len > DSA_FG_PATCH_SIZE)
		patch_len = DSA_FG_PATCH_SIZE;

	if (page->patch_count >= DSA_FG_MAX_PATCHES ||
	    page->patch_bytes + patch_len > DSA_FG_MAX_BYTES) {
		page->state = HOT_FG_RAW_FULL;
		page->cursor = PAGE_SIZE;
		return 0;
	}
	page->patches[page->patch_count].off = page_off;
	page->patches[page->patch_count].len = patch_len;
	page->patch_bytes += patch_len;
	page->patch_count++;
	page->cursor = page_off + patch_len;
	return 0;
}

static int hot_fg_span_record_diff(struct hot_fg_compare_span *span,
				  struct hot_fg_raw_page *pages, u32 diff)
{
	size_t page_idx;
	struct hot_fg_raw_page *page;
	u32 page_off;

	if (diff >= span->length || diff < span->cursor)
		return -1;
	if (hot_fg_span_finalize(span, pages, diff))
		return -1;

	page_idx = diff / PAGE_SIZE;
	page = &pages[span->first_page + page_idx];
	page_off = diff % PAGE_SIZE;
	if (hot_fg_page_record_diff(page, page_off))
		return -1;
	span->cursor = page_idx * PAGE_SIZE + page->cursor;
	return hot_fg_span_finalize(span, pages, span->cursor);
}

struct hot_fg_cpu_scan_stats {
	u64 memcmp_calls;
	u64 memcmp_requested_bytes;
	u64 memcmp_scalar_bytes;
	u64 scalar64_calls;
	u64 scalar64_word_ops;
	u64 scalar64_refine_bytes;
	u64 scalar64_tail_bytes;
	u64 scalar64_bytes_examined;
	u64 vector_ops;
	u64 bytes_examined;
};

static int (*volatile hot_fg_libc_memcmp)(const void *, const void *, size_t) = memcmp;

static noinline u32 __attribute__((optimize("no-tree-vectorize")))
hot_fg_scalar_first_diff(const unsigned char *raw,
			 const unsigned char *parent, u32 length)
{
	u32 cursor;

	for (cursor = 0; cursor < length; cursor++) {
		if (raw[cursor] != parent[cursor])
			return cursor;
	}
	return length;
}

static int hot_fg_memcmp_first_diff(const unsigned char *raw,
				    const unsigned char *parent, u32 length,
				    bool *equal, u32 *first_diff,
				    struct hot_fg_cpu_scan_stats *stats)
{
	u32 diff;

	if (stats) {
		stats->memcmp_calls++;
		stats->memcmp_requested_bytes += length;
	}
	if (hot_fg_libc_memcmp(raw, parent, length) == 0) {
		*equal = true;
		*first_diff = length;
		return 0;
	}

	diff = hot_fg_scalar_first_diff(raw, parent, length);
	if (diff >= length) {
		pr_err("DSA fine-grained memcmp backend couldn't recover first difference\n");
		return -1;
	}
	if (stats)
		stats->memcmp_scalar_bytes += diff + 1;
	*equal = false;
	*first_diff = diff;
	return 0;
}

static noinline int __attribute__((optimize("no-tree-vectorize", "no-tree-slp-vectorize")))
hot_fg_scalar64_first_diff(const unsigned char *raw,
			   const unsigned char *parent, u32 length,
			   bool *equal, u32 *first_diff,
			   struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;
	u32 word_region = length & ~((u32)sizeof(u64) - 1);

	while (length - cursor >= sizeof(u64)) {
		u64 raw_word;
		u64 parent_word;
		u32 byte;

		/* memcpy keeps unaligned accesses and aliasing valid.  With the
		 * vectorizers disabled, x86-64 lowers these to ordinary GPR loads. */
		memcpy(&raw_word, raw + cursor, sizeof(raw_word));
		memcpy(&parent_word, parent + cursor, sizeof(parent_word));
		if ((raw_word ^ parent_word) == 0) {
			cursor += sizeof(u64);
			continue;
		}

		/* Refine by address order rather than ctz so this remains correct
		 * independently of host byte order. */
		for (byte = 0; byte < sizeof(u64); byte++) {
			if (raw[cursor + byte] != parent[cursor + byte]) {
				*equal = false;
				*first_diff = cursor + byte;
				goto account;
			}
		}
		pr_err("DSA fine-grained scalar64 backend couldn't refine unequal word\n");
		return -1;
	}

	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	/* Derive the profile geometry once per first-diff call.  Keeping all
	 * counters out of the 8-byte loop makes profile mode low disturbance. */
	if (stats) {
		u64 word_ops;
		u64 refine_bytes = 0;
		u64 tail_bytes = 0;

		if (*equal) {
			word_ops = length / sizeof(u64);
			tail_bytes = length - word_region;
		} else if (*first_diff < word_region) {
			word_ops = *first_diff / sizeof(u64) + 1;
			refine_bytes = *first_diff % sizeof(u64) + 1;
		} else {
			word_ops = length / sizeof(u64);
			tail_bytes = *first_diff - word_region + 1;
		}
		stats->scalar64_calls++;
		stats->scalar64_word_ops += word_ops;
		stats->scalar64_refine_bytes += refine_bytes;
		stats->scalar64_tail_bytes += tail_bytes;
		stats->scalar64_bytes_examined += word_ops * sizeof(u64) +
			refine_bytes + tail_bytes;
	}
	return 0;
}

#ifdef HOT_FG_HAVE_X86_SIMD
static void hot_fg_account_simd_scan(struct hot_fg_cpu_scan_stats *stats,
				     u32 length, bool equal, u32 first_diff,
				     u32 vector_bytes)
{
	u32 vector_region;
	u64 vector_ops;
	u64 tail_bytes = 0;

	if (!stats)
		return;
	vector_region = length - length % vector_bytes;
	if (equal) {
		vector_ops = length / vector_bytes;
		tail_bytes = length - vector_region;
	} else if (first_diff < vector_region) {
		vector_ops = first_diff / vector_bytes + 1;
	} else {
		vector_ops = length / vector_bytes;
		tail_bytes = first_diff - vector_region + 1;
	}
	stats->vector_ops += vector_ops;
	stats->bytes_examined += vector_ops * vector_bytes + tail_bytes;
}

static int __attribute__((target("avx2")))
hot_fg_simd_avx2_first_diff(const unsigned char *raw,
			    const unsigned char *parent, u32 length,
			    bool *equal, u32 *first_diff,
			    struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;

	while (cursor + 32 <= length) {
		__m256i raw_v = _mm256_loadu_si256((const __m256i *)(raw + cursor));
		__m256i parent_v = _mm256_loadu_si256((const __m256i *)(parent + cursor));
		u32 equal_mask = (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi8(raw_v, parent_v));

		if (equal_mask != UINT32_MAX) {
			*equal = false;
			*first_diff = cursor + (u32)__builtin_ctz(~equal_mask);
			goto account;
		}
		cursor += 32;
	}
	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	hot_fg_account_simd_scan(stats, length, *equal, *first_diff, 32);
	return 0;
}

static int __attribute__((target("avx512f,avx512bw,avx512vl")))
hot_fg_simd_avx512_first_diff(const unsigned char *raw,
			      const unsigned char *parent, u32 length,
			      bool *equal, u32 *first_diff,
			      struct hot_fg_cpu_scan_stats *stats)
{
	u32 cursor = 0;

	while (cursor + 64 <= length) {
		__m512i raw_v = _mm512_loadu_si512((const void *)(raw + cursor));
		__m512i parent_v = _mm512_loadu_si512((const void *)(parent + cursor));
		__mmask64 equal_mask = _mm512_cmpeq_epi8_mask(raw_v, parent_v);

		if (equal_mask != ~(__mmask64)0) {
			*equal = false;
			*first_diff = cursor + (u32)__builtin_ctzll((u64)~equal_mask);
			goto account;
		}
		cursor += 64;
	}
	while (cursor < length) {
		if (raw[cursor] != parent[cursor]) {
			*equal = false;
			*first_diff = cursor;
			goto account;
		}
		cursor++;
	}
	*equal = true;
	*first_diff = length;

account:
	hot_fg_account_simd_scan(stats, length, *equal, *first_diff, 64);
	return 0;
}
#endif

static int hot_fg_cpu_first_diff(enum hot_fg_compare_backend backend,
				 const unsigned char *raw,
				 const unsigned char *parent, u32 length,
				 bool *equal, u32 *first_diff,
				 struct hot_fg_cpu_scan_stats *stats)
{
	if (!raw || !parent || !length || !equal || !first_diff)
		return -1;

	if (backend == HOT_FG_COMPARE_MEMCMP)
		return hot_fg_memcmp_first_diff(raw, parent, length, equal,
					       first_diff, stats);
	if (backend == HOT_FG_COMPARE_SCALAR64)
		return hot_fg_scalar64_first_diff(raw, parent, length, equal,
						 first_diff, stats);

#ifdef HOT_FG_HAVE_X86_SIMD
	if (backend == HOT_FG_COMPARE_SIMD_AVX2)
		return hot_fg_simd_avx2_first_diff(raw, parent, length, equal,
					  first_diff, stats);
	if (backend == HOT_FG_COMPARE_SIMD_AVX512 ||
	    backend == HOT_FG_COMPARE_VALIDATE)
		return hot_fg_simd_avx512_first_diff(raw, parent, length, equal,
					    first_diff, stats);
#else
	(void)backend;
	(void)stats;
#endif

	pr_err("DSA fine-grained CPU compare backend is unavailable\n");
	return -1;
}

static int hot_fg_prefault_parent_span(const struct hot_fg_compare_span *span,
				       size_t span_idx, const char *stage)
{
	if (!span || !span->parent || !span->length ||
	    ((unsigned long)span->parent & (PAGE_SIZE - 1)) ||
	    span->length % PAGE_SIZE) {
		pr_err("DSA fine-grained parent prefault invalid stage=%s span=%zu parent=%p length=%u\n",
		       stage, span_idx, span ? span->parent : NULL,
		       span ? span->length : 0);
		return -1;
	}

	/*
	 * Populate only the exact compare span.  The hot parent is already a
	 * resident tmpfs-backed, read-only MAP_SHARED mapping; this establishes
	 * readable PTEs synchronously without the post-fault user load performed
	 * by the old byte-per-page loop.  A failed populate must not submit DSA
	 * against a partially prepared span or silently change fault semantics.
	 */
	if (madvise((void *)span->parent, span->length, MADV_POPULATE_READ)) {
		pr_perror("DSA fine-grained parent MADV_POPULATE_READ failed stage=%s span=%zu parent=%p length=%u",
			  stage, span_idx, span->parent, span->length);
		return -1;
	}

	return 0;
}

static int hot_fg_prefault_all(struct hot_apply_ctx *ctx,
			       struct hot_fg_compare_span *spans, size_t nr_spans)
{
	size_t i;

	for (i = 0; i < nr_spans; i++) {
		struct hot_fg_compare_span *span = &spans[i];

		if (!span->parent || !span->length || span->length % PAGE_SIZE ||
		    span->state != HOT_FG_SPAN_UNPREFAULTED) {
			pr_err("DSA compare breakdown has invalid prefault span=%zu state=%u length=%u\n",
			       i, span->state, span->length);
			return -1;
		}
		if (hot_fg_prefault_parent_span(span, i, "breakdown"))
			return -1;
		span->state = HOT_FG_SPAN_READY;
		if (ctx->profile) {
			ctx->profile_prefault_spans++;
			ctx->profile_prefault_pages += span->length / PAGE_SIZE;
		}
	}
	return 0;
}

static int hot_fg_compare_cpu(struct hot_apply_ctx *ctx,
			      struct hot_fg_raw_page *pages,
			      struct hot_fg_compare_span *spans, size_t nr_spans,
			      enum hot_fg_compare_backend backend,
			      bool record_profile)
{
	struct hot_fg_cpu_scan_stats stats = {};
	size_t i;

	for (i = 0; i < nr_spans; i++) {
		struct hot_fg_compare_span *span = &spans[i];

		if (!span->parent || !span->length || span->length % PAGE_SIZE ||
		    (span->state != HOT_FG_SPAN_UNPREFAULTED &&
		     !(ctx->compare_breakdown && span->state == HOT_FG_SPAN_READY))) {
			pr_err("DSA fine-grained CPU compare has invalid backend=%s span=%zu state=%u length=%u\n",
			       hot_fg_compare_backend_name(backend), i,
			       span->state, span->length);
			return -1;
		}
		/* CPU backends do not need a separate residency pass.  A missing
		 * file-backed PTE is resolved synchronously by the first real load,
		 * which then resumes and performs useful comparison.  The explicit
		 * all-span MADV_POPULATE_READ barrier is retained only by the
		 * compare-breakdown path above this function. */
		span->state = HOT_FG_SPAN_ACTIVE;
		while (span->cursor < span->length) {
			bool equal;
			u32 diff;

			if (hot_fg_cpu_first_diff(backend, span->raw + span->cursor,
						  span->parent + span->cursor,
						  span->length - span->cursor, &equal, &diff,
						  record_profile && ctx->profile ? &stats : NULL))
				return -1;
			if (equal) {
				span->cursor = span->length;
				if (hot_fg_span_finalize(span, pages, span->cursor))
					return -1;
				break;
			}
			if (hot_fg_span_record_diff(span, pages, span->cursor + diff))
				return -1;
		}
		if (span->cursor != span->length ||
		    hot_fg_span_finalize(span, pages, span->length) ||
		    span->finalized_pages != span->page_count) {
			pr_err("DSA fine-grained CPU compare backend=%s span ended with unfinished pages\n",
			       hot_fg_compare_backend_name(backend));
			return -1;
		}
		span->state = HOT_FG_SPAN_DONE;
	}

	if (record_profile && ctx->profile) {
		ctx->profile_memcmp_calls += stats.memcmp_calls;
		ctx->profile_memcmp_requested_bytes += stats.memcmp_requested_bytes;
		ctx->profile_memcmp_scalar_bytes += stats.memcmp_scalar_bytes;
		ctx->profile_scalar64_calls += stats.scalar64_calls;
		ctx->profile_scalar64_word_ops += stats.scalar64_word_ops;
		ctx->profile_scalar64_refine_bytes += stats.scalar64_refine_bytes;
		ctx->profile_scalar64_tail_bytes += stats.scalar64_tail_bytes;
		ctx->profile_scalar64_bytes_examined += stats.scalar64_bytes_examined;
		ctx->profile_simd_vector_ops += stats.vector_ops;
		ctx->profile_simd_bytes_examined += stats.bytes_examined;
	}
	return 0;
}

static int hot_fg_validate_compare_metadata(const struct hot_fg_raw_page *dsa_pages,
					    const struct hot_fg_raw_page *simd_pages,
					    size_t nr_pages,
					    const struct hot_fg_compare_span *dsa_spans,
					    const struct hot_fg_compare_span *simd_spans,
					    size_t nr_spans)
{
	size_t i;

	for (i = 0; i < nr_pages; i++) {
		const struct hot_fg_raw_page *dsa = &dsa_pages[i];
		const struct hot_fg_raw_page *simd = &simd_pages[i];
		bool ranges_equal = dsa->patch_count == simd->patch_count &&
			!memcmp(dsa->patches, simd->patches,
				dsa->patch_count * sizeof(dsa->patches[0]));

		if (dsa->state != simd->state || dsa->cursor != simd->cursor ||
		    dsa->patch_bytes != simd->patch_bytes ||
		    !ranges_equal) {
			size_t range_idx = SIZE_MAX;
			size_t common = dsa->patch_count < simd->patch_count ?
				dsa->patch_count : simd->patch_count;
			size_t j;
			u32 dsa_off = UINT_MAX, dsa_len = UINT_MAX;
			u32 simd_off = UINT_MAX, simd_len = UINT_MAX;

			for (j = 0; j < common; j++) {
				if (dsa->patches[j].off != simd->patches[j].off ||
				    dsa->patches[j].len != simd->patches[j].len) {
					range_idx = j;
					break;
				}
			}
			if (range_idx == SIZE_MAX && dsa->patch_count != simd->patch_count)
				range_idx = common;
			if (range_idx < dsa->patch_count) {
				dsa_off = dsa->patches[range_idx].off;
				dsa_len = dsa->patches[range_idx].len;
			}
			if (range_idx < simd->patch_count) {
				simd_off = simd->patches[range_idx].off;
				simd_len = simd->patches[range_idx].len;
			}
			pr_err("DSA fine-grained validate page metadata mismatch page=%zu vaddr=%lx dsa_state=%u simd_state=%u dsa_cursor=%u simd_cursor=%u dsa_patch_bytes=%u simd_patch_bytes=%u dsa_ranges=%u simd_ranges=%u first_range=%zu dsa_off=%u dsa_len=%u simd_off=%u simd_len=%u\n",
			       i, dsa->vaddr, dsa->state, simd->state,
			       dsa->cursor, simd->cursor,
			       dsa->patch_bytes, simd->patch_bytes,
			       dsa->patch_count, simd->patch_count,
			       range_idx, dsa_off, dsa_len, simd_off, simd_len);
			return -1;
		}
	}
	for (i = 0; i < nr_spans; i++) {
		const struct hot_fg_compare_span *dsa = &dsa_spans[i];
		const struct hot_fg_compare_span *simd = &simd_spans[i];

		if (dsa->cursor != simd->cursor ||
		    dsa->finalized_pages != simd->finalized_pages ||
		    dsa->state != simd->state) {
			pr_err("DSA fine-grained validate span metadata mismatch span=%zu dsa_cursor=%u simd_cursor=%u dsa_state=%u simd_state=%u\n",
			       i, dsa->cursor, simd->cursor, dsa->state, simd->state);
			return -1;
		}
	}
	return 0;
}

static int hot_fg_wavefront_fill(struct hot_apply_ctx *ctx,
				 struct hot_fg_compare_slot *slots,
				 struct hot_fg_ready_queue *ready,
				 size_t *active, u64 *submit_sequence,
				 u64 submit_ns)
{
	size_t i;

	for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT &&
	     *active < HOT_DSA_COMPARE_INFLIGHT; i++) {
		struct hot_fg_compare_span *span;
		size_t span_idx;

		if (slots[i].active)
			continue;
		if (!ready->nr)
			break;
		if (hot_fg_ready_queue_pop(ready, &span_idx))
			return -1;
		span = &ready->spans[span_idx];
		if (span->state != HOT_FG_SPAN_READY) {
			pr_err("DSA fine-grained compare ready queue state=%u span=%zu\n",
			       span->state, span_idx);
			return -1;
		}
		if (hot_fg_compare_submit(ctx, &slots[i], span,
					  ++*submit_sequence, submit_ns))
			return -1;
		(*active)++;
	}
	return 0;
}

static int hot_fg_wavefront_drain_slots(struct hot_fg_compare_slot *slots,
					 size_t *active)
{
	u64 sweeps = 0;

	while (*active) {
		size_t i;
		bool progress = false;

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			if (!slots[i].active ||
			    __atomic_load_n(&slots[i].comp.status, __ATOMIC_ACQUIRE) == 0)
				continue;
			slots[i].active = false;
			(*active)--;
			progress = true;
		}
		if (!*active)
			return 0;
		if (!progress && (++sweeps & 0xfffULL) == 0) {
			u64 now_ns = hot_dsa_watchdog_now_ns();

			for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
				if (!slots[i].active)
					continue;
				if (!now_ns)
					hot_fg_completion_timeout_fatal(&slots[i], *active,
						slots[i].completion_deadline_ns,
						"error-drain-clock");
				if (now_ns >= slots[i].completion_deadline_ns)
					hot_fg_completion_timeout_fatal(&slots[i], *active,
						now_ns, "error-drain");
			}
		}
		hot_dsa_cpu_relax();
	}
	return 0;
}

/*
 * A no-BOF fault does not change ownership of the extent.  DSA has proved the
 * bytes_completed prefix equal; AVX-512 resolves and classifies only the page
 * containing the next unprocessed byte, then the page-aligned suffix returns
 * to the ordinary DSA ready FIFO.
 */
static int hot_fg_compare_fault_page_simd(struct hot_apply_ctx *ctx,
					  struct hot_fg_raw_page *pages,
					  struct hot_fg_compare_span *span,
					  struct hot_fg_compare_slot *slot)
{
	struct hot_fg_cpu_scan_stats stats = {};
	u8 fault_info = slot->comp.fault_info;
	u32 operand = (fault_info >> HOT_DSA_FAULT_OPERAND_SHIFT) &
		HOT_DSA_FAULT_OPERAND_MASK;
	u32 partial = slot->comp.bytes_completed;
	u64 operand_addr;
	u64 operand_end;
	u64 fault_page;
	u64 first_page;
	u64 end_page;
	const u64 page_mask = (u64)PAGE_SIZE - 1ULL;
	u32 old_cursor = span->cursor;
	u32 absolute;
	u32 page_base;
	u32 page_end;
	u32 start;
	u64 simd_progress;
	size_t page_idx;
	struct hot_fg_raw_page *page;

	if (slot->comp.result != 0 || (fault_info & HOT_DSA_FAULT_ADDR_MASKED) ||
	    (operand != HOT_DSA_FAULT_OPERAND_SRC1 &&
	     operand != HOT_DSA_FAULT_OPERAND_SRC2) ||
	    partial >= slot->submitted_len ||
	    slot->submitted_cursor != old_cursor) {
		pr_err("DSA no-BOF fault has invalid metadata result=%u info=%u partial=%u submitted=%u cursor=%u\n",
		       slot->comp.result, fault_info, partial,
		       slot->submitted_len, old_cursor);
		return -1;
	}

	operand_addr = operand == HOT_DSA_FAULT_OPERAND_SRC1 ?
		slot->desc.src_addr : slot->desc.src2_addr;
	if (operand_addr > UINT64_MAX - slot->submitted_len)
		return -1;
	operand_end = operand_addr + slot->submitted_len;
	if (operand_end > UINT64_MAX - page_mask)
		return -1;
	first_page = operand_addr & ~page_mask;
	end_page = (operand_end + page_mask) & ~page_mask;
	fault_page = slot->comp.fault_addr & ~page_mask;
	if (fault_page < first_page || fault_page >= end_page) {
		pr_err("DSA no-BOF fault outside submitted range operand=%u fault=%" PRIx64
		       " range=[%" PRIx64 ",%" PRIx64 ") partial=%u len=%u\n",
		       operand, fault_page, first_page, end_page, partial,
		       slot->submitted_len);
		return -1;
	}

	absolute = old_cursor + partial;
	if (absolute >= span->length)
		return -1;
	if (hot_fg_span_finalize(span, pages, absolute))
		return -1;
	page_base = absolute & ~(PAGE_SIZE - 1);
	page_end = page_base + PAGE_SIZE;
	if (page_end > span->length)
		return -1;
	page_idx = span->first_page + page_base / PAGE_SIZE;
	page = &pages[page_idx];
	start = absolute - page_base;
	if (page->state != HOT_FG_RAW_PENDING || page->cursor > start) {
		pr_err("DSA no-BOF fault overlaps page state page=%zu state=%u cursor=%u start=%u\n",
		       page_idx, page->state, page->cursor, start);
		return -1;
	}
	page->cursor = start;
	page->state = HOT_FG_RAW_CPU_FAULT;

	while (page->cursor < PAGE_SIZE && page->state != HOT_FG_RAW_FULL) {
		bool equal;
		u32 diff;
		u32 length = PAGE_SIZE - page->cursor;

		if (hot_fg_cpu_first_diff(HOT_FG_COMPARE_SIMD_AVX512,
					  page->raw + page->cursor,
					  page->parent + page->cursor,
					  length, &equal, &diff,
					  ctx->profile ? &stats : NULL))
			return -1;
		if (equal) {
			page->cursor = PAGE_SIZE;
			break;
		}
		if (hot_fg_page_record_diff(page, page->cursor + diff))
			return -1;
	}
	if (page->state != HOT_FG_RAW_FULL)
		page->state = page->patch_count ? HOT_FG_RAW_PATCH :
			HOT_FG_RAW_PARENT;
	if (page->cursor != PAGE_SIZE)
		return -1;

	span->cursor = page_end;
	if (hot_fg_span_finalize(span, pages, span->cursor))
		return -1;

	simd_progress = PAGE_SIZE - start;
	if (ctx->profile) {
		ctx->profile_compare_nobof_faults++;
		ctx->profile_compare_nobof_equal_prefix_bytes += partial;
		if (operand == HOT_DSA_FAULT_OPERAND_SRC1)
			ctx->profile_compare_nobof_fault_source1++;
		else
			ctx->profile_compare_nobof_fault_source2++;
		ctx->profile_compare_fault_handoff_spans++;
		ctx->profile_compare_fault_handoff_pages++;
		ctx->profile_compare_fault_handoff_remaining_bytes += simd_progress;
		ctx->profile_compare_cpu_fault_waves++;
		if (ctx->profile_compare_fault_queue_max < 1)
			ctx->profile_compare_fault_queue_max = 1;
		ctx->profile_dsa_logical_progress_bytes += partial;
		ctx->profile_simd_logical_progress_bytes += simd_progress;
		ctx->profile_fault_simd_logical_progress_bytes += simd_progress;
		ctx->profile_simd_vector_ops += stats.vector_ops;
		ctx->profile_simd_bytes_examined += stats.bytes_examined;
	}
	return 0;
}

static int __attribute__((unused)) hot_fg_compare_wavefront(struct hot_apply_ctx *ctx,
				    struct hot_fg_raw_page *pages,
				    struct hot_fg_compare_span *spans, size_t nr_spans)
{
	struct hot_fg_compare_slot slots[HOT_DSA_COMPARE_INFLIGHT] = {};
	struct hot_fg_ready_queue ready;
	size_t done = 0;
	size_t active = 0;
	u64 submit_sequence = 0;
	size_t i;
	int ret = -1;

	if (!nr_spans)
		return 0;
	if (hot_fg_ready_queue_init(&ready, spans, nr_spans))
		return -1;
	for (i = 0; i < nr_spans; i++) {
		if (spans[i].state == HOT_FG_SPAN_UNPREFAULTED)
			spans[i].state = HOT_FG_SPAN_READY;
		else if (!ctx->compare_breakdown ||
			 spans[i].state != HOT_FG_SPAN_READY) {
			pr_err("DSA no-BOF compare has invalid initial span=%zu state=%u\n",
			       i, spans[i].state);
			goto out;
		}
		if (hot_fg_ready_queue_push(&ready, i)) {
			pr_err("DSA no-BOF compare initial ready queue failed span=%zu\n",
			       i);
			goto out;
		}
	}

	while (done < nr_spans) {
		u64 now_ns = hot_dsa_watchdog_now_ns();
		struct hot_fg_compare_slot *expired_slot = NULL;
		size_t harvested = 0;
		bool had_active = active != 0;

		if (!now_ns) {
			if (active) {
				for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++)
					if (slots[i].active)
						hot_fg_completion_timeout_fatal(
							&slots[i], active,
							slots[i].completion_deadline_ns,
							"scheduler-clock");
			}
			pr_perror("DSA no-BOF completion watchdog clock failed");
			goto out;
		}
		if (had_active && ctx->profile) {
			ctx->profile_compare_poll_sweeps++;
			if (active > ctx->profile_compare_max_active)
				ctx->profile_compare_max_active = active;
		}

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			struct hot_fg_compare_slot *slot = &slots[i];
			struct hot_fg_compare_span *span;
			enum hot_fg_nobof_completion kind;
			u32 diff = 0;
			u32 old_cursor;

			if (!slot->active)
				continue;
			if (hot_fg_compare_complete_nobof(slot, &kind, &diff)) {
				if (__atomic_load_n(&slot->comp.status,
						    __ATOMIC_ACQUIRE)) {
					slot->active = false;
					active--;
				}
				goto out;
			}
			if (kind == HOT_FG_NOBOF_NOT_READY) {
				if (ctx->profile)
					ctx->profile_compare_not_ready++;
				if (!expired_slot &&
				    now_ns >= slot->completion_deadline_ns)
					expired_slot = slot;
				continue;
			}
			span = slot->span;
			if (!span || span->state != HOT_FG_SPAN_ACTIVE ||
			    slot->submitted_cursor != span->cursor) {
				pr_err("DSA no-BOF completion has stale span cursor\n");
				slot->active = false;
				active--;
				goto out;
			}
			slot->active = false;
			active--;
			harvested++;
			if (ctx->profile && now_ns >= slot->submit_ns) {
				u64 age_us = (now_ns - slot->submit_ns) / 1000ULL;

				if (age_us > ctx->profile_max_completion_age_us)
					ctx->profile_max_completion_age_us = age_us;
			}

			old_cursor = span->cursor;
			if (kind == HOT_FG_NOBOF_EQUAL) {
				span->cursor += slot->submitted_len;
				if (hot_fg_span_finalize(span, pages, span->cursor))
					goto out;
				if (ctx->profile)
					ctx->profile_dsa_logical_progress_bytes +=
						slot->submitted_len;
			} else if (kind == HOT_FG_NOBOF_DIFFERENT) {
				diff += slot->submitted_cursor;
				if (hot_fg_span_record_diff(span, pages, diff))
					goto out;
				if (ctx->profile)
					ctx->profile_dsa_logical_progress_bytes +=
						span->cursor - old_cursor;
			} else if (hot_fg_compare_fault_page_simd(ctx, pages,
								  span, slot)) {
				goto out;
			}

			if (span->cursor == span->length) {
				if (hot_fg_span_finalize(span, pages, span->length))
					goto out;
				if (span->finalized_pages != span->page_count) {
					pr_err("DSA no-BOF span ended with unfinished pages\n");
					goto out;
				}
				span->state = HOT_FG_SPAN_DONE;
				done++;
			} else {
				span->state = HOT_FG_SPAN_READY;
				if (hot_fg_ready_queue_push(&ready,
							(size_t)(span - spans))) {
					pr_err("DSA no-BOF ready queue overflow\n");
					goto out;
				}
			}
		}

		if (expired_slot &&
		    __atomic_load_n(&expired_slot->comp.status,
				    __ATOMIC_ACQUIRE) == 0) {
			if (ctx->profile)
				ctx->profile_completion_timeout_count++;
			hot_fg_completion_timeout_fatal(expired_slot, active, now_ns,
							"compare");
		}
		if (had_active && ctx->profile)
			ctx->profile_completions_harvested += harvested;

		if (hot_fg_wavefront_fill(ctx, slots, &ready, &active,
					  &submit_sequence, now_ns))
			goto out;
		if (ctx->profile && active > ctx->profile_compare_max_active)
			ctx->profile_compare_max_active = active;
		if (!active && done < nr_spans) {
			pr_err("DSA no-BOF compare lost work done=%zu ready=%zu total=%zu\n",
			       done, ready.nr, nr_spans);
			goto out;
		}
		if (active)
			hot_dsa_cpu_relax();
	}

	for (i = 0; i < nr_spans; i++) {
		if (spans[i].state != HOT_FG_SPAN_DONE ||
		    spans[i].cursor != spans[i].length ||
		    spans[i].finalized_pages != spans[i].page_count) {
			pr_err("DSA no-BOF final span mismatch span=%zu state=%u cursor=%u length=%u finalized=%zu pages=%zu\n",
			       i, spans[i].state, spans[i].cursor, spans[i].length,
			       spans[i].finalized_pages, spans[i].page_count);
			goto out;
		}
	}
	ret = 0;
out:
	if (active && hot_fg_wavefront_drain_slots(slots, &active))
		ret = -1;
	hot_fg_ready_queue_fini(&ready);
	return ret;
}

static int hot_fg_compare_batch_prepare_child(
	struct hot_apply_ctx *ctx, struct hot_fg_compare_batch *batch, u32 child,
	struct hot_fg_compare_span *span, u64 sequence)
{
	struct dsa_hw_desc *desc = &batch->child_desc[child];
	struct hot_fg_compare_child_meta *meta = &batch->child[child];

	if (!span || !span->parent || span->state != HOT_FG_SPAN_READY ||
	    span->cursor >= span->length || child >= HOT_DSA_COMPARE_BATCH_CHILDREN)
		return -1;
	memset(desc, 0, sizeof(*desc));
	memset((void *)&batch->child_comp[child], 0,
	       sizeof(batch->child_comp[child]));
	meta->span = span;
	meta->submitted_cursor = span->cursor;
	meta->submitted_len = span->length - span->cursor;
	if (meta->submitted_len > ctx->dsa_max_transfer_size)
		meta->submitted_len = ctx->dsa_max_transfer_size;
	if (!meta->submitted_len)
		return -1;
	meta->submit_sequence = sequence;
	desc->opcode = DSA_OPCODE_COMPARE;
	desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	desc->src_addr = (u64)(unsigned long)(span->raw + span->cursor);
	desc->src2_addr = (u64)(unsigned long)(span->parent + span->cursor);
	desc->xfer_size = meta->submitted_len;
	desc->completion_addr = (u64)(unsigned long)&batch->child_comp[child];
	span->state = HOT_FG_SPAN_ACTIVE;
	return 0;
}

static int hot_fg_compare_batch_prepare_outer(struct hot_apply_ctx *ctx,
					      struct hot_fg_compare_batch *batch)
{
	if (!batch->child_count || batch->child_count > HOT_DSA_COMPARE_BATCH_CHILDREN ||
	    !ctx->dsa_wq_count)
		return -1;
	batch->wq_idx = ctx->dsa_next_wq++ % (u32)ctx->dsa_wq_count;
	batch->direct_single = batch->child_count == 1;
	if (!batch->direct_single) {
		memset(&batch->outer_desc, 0, sizeof(batch->outer_desc));
		memset((void *)&batch->outer_comp, 0, sizeof(batch->outer_comp));
		batch->outer_desc.opcode = DSA_OPCODE_BATCH;
		batch->outer_desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		batch->outer_desc.desc_list_addr =
			(u64)(unsigned long)&batch->child_desc[0];
		batch->outer_desc.desc_count = batch->child_count;
		batch->outer_desc.completion_addr =
			(u64)(unsigned long)&batch->outer_comp;
	}
	return 0;
}

/* All descriptor and completion-record stores for the current refill group
 * must be released by one hot_dsa_release_descriptors() before entering this
 * helper.  ENQCMD retry does not need another fence because the descriptor is
 * immutable between attempts. */
static int hot_fg_compare_batch_submit_released(
	struct hot_apply_ctx *ctx, struct hot_fg_compare_batch *batch, u64 submit_ns)
{
	u32 retry;
	unsigned long portal_mask;
	unsigned long off;
	const void *submitted_desc;
	u32 i;

	if (!batch->child_count || batch->child_count > HOT_DSA_COMPARE_BATCH_CHILDREN ||
	    batch->active || batch->wq_idx >= (u32)ctx->dsa_wq_count)
		return -1;
	portal_mask = ((unsigned long)ctx->dsa_portals[batch->wq_idx]) & ~0xfffUL;
	submitted_desc = batch->direct_single ?
		(const void *)&batch->child_desc[0] : (const void *)&batch->outer_desc;

	for (retry = 0; retry < HOT_DSA_MAX_ENQ_RETRY; retry++) {
		void *portal_slot;

		off = ((ctx->dsa_portal_offset[batch->wq_idx]++ << 6) & 0xfffUL);
		portal_slot = (void *)(portal_mask | off);
		if (hot_dsa_enqcmd(portal_slot, submitted_desc) == 0)
			break;
		hot_dsa_cpu_relax();
	}
	if (retry == HOT_DSA_MAX_ENQ_RETRY) {
		pr_err("DSA fine-grained hardware-BATCH enqcmd timed out\n");
		return -1;
	}
	batch->submit_ns = submit_ns;
	batch->completion_deadline_ns = submit_ns + HOT_DSA_COMPLETION_TIMEOUT_NS;
	batch->active = true;
	if (ctx->profile) {
		ctx->dsa_enqcmd++;
		ctx->profile_compare_enq_retries += retry;
		ctx->profile_batch_child_submits += batch->child_count;
		if (batch->direct_single)
			ctx->profile_batch_single_tail_submits++;
		else {
			ctx->profile_batch_outer_submits++;
			if (batch->child_count < HOT_DSA_COMPARE_BATCH_CHILDREN)
				ctx->profile_batch_partial_submits++;
		}
		for (i = 0; i < batch->child_count; i++) {
			ctx->fg_compare_ops++;
			ctx->profile_dsa_submitted_bytes += batch->child[i].submitted_len;
			if (batch->child[i].submitted_cursor)
				ctx->profile_dsa_continuation_submit_ops++;
			else
				ctx->profile_dsa_fresh_submit_ops++;
		}
	}
	return 0;
}

static bool hot_fg_compare_batch_ready(const struct hot_fg_compare_batch *batch)
{
	if (!batch->active)
		return false;
	if (batch->direct_single)
		return __atomic_load_n(&batch->child_comp[0].status,
				       __ATOMIC_ACQUIRE) != 0;
	return __atomic_load_n(&batch->outer_comp.status, __ATOMIC_ACQUIRE) != 0;
}

static int hot_fg_compare_batch_harvest(
	struct hot_apply_ctx *ctx, struct hot_fg_compare_batch *batch,
	struct hot_fg_raw_page *pages, struct hot_fg_compare_span *spans,
	struct hot_fg_ready_queue *ready, size_t *done, u64 now_ns)
{
	u32 i;
	bool saw_nobof = false;
	u32 outer_code = DSA_COMP_SUCCESS;

	if (!hot_fg_compare_batch_ready(batch))
		return 0;
	if (!batch->direct_single) {
		outer_code = DSA_COMP_STATUS(batch->outer_comp.status);
		if ((outer_code != DSA_COMP_SUCCESS &&
		     outer_code != DSA_COMP_BATCH_FAIL) ||
		    batch->outer_comp.descs_completed != batch->child_count) {
			pr_err("DSA COMPARE BATCH outer failed code=%u completed=%u expected=%u\n",
			       outer_code, batch->outer_comp.descs_completed,
			       batch->child_count);
			return -1;
		}
	}

	for (i = 0; i < batch->child_count; i++) {
		struct hot_fg_compare_child_meta *meta = &batch->child[i];
		struct hot_fg_compare_span *span = meta->span;
		struct hot_fg_compare_slot view;
		enum hot_fg_nobof_completion kind;
		u32 diff = 0;
		u32 old_cursor;

		memset(&view, 0, sizeof(view));
		view.desc = batch->child_desc[i];
		memcpy((void *)&view.comp, (const void *)&batch->child_comp[i],
		       sizeof(view.comp));
		view.span = span;
		view.submitted_cursor = meta->submitted_cursor;
		view.submitted_len = meta->submitted_len;
		view.wq_idx = batch->wq_idx;
		view.submit_sequence = meta->submit_sequence;
		view.submit_ns = batch->submit_ns;
		view.completion_deadline_ns = batch->completion_deadline_ns;
		if (hot_fg_compare_complete_nobof(&view, &kind, &diff) ||
		    kind == HOT_FG_NOBOF_NOT_READY) {
			pr_err("DSA COMPARE BATCH child is not terminal child=%u\n", i);
			return -1;
		}
		if (!span || span->state != HOT_FG_SPAN_ACTIVE ||
		    meta->submitted_cursor != span->cursor) {
			pr_err("DSA COMPARE BATCH child has stale span cursor child=%u\n", i);
			return -1;
		}
		if (ctx->profile && now_ns >= batch->submit_ns) {
			u64 age_us = (now_ns - batch->submit_ns) / 1000ULL;
			if (age_us > ctx->profile_max_completion_age_us)
				ctx->profile_max_completion_age_us = age_us;
		}
		old_cursor = span->cursor;
		if (kind == HOT_FG_NOBOF_EQUAL) {
			span->cursor += meta->submitted_len;
			if (hot_fg_span_finalize(span, pages, span->cursor))
				return -1;
			if (ctx->profile) {
				ctx->profile_dsa_logical_progress_bytes += meta->submitted_len;
				ctx->profile_batch_child_success++;
			}
		} else if (kind == HOT_FG_NOBOF_DIFFERENT) {
			diff += meta->submitted_cursor;
			if (hot_fg_span_record_diff(span, pages, diff))
				return -1;
			if (ctx->profile) {
				ctx->profile_dsa_logical_progress_bytes += span->cursor - old_cursor;
				ctx->profile_batch_child_success++;
			}
		} else {
			saw_nobof = true;
			if (hot_fg_compare_fault_page_simd(ctx, pages, span, &view))
				return -1;
			if (ctx->profile)
				ctx->profile_batch_child_nobof++;
		}

		if (span->cursor == span->length) {
			if (hot_fg_span_finalize(span, pages, span->length) ||
			    span->finalized_pages != span->page_count)
				return -1;
			span->state = HOT_FG_SPAN_DONE;
			(*done)++;
		} else {
			span->state = HOT_FG_SPAN_READY;
			if (hot_fg_ready_queue_push(ready, (size_t)(span - spans)))
				return -1;
		}
	}
	if (!batch->direct_single) {
		if ((outer_code == DSA_COMP_BATCH_FAIL) != saw_nobof) {
			pr_err("DSA COMPARE BATCH outer/child status mismatch outer=%u nobof=%u\n",
			       outer_code, saw_nobof ? 1U : 0U);
			return -1;
		}
		if (ctx->profile) {
			if (outer_code == DSA_COMP_SUCCESS)
				ctx->profile_batch_outer_success++;
			else
				ctx->profile_batch_outer_fail++;
		}
	}
	batch->active = false;
	batch->child_count = 0;
	return 1;
}

static void hot_fg_compare_batch_timeout(
	const struct hot_fg_compare_batch *batch, size_t active, u64 now_ns)
{
	u64 age_us = now_ns >= batch->submit_ns ?
		(now_ns - batch->submit_ns) / 1000ULL : 0;

	pr_err("CDP_DSA_COMPLETION_TIMEOUT: stage=compare-batch exit=%u wq=%u age_us=%" PRIu64
	       " active_outer=%zu child_count=%u outer_status=%u\n",
	       CDP_DSA_COMPLETION_TIMEOUT_EXIT, batch->wq_idx, age_us, active,
	       batch->child_count,
	       batch->direct_single ?
		(unsigned int)__atomic_load_n(&batch->child_comp[0].status,
					 __ATOMIC_ACQUIRE) :
		(unsigned int)__atomic_load_n(&batch->outer_comp.status,
					 __ATOMIC_ACQUIRE));
	_exit(CDP_DSA_COMPLETION_TIMEOUT_EXIT);
}

static int hot_fg_compare_hw_batch(struct hot_apply_ctx *ctx,
				   struct hot_fg_raw_page *pages,
				   struct hot_fg_compare_span *spans,
				   size_t nr_spans)
{
	struct hot_fg_compare_batch *batches;
	struct hot_fg_ready_queue ready;
	size_t active_outer = 0;
	size_t active_children = 0;
	size_t done = 0;
	u64 sequence = 0;
	size_t i;
	int ret = -1;

	if (!nr_spans)
		return 0;
	if (!ctx->compare_batches) {
		if (posix_memalign((void **)&ctx->compare_batches, 64,
				   HOT_DSA_COMPARE_INFLIGHT *
					   sizeof(*ctx->compare_batches)))
			return -1;
		memset(ctx->compare_batches, 0,
		       HOT_DSA_COMPARE_INFLIGHT * sizeof(*ctx->compare_batches));
	}
	batches = ctx->compare_batches;
	for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
		if (batches[i].active) {
			pr_err("DSA hardware-BATCH compare pool still has active outer=%zu\n",
			       i);
			return -1;
		}
		batches[i].child_count = 0;
		batches[i].direct_single = false;
	}
	if (hot_fg_ready_queue_init(&ready, spans, nr_spans))
		goto out;
	for (i = 0; i < nr_spans; i++) {
		if (spans[i].state == HOT_FG_SPAN_UNPREFAULTED)
			spans[i].state = HOT_FG_SPAN_READY;
		else if (!ctx->compare_breakdown ||
			 spans[i].state != HOT_FG_SPAN_READY)
			goto out_queue;
		if (hot_fg_ready_queue_push(&ready, i))
			goto out_queue;
	}

	while (done < nr_spans) {
		u64 now_ns = hot_dsa_watchdog_now_ns();
		u32 prepared[HOT_DSA_COMPARE_INFLIGHT];
		size_t prepared_count = 0;
		size_t harvested = 0;
		bool submitted = false;

		if (!now_ns)
			goto out_queue;
		if (ctx->profile && active_outer)
			ctx->profile_compare_poll_sweeps++;
		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
			struct hot_fg_compare_batch *batch = &batches[i];
			int rc;

			if (!batch->active)
				continue;
			if (!hot_fg_compare_batch_ready(batch)) {
				if (now_ns >= batch->completion_deadline_ns)
					hot_fg_compare_batch_timeout(batch, active_outer, now_ns);
				continue;
			}
			rc = hot_fg_compare_batch_harvest(ctx, batch, pages, spans,
							  &ready, &done, now_ns);
			if (rc < 0)
				goto out_queue;
			if (rc > 0) {
				active_outer--;
				harvested++;
			}
		}
		/* harvest resets child_count; recompute the exact active child count
		 * before refilling rather than maintaining a second failure-prone
		 * ownership ledger. */
		active_children = 0;
		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++)
			if (batches[i].active)
				active_children += batches[i].child_count;

		for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT && ready.nr; i++) {
			struct hot_fg_compare_batch *batch = &batches[i];
			u32 count;
			u32 j;

			if (batch->active)
				continue;
			count = ready.nr > HOT_DSA_COMPARE_BATCH_CHILDREN ?
				HOT_DSA_COMPARE_BATCH_CHILDREN : (u32)ready.nr;
			if (count == 1 && active_outer)
				break;
			batch->child_count = count;
			for (j = 0; j < count; j++) {
				size_t span_idx;
				if (hot_fg_ready_queue_pop(&ready, &span_idx) ||
				    hot_fg_compare_batch_prepare_child(
					ctx, batch, j, &spans[span_idx], ++sequence))
					goto out_queue;
			}
			if (hot_fg_compare_batch_prepare_outer(ctx, batch))
				goto out_queue;
			prepared[prepared_count++] = (u32)i;
		}
		if (prepared_count) {
			hot_dsa_release_descriptors();
			for (i = 0; i < prepared_count; i++) {
				struct hot_fg_compare_batch *batch =
					&batches[prepared[i]];

				if (hot_fg_compare_batch_submit_released(ctx, batch, now_ns))
					goto out_queue;
				active_outer++;
				active_children += batch->child_count;
			}
			submitted = true;
		}
		if (ctx->profile) {
			ctx->profile_completions_harvested += harvested;
			if (active_outer > ctx->profile_batch_max_active_outer)
				ctx->profile_batch_max_active_outer = active_outer;
			if (active_children > ctx->profile_batch_max_active_children)
				ctx->profile_batch_max_active_children = active_children;
			if (active_children > ctx->profile_compare_max_active)
				ctx->profile_compare_max_active = active_children;
		}
		if (!active_outer && done < nr_spans && !ready.nr) {
			pr_err("DSA hardware-BATCH compare lost work done=%zu total=%zu\n",
			       done, nr_spans);
			goto out_queue;
		}
		if (active_outer && !submitted && !harvested)
			hot_dsa_cpu_relax();
	}

	for (i = 0; i < nr_spans; i++)
		if (spans[i].state != HOT_FG_SPAN_DONE ||
		    spans[i].cursor != spans[i].length ||
		    spans[i].finalized_pages != spans[i].page_count)
			goto out_queue;
	ret = 0;

out_queue:
	if (active_outer) {
		for (;;) {
			u64 now_ns = hot_dsa_watchdog_now_ns();
			size_t remaining = 0;
			for (i = 0; i < HOT_DSA_COMPARE_INFLIGHT; i++) {
				if (!batches[i].active)
					continue;
				if (hot_fg_compare_batch_ready(&batches[i]))
					batches[i].active = false;
				else {
					remaining++;
					if (!now_ns || now_ns >= batches[i].completion_deadline_ns)
						hot_fg_compare_batch_timeout(
							&batches[i], remaining, now_ns);
				}
			}
			if (!remaining)
				break;
			hot_dsa_cpu_relax();
		}
	}
	hot_fg_ready_queue_fini(&ready);
out:
	return ret;
}

static int hot_fg_apply_raw_page(struct hot_apply_ctx *ctx,
				 struct hot_fg_raw_page *page)
{
	u16 i;

	if (page->state == HOT_FG_RAW_PARENT)
		return 0;
	if (page->state == HOT_FG_RAW_FULL) {
		if (hot_memstore_write_to_segments(ctx, page->raw,
						  page->vaddr, PAGE_SIZE))
			return -1;
		if (ctx->profile)
			ctx->memstore_bytes += PAGE_SIZE;
		return 0;
	}
	for (i = 0; i < page->patch_count; i++) {
		if (hot_memstore_write_to_segments(ctx,
						  page->raw + page->patches[i].off,
						  page->vaddr + page->patches[i].off,
						  page->patches[i].len))
			return -1;
		if (ctx->profile)
			ctx->memstore_bytes += page->patches[i].len;
	}
	return 0;
}

/* Publish the one canonical classification consumed by both the durable
 * serializer and hot apply.  Payload offsets deliberately point back into
 * the immutable raw capture; no second patch-data arena is created. */
static int hot_fg_publish_results(struct page_xfer *xfer,
				  const unsigned char *shared,
				  const struct hot_fg_raw_page *pages, size_t nr)
{
	struct hot_apply_ctx *ctx = xfer ? xfer->hot_apply : NULL;
	u32 head;
	size_t i;

	if (!xfer->dsa_fg_result_meta_base ||
	    xfer->dsa_fg_result_meta_limit < xfer->dsa_fg_result_meta_base ||
	    nr > (xfer->dsa_fg_result_meta_limit - xfer->dsa_fg_result_meta_base) /
		 sizeof(struct parasite_dsa_fg_result)) {
		pr_err("DSA fine-grained result metadata capacity is insufficient pages=%zu base=%u limit=%u\n",
		       nr, xfer->dsa_fg_result_meta_base,
		       xfer->dsa_fg_result_meta_limit);
		return -1;
	}
	head = xfer->dsa_fg_result_meta_base +
		nr * sizeof(struct parasite_dsa_fg_result);
	for (i = 0; i < nr; i++) {
		const struct hot_fg_raw_page *page = &pages[i];
		struct parasite_dsa_fg_result *result;
		u32 raw_off;
		u16 j;

		if ((page->state != HOT_FG_RAW_PARENT &&
		     page->state != HOT_FG_RAW_PATCH &&
		     page->state != HOT_FG_RAW_FULL) || page->raw < shared ||
		    (u64)(page->raw - shared) > UINT_MAX) {
			pr_err("DSA fine-grained cannot publish incomplete result page=%zu\n", i);
			return -1;
		}
		raw_off = page->raw - shared;
		if (raw_off < xfer->dsa_fg_raw_payload_base ||
		    raw_off > xfer->dsa_fg_raw_payload_head - PAGE_SIZE) {
			pr_err("DSA fine-grained raw offset is outside capture payload page=%zu off=%u\n",
			       i, raw_off);
			return -1;
		}
		result = (struct parasite_dsa_fg_result *)(shared +
			xfer->dsa_fg_result_meta_base +
			i * sizeof(*result));
		memset(result, 0, sizeof(*result));
		result->vaddr = page->vaddr;
		switch (page->state) {
		case HOT_FG_RAW_PARENT:
			result->flags = DSA_FG_PAGE_PARENT;
			if (ctx && ctx->profile)
				ctx->profile_parent_pages++;
			break;
		case HOT_FG_RAW_FULL:
			result->flags = DSA_FG_PAGE_FULL;
			result->data_off = raw_off;
			result->data_len = PAGE_SIZE;
			if (ctx && ctx->profile) {
				ctx->fg_full_pages++;
				ctx->fg_patch_bytes += PAGE_SIZE;
			}
			break;
		case HOT_FG_RAW_PATCH:
			if (!page->patch_count || page->patch_count > DSA_FG_MAX_PATCHES ||
			    page->patch_bytes > DSA_FG_MAX_BYTES) {
				pr_err("DSA fine-grained invalid patch result page=%zu ranges=%u bytes=%u\n",
				       i, page->patch_count, page->patch_bytes);
				return -1;
			}
			result->flags = DSA_FG_PAGE_PATCH;
			result->patch_count = page->patch_count;
			result->data_len = page->patch_bytes;
			if (ctx && ctx->profile) {
				ctx->fg_patch_pages++;
				ctx->fg_patch_bytes += page->patch_bytes;
				ctx->profile_patch_ranges += page->patch_count;
			}
			for (j = 0; j < page->patch_count; j++) {
				if (!page->patches[j].len ||
				    (u32)page->patches[j].off + page->patches[j].len > PAGE_SIZE) {
					pr_err("DSA fine-grained invalid patch bounds page=%zu range=%u\n", i, j);
					return -1;
				}
				result->entries[j].off = page->patches[j].off;
				result->entries[j].len = page->patches[j].len;
				result->entries[j].data_off = raw_off + page->patches[j].off;
			}
			break;
		default:
			pr_err("DSA fine-grained invalid result state=%u page=%zu\n", page->state, i);
			return -1;
		}
		if (ctx && ctx->profile)
			ctx->fg_pages++;
	}
	__atomic_thread_fence(__ATOMIC_RELEASE);
	xfer->dsa_fg_result_meta_head = head;
	((struct parasite_dsa_stream_hdr *)shared)->fg_result_meta_head = head;
	return 0;
}

static int hot_fg_load_vma_plan(struct hot_apply_ctx *ctx,
				const unsigned char *shared, u32 base, u32 head, u32 count)
{
	const struct dsa_fg_vma_plan_record *records;
	struct hot_vma_plan *plans;
	size_t bytes;
	size_t i;

	if (!ctx || !shared || head < base ||
	    count > UINT32_MAX / sizeof(*records) ||
	    (u64)head - base != (u64)count * sizeof(*records))
		return -1;
	bytes = (size_t)count * sizeof(*records);
	if (!count || !bytes)
		return -1;
	records = (const struct dsa_fg_vma_plan_record *)(shared + base);
	plans = xmalloc((size_t)count * sizeof(*plans));
	if (!plans)
		return -1;
	for (i = 0; i < count; i++) {
		if (records[i].start >= records[i].end ||
		    (records[i].start & (PAGE_SIZE - 1)) ||
		    (records[i].end & (PAGE_SIZE - 1)) ||
		    (i && records[i - 1].end > records[i].start)) {
			pr_err("DSA fine-grained service received invalid VMA plan index=%zu\n", i);
			xfree(plans);
			return -1;
		}
		plans[i].start = records[i].start;
		plans[i].end = records[i].end;
	}
	/* The service owns this generation's VMA plan.  Old plans must never be
	 * reused after a target VMA layout change. */
	xfree(ctx->vma_plans);
	ctx->vma_plans = plans;
	ctx->nr_vma_plans = count;
	ctx->vma_plans_cap = count;
	(void)bytes;
	return 0;
}

static int hot_fg_pages_from_results(struct page_xfer *xfer,
				    struct hot_apply_ctx *ctx,
				    const unsigned char *shared,
				    struct hot_fg_raw_page **pages_out,
				    size_t *nr_out,
				    size_t *failure_index,
				    unsigned long *failure_vaddr)
{
	struct hot_fg_raw_page *pages = NULL;
	size_t nr = 0, cap = 0;
	u32 desc_off;
	u32 raw_off = xfer->dsa_fg_raw_payload_base;
	size_t result_index = 0;
	(void)ctx;

	if (failure_index)
		*failure_index = SIZE_MAX;
	if (failure_vaddr)
		*failure_vaddr = ULONG_MAX;
	if (!xfer || !shared || xfer->dsa_fg_result_meta_head <
	    xfer->dsa_fg_result_meta_base)
		return -1;
	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off)
			goto err;
		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			const struct parasite_dsa_fg_result *result;
			struct hot_fg_raw_page *page;
			u16 j;

			if (failure_index)
				*failure_index = result_index;
			if (failure_vaddr)
				*failure_vaddr =
					(unsigned long)desc->src_addr + page_off;
			if (result_index >= (xfer->dsa_fg_result_meta_head -
				     xfer->dsa_fg_result_meta_base) / sizeof(*result))
				goto err;
			if (nr == cap) {
				size_t new_cap = cap ? cap * 2 : 4096;
				void *new_pages = xrealloc(pages, new_cap * sizeof(*pages));
				if (!new_pages)
					goto err;
				pages = new_pages;
				cap = new_cap;
			}
			result = (const struct parasite_dsa_fg_result *)(shared +
				xfer->dsa_fg_result_meta_base +
				result_index * sizeof(*result));
			page = &pages[nr++];
			memset(page, 0, sizeof(*page));
			page->vaddr = (unsigned long)desc->src_addr + page_off;
			page->raw = shared + raw_off + page_off;
			if (result->vaddr != page->vaddr)
				goto err;
			if (result->flags == DSA_FG_PAGE_PARENT) {
				if (result->data_len || result->patch_count)
					goto err;
				page->state = HOT_FG_RAW_PARENT;
			} else if (result->flags == DSA_FG_PAGE_FULL) {
				if (result->data_len != PAGE_SIZE || result->patch_count ||
				    result->data_off != raw_off + page_off)
					goto err;
				page->state = HOT_FG_RAW_FULL;
			} else if (result->flags == DSA_FG_PAGE_PATCH) {
				u32 sum = 0;
				if (!result->patch_count || result->patch_count > DSA_FG_MAX_PATCHES ||
				    result->data_len > DSA_FG_MAX_BYTES)
					goto err;
				page->state = HOT_FG_RAW_PATCH;
				page->patch_count = result->patch_count;
				page->patch_bytes = result->data_len;
				for (j = 0; j < result->patch_count; j++) {
					const struct parasite_dsa_fg_result_entry *in = &result->entries[j];
					if (!in->len || (u32)in->off + in->len > PAGE_SIZE ||
					    in->data_off != raw_off + page_off + in->off)
						goto err;
					page->patches[j].off = in->off;
					page->patches[j].len = in->len;
					sum += in->len;
				}
				if (sum != page->patch_bytes)
					goto err;
			} else {
				goto err;
			}
			result_index++;
		}
		raw_off += desc->copy_len;
	}
	if (raw_off != xfer->dsa_fg_raw_payload_head ||
	    result_index * sizeof(struct parasite_dsa_fg_result) !=
	    xfer->dsa_fg_result_meta_head - xfer->dsa_fg_result_meta_base)
		goto err;
	*pages_out = pages;
	*nr_out = nr;
	if (failure_index)
		*failure_index = SIZE_MAX;
	if (failure_vaddr)
		*failure_vaddr = ULONG_MAX;
	return 0;
err:
	pr_err("DSA fine-grained canonical result validation failed\n");
	xfree(pages);
	return -1;
}

/* Service-side APPLY consumes the exact result array returned by COMPARE.
 * It intentionally reconstructs only lightweight page views; raw bytes stay
 * in the arena and no result/payload is copied over the control socket. */
static int hot_fg_apply_published_results(
						       struct page_xfer *xfer,
						       struct hot_apply_ctx *ctx,
						       const unsigned char *shared)
{
	struct hot_fg_raw_page *pages = NULL;
	size_t nr = 0;
	size_t i;
	int ret = -1;

	if (hot_fg_pages_from_results(xfer, ctx, shared, &pages, &nr,
				       NULL, NULL))
		goto out;
	if (hot_memstore_materialize_vmas(ctx, NULL, NULL))
		goto out;
	for (i = 0; i < nr; i++) {
		if (hot_fg_apply_raw_page(ctx, &pages[i]))
			goto out;
	}
	ret = 0;
out:
	xfree(pages);
	return ret;
}

static int hot_fg_encode_raw_wavefront(struct page_xfer *xfer,
				       struct hot_apply_ctx *ctx,
				       const unsigned char *shared,
				       bool publish_only)
{
	struct hot_fg_raw_page *pages = NULL;
	struct hot_fg_compare_span *spans = NULL;
	struct hot_fg_output_state *output = NULL;
	struct hot_fg_raw_page *validate_pages = NULL;
	struct hot_fg_compare_span *validate_spans = NULL;
	size_t nr = 0, cap = 0, nr_spans = 0, spans_cap = 0, i;
	size_t vma_cursor = 0;
	u32 desc_off;
	u32 raw_off = xfer->dsa_fg_raw_payload_base;
	u32 capture_run = 0;
	u32 max_xfer;
	u64 phase_start_us = 0;
	u64 compare_cpu_start_us = 0;
	u64 compare_cpu_end_us = 0;
	u64 compare_engine_end_us = 0;
	u64 compare_engine_cpu_start_us = 0;
	u64 compare_engine_cpu_end_us = 0;
	u64 prefault_wall_start_us = 0;
	u64 prefault_cpu_start_us = 0;
	u64 compare_core_wall_start_us = 0;
	u64 compare_core_cpu_start_us = 0;
	u64 result_publish_start_us = 0;

	if (ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();

	for (desc_off = xfer->dsa_fg_desc_area_off;
	     desc_off < xfer->dsa_fg_desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor)) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);
		u32 page_off;

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    desc->src_addr & (PAGE_SIZE - 1) ||
		    raw_off > xfer->dsa_fg_raw_payload_head ||
		    desc->copy_len > xfer->dsa_fg_raw_payload_head - raw_off) {
			pr_err("DSA fine-grained raw descriptor is invalid off=%u src=%" PRIx64 " len=%u raw_off=%u raw_head=%u\n",
			       desc_off, desc->src_addr, desc->copy_len, raw_off,
			       xfer->dsa_fg_raw_payload_head);
			goto err;
		}
		for (page_off = 0; page_off < desc->copy_len; page_off += PAGE_SIZE) {
			if (hot_fg_raw_pages_append(ctx, &pages, &nr, &cap,
						    (unsigned long)desc->src_addr + page_off,
						    shared + raw_off + page_off))
				goto err;
		}
		raw_off += desc->copy_len;
		capture_run++;
	}
	if (raw_off != xfer->dsa_fg_raw_payload_head) {
		pr_err("DSA fine-grained raw capture size mismatch used=%u head=%u\n",
		       raw_off, xfer->dsa_fg_raw_payload_head);
		goto err;
	}
	if (ctx->profile) {
		ctx->profile_raw_index_us += dsa_profile_delta_us(phase_start_us,
							     dsa_profile_wall_now_us());
		ctx->profile_raw_pages = nr;
		ctx->profile_raw_bytes = xfer->dsa_fg_raw_payload_head -
			xfer->dsa_fg_raw_payload_base;
		ctx->profile_capture_runs = capture_run;
		phase_start_us = dsa_profile_wall_now_us();
	}
	if (ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
	    ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE) {
		max_xfer = ctx->dsa_max_transfer_size & ~(PAGE_SIZE - 1);
		if (max_xfer < PAGE_SIZE) {
			pr_err("DSA fine-grained compare max transfer is smaller than one page\n");
			goto err;
		}
	} else {
		/* CPU backends do not open a COMPARE WQ.  Their common span is
		 * bounded by the u32 wire/state representation rather than by an
		 * uninitialised DSA device limit. */
		max_xfer = UINT_MAX & ~(PAGE_SIZE - 1);
	}

	/* Build compare extents from the real address invariants.  Capture-run
	 * boundaries do not matter once adjacent raw arena, vaddr and parent
	 * addresses are all proven continuous. */
	for (i = 0; i < nr;) {
		struct hot_fg_raw_page *first = &pages[i];
		size_t j;
		unsigned long vma_end;
		u32 length;

		if (first->state != HOT_FG_RAW_PENDING) {
			i++;
			continue;
		}
		while (vma_cursor < ctx->nr_vma_plans &&
		       ctx->vma_plans[vma_cursor].end <= first->vaddr)
			vma_cursor++;
		if (vma_cursor == ctx->nr_vma_plans ||
		    ctx->vma_plans[vma_cursor].start > first->vaddr ||
		    ctx->vma_plans[vma_cursor].end < first->vaddr + PAGE_SIZE) {
			pr_err("DSA fine-grained raw page lacks current VMA plan vaddr=%lx\n",
			       first->vaddr);
			goto err;
		}
		vma_end = ctx->vma_plans[vma_cursor].end;
		j = i + 1;
		length = PAGE_SIZE;
		while (j < nr && length <= max_xfer - PAGE_SIZE) {
			struct hot_fg_raw_page *prev = &pages[j - 1];
			struct hot_fg_raw_page *next = &pages[j];

			if (next->state != HOT_FG_RAW_PENDING ||
			    next->vaddr != prev->vaddr + PAGE_SIZE ||
			    next->raw != prev->raw + PAGE_SIZE ||
			    next->parent != prev->parent + PAGE_SIZE ||
			    next->vaddr + PAGE_SIZE > vma_end)
				break;
			length += PAGE_SIZE;
			j++;
		}
		if (nr_spans == spans_cap) {
			size_t new_cap = spans_cap ? spans_cap * 2 : 256;
			void *new_spans = xrealloc(spans, new_cap * sizeof(*spans));

			if (!new_spans)
				goto err;
			spans = new_spans;
			spans_cap = new_cap;
		}
		spans[nr_spans] = (struct hot_fg_compare_span) {
			.raw = first->raw,
			.parent = first->parent,
			.first_page = i,
			.page_count = j - i,
			.length = length,
		};
		i = j;
		nr_spans++;
	}
	if (ctx->profile) {
		ctx->profile_span_build_us += dsa_profile_delta_us(phase_start_us,
							      dsa_profile_wall_now_us());
		ctx->profile_spans = nr_spans;
		for (i = 0; i < nr_spans; i++) {
			ctx->profile_span_pages += spans[i].page_count;
			if (spans[i].page_count > ctx->profile_max_span_pages)
				ctx->profile_max_span_pages = spans[i].page_count;
		}
		phase_start_us = dsa_profile_wall_now_us();
	}
	if (ctx->profile) {
		(void)hot_prq_profile_start(ctx);
		phase_start_us = dsa_profile_wall_now_us();
		compare_cpu_start_us = dsa_profile_thread_now_us();
		compare_engine_cpu_start_us = compare_cpu_start_us;
	}
	if (ctx->compare_breakdown && nr_spans) {
		prefault_wall_start_us = dsa_profile_wall_now_us();
		prefault_cpu_start_us = dsa_profile_thread_now_us();
		if (hot_fg_prefault_all(ctx, spans, nr_spans))
			goto err;
		ctx->profile_parent_prefault_wall_us +=
			dsa_profile_delta_us(prefault_wall_start_us,
					     dsa_profile_wall_now_us());
		ctx->profile_parent_prefault_cpu_us +=
			dsa_profile_delta_us(prefault_cpu_start_us,
					     dsa_profile_thread_now_us());
	}
	if (ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE && nr_spans) {
		validate_pages = xmalloc(nr * sizeof(*validate_pages));
		validate_spans = xmalloc(nr_spans * sizeof(*validate_spans));
		if (!validate_pages || !validate_spans)
			goto err;
		memcpy(validate_pages, pages, nr * sizeof(*validate_pages));
		memcpy(validate_spans, spans, nr_spans * sizeof(*validate_spans));
	}
	if (ctx->compare_breakdown && nr_spans) {
		compare_core_wall_start_us = dsa_profile_wall_now_us();
		compare_core_cpu_start_us = dsa_profile_thread_now_us();
	}
	if (nr_spans) {
		switch (ctx->fg_compare_backend) {
		case HOT_FG_COMPARE_DSA:
			if (hot_fg_compare_hw_batch(ctx, pages, spans, nr_spans))
				goto err;
			break;
		case HOT_FG_COMPARE_MEMCMP:
		case HOT_FG_COMPARE_SCALAR64:
		case HOT_FG_COMPARE_SIMD_AVX2:
		case HOT_FG_COMPARE_SIMD_AVX512:
			if (hot_fg_compare_cpu(ctx, pages, spans, nr_spans,
					       ctx->fg_compare_backend, true))
				goto err;
			break;
		case HOT_FG_COMPARE_VALIDATE:
			if (hot_fg_compare_hw_batch(ctx, pages, spans, nr_spans) ||
			    hot_fg_compare_cpu(ctx, validate_pages, validate_spans, nr_spans,
					       HOT_FG_COMPARE_SIMD_AVX512, false) ||
			    hot_fg_validate_compare_metadata(pages, validate_pages, nr,
						     spans, validate_spans, nr_spans))
				goto err;
			break;
		default:
			pr_err("DSA fine-grained compare backend is invalid\n");
			goto err;
		}
	}
	if (ctx->compare_breakdown && nr_spans) {
		ctx->profile_compare_core_wall_us +=
			dsa_profile_delta_us(compare_core_wall_start_us,
					     dsa_profile_wall_now_us());
		ctx->profile_compare_core_cpu_us +=
			dsa_profile_delta_us(compare_core_cpu_start_us,
					     dsa_profile_thread_now_us());
	}
	if (ctx->profile) {
		compare_engine_end_us = dsa_profile_wall_now_us();
		compare_engine_cpu_end_us = dsa_profile_thread_now_us();
		(void)hot_prq_profile_stop(ctx);
	}
	for (i = 0; i < nr; i++) {
		if (pages[i].state != HOT_FG_RAW_PARENT &&
		    pages[i].state != HOT_FG_RAW_PATCH &&
		    pages[i].state != HOT_FG_RAW_FULL) {
			pr_err("DSA fine-grained compare barrier has incomplete page=%zu vaddr=%lx state=%u\n",
			       i, pages[i].vaddr, pages[i].state);
			goto err;
		}
	}
	if (publish_only) {
		if (ctx->profile)
			result_publish_start_us = dsa_profile_wall_now_us();
		if (hot_fg_publish_results(xfer, shared, pages, nr))
			goto err;
		if (ctx->profile)
			ctx->profile_sidecar_emit_us +=
				dsa_profile_delta_us(result_publish_start_us,
						     dsa_profile_wall_now_us());
	} else {
		output = xzalloc(sizeof(*output));
		if (!output)
			goto err;
		output->ctx = ctx;
		output->pages = pages;
		output->nr_pages = nr;
		output->sink.idx_fd = ctx->fg_idx_fd;
		output->sink.dat_fd = ctx->fg_dat_fd;
		output->sink.dat_off = ctx->fg_dat_off;
		output->sink.stats = (struct dsa_fg_sidecar_stats) {
			.enabled = ctx->profile,
			.idx_write_calls = &ctx->profile_idx_writes,
			.dat_write_calls = &ctx->profile_dat_writes,
			.dat_writev_calls = &ctx->profile_dat_writevs,
			.write_units = &ctx->profile_write_units,
			.write_unit_max_us = &ctx->profile_write_unit_max_us,
		};
		if (hot_fg_output_drain(output))
			goto err;
	}
	if (ctx->profile) {
		compare_cpu_end_us = dsa_profile_thread_now_us();
		ctx->profile_compare_wall_us += dsa_profile_delta_us(phase_start_us,
							       dsa_profile_wall_now_us());
		ctx->profile_compare_cpu_us += dsa_profile_delta_us(compare_cpu_start_us,
							      compare_cpu_end_us);
		ctx->profile_compare_engine_wall_us +=
			dsa_profile_delta_us(phase_start_us, compare_engine_end_us);
		ctx->profile_compare_engine_cpu_us +=
			dsa_profile_delta_us(compare_engine_cpu_start_us,
					     compare_engine_cpu_end_us);
		if (ctx->profile_output_start_us)
			ctx->profile_output_wall_us +=
				dsa_profile_delta_us(ctx->profile_output_start_us,
						     dsa_profile_wall_now_us());
		phase_start_us = dsa_profile_wall_now_us();
	}
	if (!publish_only) {
		if (ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		/* Current VMA coverage is not needed by COMPARE.  Delay gap backing
		 * creation until the durable sidecar has been fully emitted, so a
		 * compare/serializer failure cannot create or prefill a new VMA file. */
		if (hot_memstore_materialize_vmas(ctx, NULL, NULL))
			goto err;
		if (ctx->profile)
			ctx->profile_materialize_us += dsa_profile_delta_us(phase_start_us,
								      dsa_profile_wall_now_us());
		if (ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		for (i = 0; i < nr; i++) {
			if (hot_fg_apply_raw_page(ctx, &pages[i]))
				goto err;
		}
	}
	if (ctx->profile)
		ctx->profile_hot_apply_us += dsa_profile_delta_us(phase_start_us,
							       dsa_profile_wall_now_us());
	xfer->dsa_fg_materialized = true;
	if (dsa_debug_enabled())
		pr_info("DSA_FG_RAW_ENCODE: pages_id=%u backend=%s raw_bytes=%u compare_ops=%" PRIu64 " spans=%zu inflight=%u max_xfer=%u\n",
			xfer->pages_id,
			hot_fg_compare_backend_name(ctx->fg_compare_backend),
			xfer->dsa_fg_raw_payload_head - xfer->dsa_fg_raw_payload_base,
			ctx->fg_compare_ops, nr_spans,
			ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
			ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE ?
			HOT_DSA_COMPARE_INFLIGHT : 0, max_xfer);
	xfree(validate_spans);
	xfree(validate_pages);
	xfree(output);
	xfree(spans);
	xfree(pages);
	return 0;
err:
	if (ctx->profile_prq_active)
		(void)hot_prq_profile_stop(ctx);
	xfree(validate_spans);
	xfree(validate_pages);
	xfree(output);
	xfree(spans);
	xfree(pages);
	return -1;
}

static int hot_fg_write_pages_loc(struct page_xfer *xfer, int p,
			  unsigned long len,
			  struct hot_apply_extent *pending_entry)
{
	struct hot_apply_ctx *ctx = xfer->hot_apply;
	unsigned long curr;
	unsigned char page[PAGE_SIZE];

	if (!pending_entry || len % PAGE_SIZE) {
		pr_err("DSA fine-grained write requires page-aligned pending extent len=%lu\n",
		       len);
		return -1;
	}

	for (curr = 0; curr < len; curr += PAGE_SIZE) {
		uint64_t start_us;
		unsigned long vaddr = pending_entry->vaddr + curr;

		start_us = hot_now_us();
		if (read_full_fd(p, page, PAGE_SIZE)) {
			pr_perror("DSA fine-grained current page read failed");
			return -1;
		}
		if (hot_fg_write_page(ctx, vaddr, page))
			return -1;
		if (hot_memstore_write_to_segments(ctx, page, vaddr, PAGE_SIZE))
			return -1;
		ctx->append_splice_us += hot_now_us() - start_us;
		ctx->append_bytes += PAGE_SIZE;
		ctx->memstore_bytes += PAGE_SIZE;
	}

	return 0;
}

/*
 * The normal DSA dump has already copied the frozen target bytes into the
 * shared payload arena.  Encode that stable arena after thaw; do not read the
 * target address space again and do not route it back through the replay pipe.
 */
static int page_xfer_dsa_fg_encode_raw_capture(struct page_xfer *xfer)
{
	struct hot_apply_ctx *ctx;
	const unsigned char *shared;

	if (!xfer || !xfer->dsa_fg_raw_capture || !xfer->dsa_fg_shared) {
		pr_err("DSA fine-grained raw capture metadata is incomplete\n");
		return -1;
	}
	ctx = xfer->hot_apply;
	if (!ctx || !ctx->memstore || !ctx->fine_output) {
		pr_err("DSA fine-grained raw capture requires an initialized hot memstore\n");
		return -1;
	}
	if (hot_apply_prepare_post_thaw(ctx))
		return -1;
	if (xfer->dsa_fg_desc_head < xfer->dsa_fg_desc_area_off ||
	    xfer->dsa_fg_raw_payload_head < xfer->dsa_fg_raw_payload_base) {
		pr_err("DSA fine-grained raw capture has invalid bounds\n");
		return -1;
	}

	shared = xfer->dsa_fg_shared;
	return hot_fg_encode_raw_wavefront(xfer, ctx, shared, false);
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	if (xfer->hot_apply)
		hot_apply_abort(xfer);
	xfree(xfer->dsa_fg_vma_plan_local);
	xfer->dsa_fg_vma_plan_local = NULL;
	xfer->dsa_fg_vma_plan_count = 0;
	close_image(xfer->pi);
	close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;

	xfer->pmi = open_image(fd_type, O_DUMP, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, &pages_id);
	if (!xfer->pi)
		goto err_pmi;

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP) ? PR_TASK : PR_SHMEM;

		/* Image streaming lacks support for incremental images */
		if (opts.stream)
			goto out;

		if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
			goto err_pi;
		if (pfd < 0)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			goto err_pi;
		}

		ret = open_page_read_at(pfd, img_id, xfer->parent, pr_flags);
		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	if (hot_apply_init_xfer(xfer, fd_type, img_id, pages_id))
		goto err_parent;

	xfer->pages_id = pages_id;
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;

err_parent:
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
err_pi:
	close_image(xfer->pi);
err_pmi:
	close_image(xfer->pmi);
	return -1;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	xfer->offset = 0;
	xfer->transfer_lazy = true;
	xfer->dsa_fine_grained = false;
	xfer->hot_apply = NULL;
	xfer->write_profile_enabled = false;
	xfer->write_profile_emitted = false;
	xfer->write_profile_target = !opts.use_page_server &&
		dsa_page_xfer_profile_target(fd_type, img_id);

	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, img_id);
	else
		return open_page_local_xfer(xfer, fd_type, img_id);
}

int open_page_xfer_no_parent(struct page_xfer *xfer, int fd_type, unsigned long img_id)
{
	u32 pages_id;
	unsigned long image_flags = O_DUMP;

	if (opts.use_page_server) {
		pr_err("DSA parent index mode does not support page server xfer\n");
		return -1;
	}

	xfer->offset = 0;
	xfer->transfer_lazy = true;
	xfer->dsa_fine_grained = false;
	xfer->parent = NULL;
	xfer->hot_apply = NULL;
	xfer->dsa_fg_service = false;
	xfer->write_profile_enabled = false;
	xfer->write_profile_emitted = false;
	xfer->write_profile_target =
		dsa_page_xfer_profile_target(fd_type, img_id);
	xfer->dsa_output_direct = dsa_direct_output_enabled_for_img(img_id);
	if (xfer->dsa_output_direct)
		image_flags |= O_DSA_DIRECT_STREAM;
	xfer->pmi = open_image(fd_type, image_flags, img_id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(image_flags, xfer->pmi, &pages_id);
	if (!xfer->pi) {
		close_image(xfer->pmi);
		return -1;
	}

	if (dsa_memory_service_client_init(xfer, img_id) ||
	    (!xfer->dsa_fg_service && hot_apply_init_xfer(xfer, fd_type, img_id, pages_id))) {
		close_image(xfer->pi);
		close_image(xfer->pmi);
		return -1;
	}

	xfer->pages_id = pages_id;
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;
}

int page_xfer_dsa_fg_enable(struct page_xfer *xfer)
{
	if (!xfer)
		return -1;
	xfer->dsa_fine_grained = true;
	return 0;
}

static int page_xfer_dump_hole(struct page_xfer *xfer, struct iovec *hole, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)xfer->offset);
	hole->iov_base -= xfer->offset;
	pr_debug("\th %p [%u]\n", hole->iov_base, (unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_pagemap(xfer, hole, flags))
		return -1;

	return 0;
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp, unsigned int *cur_hole, void *limit)
{
	int ret;

	for (; *cur_hole < pp->free_hole; (*cur_hole)++) {
		struct iovec hole = pp->holes[*cur_hole];
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static inline u32 ppb_xfer_flags(struct page_xfer *xfer, struct page_pipe_buf *ppb)
{
	if (ppb->flags & PPB_LAZY)
		/*
		 * Pages that can be lazily restored are always marked as such.
		 * In the case we actually transfer them into image mark them
		 * as present as well.
		 */
		return (xfer->transfer_lazy ? PE_PRESENT : 0) | PE_LAZY;
	else
		return PE_PRESENT;
}

/*
 * Optimized pre-dump algorithm
 * ==============================
 *
 * Note: Please refer man(2) page of process_vm_readv syscall.
 *
 * The following discussion covers the possibly faulty-iov
 * locations in an iovec, which hinders process_vm_readv from
 * dumping the entire iovec in a single invocation.
 *
 * Memory layout of target process:
 *
 * Pages: A        B        C
 *	  +--------+--------+--------+--------+--------+--------+
 *	  |||||||||||||||||||||||||||||||||||||||||||||||||||||||
 *	  +--------+--------+--------+--------+--------+--------+
 *
 * Single "iov" representation: {starting_address, length_in_bytes}
 * An iovec is array of iov-s.
 *
 * NOTE: For easy representation and discussion purpose, we carry
 *	 out further discussion at "page granularity".
 *	 length_in_bytes will represent page count in iov instead
 *	 of byte count. Same assumption applies for the syscall's
 *	 return value. Instead of returning the number of bytes
 *	 read, it returns a page count.
 *
 * For above memory mapping, generated iovec: {A,1}{B,1}{C,4}
 *
 * This iovec remains unmodified once generated. At the same
 * time some of memory regions listed in iovec may get modified
 * (unmap/change protection) by the target process while syscall
 * is trying to dump iovec regions.
 *
 * Case 1:
 *	A is unmapped, {A,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |        ||||||||||||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^        ^
 *      |        |
 *      start    |
 *      (1)      |
 *               start
 *               (2)
 *
 *	process_vm_readv will return -1. Increment start pointer(2),
 *	syscall will process {B,1}{C,4} in one go and copy 5 pages
 *	to userbuf from iov-B and iov-C.
 *
 * Case 2:
 *	B is unmapped, {B,1} become faulty iov
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      |||||||||         |||||||||||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                 ^
 *      |                 |
 *      start             |
 *      (1)               |
 *                        start
 *                        (2)
 *
 *	process_vm_readv will return 1, i.e. page A copied to
 *	userbuf successfully and syscall stopped, since B got
 *	unmapped.
 *
 *	Increment the start pointer to C(2) and invoke syscall.
 *	Userbuf contains 5 pages overall from iov-A and iov-C.
 *
 * Case 3:
 *	This case deals with partial unmapping of iov representing
 *	more than one pagesize region.
 *
 *	Syscall can't process such faulty iov as whole. So we
 *	process such regions part-by-part and form new sub-iovs
 *	in aux_iov from successfully processed pages.
 *
 *
 *	Part 3.1:
 *		First page of C is unmapped
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||         ||||||||||||||||||||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                          ^
 *      |                          |
 *      start                      |
 *      (1)                        |
 *                                 dummy
 *                                 (2)
 *
 *	process_vm_readv will return 2, i.e. pages A and B copied.
 *	We identify length of iov-C is more than 1 page, that is
 *	where this case differs from Case 2.
 *
 *	dummy-iov is introduced(2) as: {C+1,3}. dummy-iov can be
 *	directly placed at next page to failing page. This will copy
 *	remaining 3 pages from iov-C to userbuf. Finally create
 *	modified iov entry in aux_iov. Complete aux_iov look like:
 *
 *	aux_iov: {A,1}{B,1}{C+1,3}*
 *
 *
 *	Part 3.2:
 *		In between page of C is unmapped, let's say third
 *
 *      A        B        C
 *      +--------+--------+--------+--------+--------+--------+
 *      ||||||||||||||||||||||||||||||||||||         ||||||||||
 *      +--------+--------+--------+--------+--------+--------+
 *      ^                                            ^
 *      |                 |-----------------|        |
 *      start              partial_read_bytes        |
 *      (1)                                          |
 *                                                   dummy
 *                                                   (2)
 *
 *	process_vm_readv will return 4, i.e. pages A and B copied
 *	completely and first two pages of C are also copied.
 *
 *	Since, iov-C is not processed completely, we need to find
 *	"partial_read_byte" count to place out dummy-iov for
 *	remaining processing of iov-C. This function is performed by
 *	analyze_iov function.
 *
 *	dummy-iov will be(2): {C+3,1}. dummy-iov will be placed
 *	next to first failing address to process remaining iov-C.
 *	New entries in aux_iov will look like:
 *
 *	aux_iov: {A,1}{B,1}{C,2}*{C+3,1}*
 */

unsigned long handle_faulty_iov(int pid, struct iovec *riov, unsigned long faulty_index, struct iovec *bufvec,
				struct iovec *aux_iov, unsigned long *aux_len)
{
	struct iovec dummy;
	ssize_t bytes_read;
	unsigned long final_read_cnt = 0;

	/* Handling Case 3-Part 3.2*/
	dummy.iov_base = riov[faulty_index].iov_base;
	dummy.iov_len = riov[faulty_index].iov_len;

	while (dummy.iov_len) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &dummy, 1, 0);
		if (bytes_read == -1) {
			/* Handling faulty page read in faulty iov */
			cnt_sub(CNT_PAGES_WRITTEN, 1);
			dummy.iov_base += PAGE_SIZE;
			dummy.iov_len -= PAGE_SIZE;
			continue;
		}

		/* If aux-iov can merge and expand or new entry required */
		if (aux_iov[(*aux_len) - 1].iov_base + aux_iov[(*aux_len) - 1].iov_len == dummy.iov_base)
			aux_iov[(*aux_len) - 1].iov_len += bytes_read;
		else {
			aux_iov[*aux_len].iov_base = dummy.iov_base;
			aux_iov[*aux_len].iov_len = bytes_read;
			(*aux_len) += 1;
		}

		dummy.iov_base += bytes_read;
		dummy.iov_len -= bytes_read;
		bufvec->iov_base += bytes_read;
		bufvec->iov_len -= bytes_read;
		final_read_cnt += bytes_read;
	}

	return final_read_cnt;
}

/*
 * This function will position start pointer to the latest
 * successfully read iov in iovec.
 */
static unsigned long analyze_iov(ssize_t bytes_read, struct iovec *riov, unsigned long *index, struct iovec *aux_iov,
				 unsigned long *aux_len)
{
	ssize_t processed_bytes = 0;

	/* correlating iovs with read bytes */
	while (processed_bytes < bytes_read) {
		processed_bytes += riov[*index].iov_len;
		aux_iov[*aux_len].iov_base = riov[*index].iov_base;
		aux_iov[*aux_len].iov_len = riov[*index].iov_len;

		(*aux_len) += 1;
		(*index) += 1;
	}

	/* handling partially processed faulty iov*/
	if (processed_bytes - bytes_read) {
		unsigned long partial_read_bytes = 0;

		(*index) -= 1;

		partial_read_bytes = riov[*index].iov_len - (processed_bytes - bytes_read);
		aux_iov[*aux_len - 1].iov_len = partial_read_bytes;
		riov[*index].iov_base += partial_read_bytes;
		riov[*index].iov_len -= partial_read_bytes;
	}

	return 0;
}

/*
 * This function iterates over complete ppb->iov entries and pass
 * them to process_vm_readv syscall.
 *
 * Since process_vm_readv returns count of successfully read bytes.
 * It does not point to iovec entry associated to last successful
 * byte read. The correlation between bytes read and corresponding
 * iovec is setup through analyze_iov function.
 *
 * If all iovecs are not processed in one go, it means there exists
 * some faulty iov entry(memory mapping modified after it was grabbed)
 * in iovec. process_vm_readv syscall stops at such faulty iov and
 * skip processing further any entry in iovec. This is handled by
 * handle_faulty_iov function.
 */
static long fill_userbuf(int pid, struct page_pipe_buf *ppb, struct iovec *bufvec, struct iovec *aux_iov,
			 unsigned long *aux_len)
{
	struct iovec *riov = ppb->iov;
	ssize_t bytes_read;
	unsigned long total_read = 0;
	unsigned long start = 0;

	while (start < ppb->nr_segs) {
		bytes_read = process_vm_readv(pid, bufvec, 1, &riov[start], ppb->nr_segs - start, 0);
		if (bytes_read == -1) {
			if (errno == ESRCH) {
				pr_debug("Target process PID:%d not found\n", pid);
				return -ESRCH;
			}
			if (errno != EFAULT) {
				pr_perror("process_vm_readv failed");
				return -1;
			}
			/* Handling Case 1*/
			if (riov[start].iov_len == PAGE_SIZE) {
				cnt_sub(CNT_PAGES_WRITTEN, 1);
				start += 1;
				continue;
			}
			total_read += handle_faulty_iov(pid, riov, start, bufvec, aux_iov, aux_len);
			start += 1;
			continue;
		}

		if (bytes_read > 0) {
			if (analyze_iov(bytes_read, riov, &start, aux_iov, aux_len) < 0)
				return -1;
			bufvec->iov_base += bytes_read;
			bufvec->iov_len -= bytes_read;
			total_read += bytes_read;
		}
	}

	return total_read;
}

/*
 * This function is similar to page_xfer_dump_pages, instead it uses
 * auxiliary_iov array for pagemap generation.
 *
 * The entries of ppb->iov may mismatch with actual process mappings
 * present at time of pre-dump. Such entries need to be adjusted as per
 * the pages read by process_vm_readv syscall. These adjusted entries
 * along with unmodified entries are present in aux_iov array.
 */

int page_xfer_predump_pages(int pid, struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0, i;
	unsigned long ret, bytes_read;
	unsigned long userbuf_len;
	struct iovec bufvec;

	struct iovec *aux_iov;
	unsigned long aux_len;
	void *userbuf;

	userbuf_len = PIPE_MAX_BUFFER_SIZE;
	userbuf = mmap(NULL, userbuf_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (userbuf == MAP_FAILED) {
		pr_perror("Unable to mmap a buffer");
		return -1;
	}
	aux_iov = xmalloc(userbuf_len / PAGE_SIZE * sizeof(aux_iov[0]));
	if (!aux_iov)
		goto err;

	list_for_each_entry(ppb, &pp->bufs, l) {
		if (ppb->pipe_size * PAGE_SIZE > userbuf_len) {
			void *addr;

			addr = mremap(userbuf, userbuf_len, ppb->pipe_size * PAGE_SIZE, MREMAP_MAYMOVE);
			if (addr == MAP_FAILED) {
				pr_perror("Unable to mmap a buffer");
				goto err;
			}
			userbuf_len = ppb->pipe_size * PAGE_SIZE;
			userbuf = addr;
			addr = xrealloc(aux_iov, ppb->pipe_size * sizeof(aux_iov[0]));
			if (!addr)
				goto err;
			aux_iov = addr;
		}
		timing_start(TIME_MEMDUMP);

		aux_len = 0;
		bufvec.iov_len = userbuf_len;
		bufvec.iov_base = userbuf;

		bytes_read = fill_userbuf(pid, ppb, &bufvec, aux_iov, &aux_len);
		if (bytes_read == -ESRCH) {
			timing_stop(TIME_MEMDUMP);
			munmap(userbuf, userbuf_len);
			xfree(aux_iov);
			return 0;
		}
		if (bytes_read < 0)
			goto err;

		bufvec.iov_base = userbuf;
		bufvec.iov_len = bytes_read;
		ret = vmsplice(ppb->p[1], &bufvec, 1, SPLICE_F_NONBLOCK | SPLICE_F_GIFT);

		if (ret == -1 || ret != bytes_read) {
			pr_err("vmsplice: Failed to splice user buffer to pipe %ld\n", ret);
			goto err;
		}

		timing_stop(TIME_MEMDUMP);
		timing_start(TIME_MEMWRITE);

		/* generating pagemap */
		for (i = 0; i < aux_len; i++) {
			struct iovec iov = aux_iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto err;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\t p %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = ppb_xfer_flags(xfer, ppb);

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto err;

			if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto err;
		}

		timing_stop(TIME_MEMWRITE);
	}

	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	timing_start(TIME_MEMWRITE);

	return dump_holes(xfer, pp, &cur_hole, NULL);
err:
	munmap(userbuf, userbuf_len);
	xfree(aux_iov);
	return -1;
}

static void page_xfer_write_profile_begin(struct page_xfer *xfer)
{
	if (!xfer || !xfer->write_profile_target || !dsa_profile_enabled() ||
	    !dsa_page_xfer_dump_enabled())
		return;

	xfer->write_profile_enabled = true;
	xfer->write_profile_emitted = false;
	xfer->write_profile_start_wall_us = dsa_profile_wall_now_us();
	xfer->write_profile_start_cpu_us = dsa_profile_thread_now_us();
	xfer->write_profile_io_wall_us = 0;
	xfer->write_profile_io_cpu_us = 0;
	xfer->write_profile_input_pages = 0;
	xfer->write_profile_input_bytes = 0;
	xfer->write_profile_pagemap_records = 0;
	xfer->write_profile_pagemap_bytes = 0;
	xfer->write_profile_pages_bytes = 0;
	xfer->write_profile_pages_emit_calls = 0;
}

static void page_xfer_write_profile_emit(struct page_xfer *xfer, int ret)
{
	const struct cdp_dsa_memory_service_profile *service;
	const char *path;
	u64 sidecar_idx_bytes = 0;
	u64 sidecar_dat_bytes = 0;
	u64 idx_write_syscalls = 0;
	u64 dat_write_syscalls = 0;
	u64 dat_writev_syscalls = 0;
	u64 logical_output_bytes;
	u64 total_wall_us;
	u64 total_cpu_us;

	if (!xfer || !xfer->write_profile_enabled ||
	    xfer->write_profile_emitted)
		return;
	xfer->write_profile_emitted = true;
	service = &xfer->dsa_fg_service_profile;
	if (xfer->dsa_fg_raw_capture && dsa_aligned_full_enabled()) {
		path = "dsa-full";
	} else if (xfer->dsa_fg_service || xfer->dsa_fg_raw_capture ||
		   xfer->dsa_fine_grained) {
		path = "dsa-fg";
		sidecar_idx_bytes = service->idx_bytes;
		sidecar_dat_bytes = service->dat_bytes;
		idx_write_syscalls = service->idx_write_syscalls;
		dat_write_syscalls = service->dat_write_syscalls;
		dat_writev_syscalls = service->dat_writev_syscalls;
	} else {
		path = "dsa-full";
	}
	logical_output_bytes = xfer->write_profile_pages_bytes +
		sidecar_idx_bytes + sidecar_dat_bytes +
		xfer->write_profile_pagemap_bytes;
	total_wall_us = dsa_profile_delta_us(
		xfer->write_profile_start_wall_us, dsa_profile_wall_now_us());
	total_cpu_us = dsa_profile_delta_us(
		xfer->write_profile_start_cpu_us, dsa_profile_thread_now_us());

	pr_info("WRITE_PATH_PROFILE: version=3 path=%s output_mode=%s "
		"snapshot_ready_to_finish_us=%" PRIu64
		" snapshot_ready_to_finish_thread_cpu_us=%" PRIu64
		" io_emit_us=%" PRIu64 " io_emit_thread_cpu_us=%" PRIu64
		" input_pages=%" PRIu64 " input_bytes=%" PRIu64
		" pagemap_records=%" PRIu64 " pagemap_bytes=%" PRIu64
		" pages_bytes=%" PRIu64 " sidecar_idx_bytes=%" PRIu64
		" sidecar_dat_bytes=%" PRIu64 " logical_output_bytes=%" PRIu64
		" pages_emit_calls=%" PRIu64
		" pagemap_direct_write_calls=%" PRIu64
		" idx_write_syscalls=%" PRIu64
		" dat_write_syscalls=%" PRIu64 " dat_writev_syscalls=%" PRIu64
		" ret=%d\n",
		path, xfer->dsa_output_direct ? "direct-sync" : "buffered",
		total_wall_us, total_cpu_us,
		xfer->write_profile_io_wall_us, xfer->write_profile_io_cpu_us,
		xfer->write_profile_input_pages, xfer->write_profile_input_bytes,
		xfer->write_profile_pagemap_records,
		xfer->write_profile_pagemap_bytes,
		xfer->write_profile_pages_bytes, sidecar_idx_bytes,
		sidecar_dat_bytes, logical_output_bytes,
		xfer->write_profile_pages_emit_calls,
	image_direct_write_calls(xfer->pmi), idx_write_syscalls,
		dat_write_syscalls, dat_writev_syscalls, ret);
}

static int page_xfer_bind_direct_arena_scratch(struct page_xfer *xfer)
{
	void *pagemap_scratch;

	if (!xfer->dsa_output_direct || !xfer->dsa_fg_service)
		return 0;
	if (!xfer->dsa_fg_shared ||
	    xfer->dsa_dio_idx_scratch_off % PAGE_SIZE ||
	    xfer->dsa_dio_dat_scratch_off !=
		    xfer->dsa_dio_idx_scratch_off +
			    DSA_DIRECT_METADATA_STAGE_BYTES ||
	    xfer->dsa_dio_pagemap_scratch_off !=
		    xfer->dsa_dio_dat_scratch_off +
			    DSA_DIRECT_PAYLOAD_STAGE_BYTES ||
	    xfer->dsa_dio_scratch_limit !=
		    xfer->dsa_dio_pagemap_scratch_off +
			    DSA_DIRECT_METADATA_STAGE_BYTES ||
	    xfer->dsa_dio_scratch_limit > xfer->dsa_fg_result_meta_base ||
	    xfer->dsa_fg_raw_payload_head > xfer->dsa_dio_idx_scratch_off) {
		pr_err("DSA direct pagemap scratch bounds are invalid idx=%u dat=%u pagemap=%u limit=%u raw_head=%u result=%u\n",
		       xfer->dsa_dio_idx_scratch_off,
		       xfer->dsa_dio_dat_scratch_off,
		       xfer->dsa_dio_pagemap_scratch_off,
		       xfer->dsa_dio_scratch_limit,
		       xfer->dsa_fg_raw_payload_head,
		       xfer->dsa_fg_result_meta_base);
		return -1;
	}
	pagemap_scratch = (unsigned char *)xfer->dsa_fg_shared +
		xfer->dsa_dio_pagemap_scratch_off;
	if (image_direct_rebind_buffer(xfer->pmi, pagemap_scratch,
				       DSA_DIRECT_METADATA_STAGE_BYTES)) {
		pr_perror("DSA direct pagemap cannot bind arena scratch");
		return -1;
	}
	if (dsa_profile_enabled())
		pr_info("DSA_DIRECT_SCRATCH: mode=arena idx_off=%u idx_bytes=%u dat_off=%u dat_bytes=%u pagemap_off=%u pagemap_bytes=%u limit=%u\n",
			xfer->dsa_dio_idx_scratch_off,
			DSA_DIRECT_METADATA_STAGE_BYTES,
			xfer->dsa_dio_dat_scratch_off,
			DSA_DIRECT_PAYLOAD_STAGE_BYTES,
			xfer->dsa_dio_pagemap_scratch_off,
			DSA_DIRECT_METADATA_STAGE_BYTES,
			xfer->dsa_dio_scratch_limit);
	return 0;
}

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	struct hot_apply_ctx *profile_ctx = xfer->hot_apply;
	unsigned int cur_hole = 0;
	int ret = -1;
	u64 phase_start_us = 0;
	u64 service_phase_start_us = 0;
	u64 write_phase_start_us = 0;
	u64 write_phase_start_cpu_us = 0;
	bool service_profile = xfer->dsa_fg_service && dsa_profile_enabled();

	if (page_xfer_bind_direct_arena_scratch(xfer))
		return -1;
	page_xfer_write_profile_begin(xfer);
	hot_profile_begin(profile_ctx);
	if (service_profile)
		xfer->dsa_fg_profile_total_start_us = dsa_profile_wall_now_us();

	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (xfer->hot_apply && !xfer->hot_apply->post_thaw_ready &&
	    hot_apply_prepare_post_thaw(xfer->hot_apply))
		goto out;
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_post_prepare_us += dsa_profile_delta_us(phase_start_us,
								      dsa_profile_wall_now_us());

	if (xfer->dsa_fg_raw_capture && !xfer->dsa_fg_materialized) {
		if (xfer->dsa_fg_service) {
			uint64_t fg_start_us = hot_now_us();

			if (dsa_memory_service_raw_sealed(xfer))
				goto out;
			if (dsa_aligned_full_enabled()) {
				/* The generic transfer below emits ordinary PE_PRESENT
				 * records and streams the same sealed raw bytes through the
				 * bounded direct writer.  There is no delta classification. */
				xfer->dsa_fg_materialized = true;
				pr_info("DSA_ALIGNED_FULL_SEALED: pages_id=%u raw_bytes=%u\n",
					xfer->pages_id, xfer->dsa_fg_raw_payload_head -
					xfer->dsa_fg_raw_payload_base);
			} else if (dsa_memory_service_compare(xfer)) {
				goto out;
			}
			if (!dsa_aligned_full_enabled()) {
			if (xfer->write_profile_enabled) {
				write_phase_start_us = dsa_profile_wall_now_us();
				write_phase_start_cpu_us = dsa_profile_thread_now_us();
			}
			if (service_profile)
				service_phase_start_us = dsa_profile_wall_now_us();
			if (page_xfer_dsa_fg_write_sidecar_results(
				    xfer, xfer->dsa_fg_shared))
				goto out;
			if (xfer->write_profile_enabled) {
				xfer->write_profile_io_wall_us += dsa_profile_delta_us(
					write_phase_start_us, dsa_profile_wall_now_us());
				xfer->write_profile_io_cpu_us += dsa_profile_delta_us(
					write_phase_start_cpu_us,
					dsa_profile_thread_now_us());
			}
			if (service_profile)
				xfer->dsa_fg_profile_sidecar_us =
					dsa_profile_delta_us(service_phase_start_us,
							     dsa_profile_wall_now_us());
			if (page_xfer_dsa_fg_enable(xfer))
				goto out;
			xfer->dsa_fg_materialized = true;
			pr_info("DSA_FG_SERVICE_COMPARE: pages_id=%u result_pages=%zu sidecar_write_us=%" PRIu64 "\n",
				xfer->pages_id,
				(xfer->dsa_fg_result_meta_head - xfer->dsa_fg_result_meta_base) /
				sizeof(struct parasite_dsa_fg_result),
				hot_now_us() - fg_start_us);
			}
		} else if (page_xfer_dsa_fg_encode_raw_capture(xfer)) {
			goto out;
		}
	}

	pr_debug("Transferring pages:\n");
	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (service_profile)
		service_phase_start_us = dsa_profile_wall_now_us();
	if (xfer->write_profile_enabled) {
		write_phase_start_us = dsa_profile_wall_now_us();
		write_phase_start_cpu_us = dsa_profile_thread_now_us();
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %lx/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];
			u32 flags;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base);
			if (ret)
				goto out;

			BUG_ON(iov.iov_base < (void *)xfer->offset);
			iov.iov_base -= xfer->offset;
			pr_debug("\tp %p - %p\n", iov.iov_base, iov.iov_base + iov.iov_len);

			flags = page_xfer_effective_flags(xfer, ppb_xfer_flags(xfer, ppb));
			if (xfer->write_profile_enabled && (flags & PE_PRESENT)) {
				xfer->write_profile_input_pages += iov.iov_len / PAGE_SIZE;
				xfer->write_profile_input_bytes += iov.iov_len;
			}

			if (xfer->write_pagemap(xfer, &iov, flags))
				goto out;
			if ((flags & PE_PRESENT) && !(flags & PE_DSA_FG) &&
			    xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
				goto out;
			if (profile_ctx && profile_ctx->profile)
				profile_ctx->profile_pagemap_iovs++;
		}
	}

	ret = dump_holes(xfer, pp, &cur_hole, NULL);
	if (ret)
		goto out;
	/* Full-control mode has emitted the ordinary pagemap above, while payload
	 * bytes were accumulated directly from the sealed arena.  Flush only once
	 * the page-pipe traversal has consumed exactly the frozen raw sequence. */
	if (xfer->dsa_fg_raw_capture && dsa_aligned_full_enabled()) {
		if (xfer->dsa_fg_raw_emit_cursor != xfer->dsa_fg_raw_payload_head) {
			pr_err("DSA aligned full raw cursor mismatch cursor=%u head=%u\n",
			       xfer->dsa_fg_raw_emit_cursor,
			       xfer->dsa_fg_raw_payload_head);
			goto out;
		}
		if (dsa_aligned_full_flush(xfer))
			goto out;
	}
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_pagemap_plan_us += dsa_profile_delta_us(phase_start_us,
								    dsa_profile_wall_now_us());
	if (hot_fg_defer_pagemap(xfer)) {
		if (profile_ctx && profile_ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		if (hot_fg_pagemap_validate(xfer))
			goto out;
		if (profile_ctx && profile_ctx->profile)
			profile_ctx->profile_parent_validate_us +=
				dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
		if (profile_ctx && profile_ctx->profile)
			phase_start_us = dsa_profile_wall_now_us();
		if (hot_fg_pagemap_emit(xfer))
			goto out;
		if (profile_ctx && profile_ctx->profile)
			profile_ctx->profile_pagemap_pack_us +=
				dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	}
	/* All logical output bytes are now known.  Complete the direct writers
	 * before publishing any hot-memory generation; a later APPLY must never
	 * make an un-synced image visible as its parent. */
	if (xfer->dsa_output_direct &&
	    (image_direct_finish(xfer->pi) || image_direct_finish(xfer->pmi)))
		goto out;
	if (xfer->dsa_output_direct &&
	    (image_direct_close(xfer->pi) || image_direct_close(xfer->pmi)))
		goto out;
	if (xfer->write_profile_enabled) {
		xfer->write_profile_io_wall_us += dsa_profile_delta_us(
			write_phase_start_us, dsa_profile_wall_now_us());
		xfer->write_profile_io_cpu_us += dsa_profile_delta_us(
			write_phase_start_cpu_us, dsa_profile_thread_now_us());
	}
	if (service_profile)
		xfer->dsa_fg_profile_pagemap_us =
			dsa_profile_delta_us(service_phase_start_us,
					     dsa_profile_wall_now_us());
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_pagemap_us += profile_ctx->profile_pagemap_plan_us +
			profile_ctx->profile_parent_validate_us + profile_ctx->profile_pagemap_pack_us;
	if (profile_ctx && profile_ctx->profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (service_profile)
		service_phase_start_us = dsa_profile_wall_now_us();
	ret = hot_apply_finish(xfer);
	if (service_profile)
		xfer->dsa_fg_profile_finish_us =
			dsa_profile_delta_us(service_phase_start_us,
					     dsa_profile_wall_now_us());
	/* The sidecar writer has closed its idx/dat fds and all pagemap records for
	 * this transfer have been emitted.  The service is now allowed to update
	 * its staged parent; CDP will still withhold TERMINAL_READY until it has
	 * renamed the manifest and committed the generation. */
	if (!ret && xfer->dsa_fg_service) {
		if (dsa_aligned_full_enabled())
			ret = dsa_memory_service_full_apply(xfer);
		else
			ret = dsa_memory_service_apply(xfer);
	}
	if (profile_ctx && profile_ctx->profile)
		profile_ctx->profile_finish_us += dsa_profile_delta_us(phase_start_us,
								      dsa_profile_wall_now_us());
	goto out;

out:
	dsa_memory_service_profile_emit(xfer, ret);
	hot_profile_emit(profile_ctx, ret);
	page_xfer_write_profile_emit(xfer, ret);
	return ret;
}

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, unsigned long img_id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	/* Image streaming lacks support for incremental images */
	if (opts.stream)
		return 0;

	if (open_parent(get_service_fd(IMG_FD_OFF), &pfd))
		return -1;
	if (pfd < 0)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, img_id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (__send(sk, &ret, sizeof(ret), 0) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, unsigned long img_id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm(fd_type, img_id);

	if (send_psi(page_server_sk, &pi))
		return -1;

	tcp_nodelay(page_server_sk, true);

	if (__recv(page_server_sk, &has_parent, sizeof(int), 0) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, unsigned long img_id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, img_id);
	else
		return check_parent_local_xfer(fd_type, img_id);
}

struct page_xfer_job {
	u64 dst_id;
	int p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static struct pipe_read_dest pipe_read_dest = {
	.sink_fd = -1,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
	if (pipe_read_dest.sink_fd != -1) {
		close(pipe_read_dest.sink_fd);
		close(pipe_read_dest.p[0]);
		close(pipe_read_dest.p[1]);
	}
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	unsigned long id;

	type = decode_pm(pi->dst_id, &id);
	if (type == -1) {
		pr_err("Unknown pagemap type received\n");
		return -1;
	}

	pr_info("Opening %d/%lu\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;
		if (__send(sk, &has_parent, 1, 0) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %" PRIx64 " - %" PRIx64 "\n",
		 pi->vaddr, pi->vaddr + pi->nr_pages * PAGE_SIZE);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		/*
		 * Splicing into a pipe may end up blocking if pipe is "full",
		 * and we need the SPLICE_F_NONBLOCK flag here. At the same time
		 * splicing from UNIX socket with this flag aborts splice with
		 * the EAGAIN if there's no data in it (TCP looks at the socket
		 * O_NONBLOCK flag _only_ and waits for data), so before doing
		 * the non-blocking splice we need to explicitly wait.
		 */

		if (sk_wait_data(sk) < 0) {
			pr_perror("Can't poll socket");
			return -1;
		}

		if (opts.tls) {
			if (tls_recv_data_to_fd(cxfer.p[1], chunk)) {
				pr_err("Can't read from socket\n");
				return -1;
			}
		} else {
			chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

			if (chunk < 0) {
				pr_perror("Can't read from socket");
				return -1;
			}
			if (chunk == 0) {
				pr_err("A socket was closed unexpectedly\n");
				return -1;
			}
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	unsigned long len, nr_pages;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	/* page_pipe_read() uses 'unsigned long *' but pi->nr_pages is u64.
	 * Use a temporary variable to fix the incompatible pointer type
	 * on 32-bit platforms (e.g. armv7). */
	nr_pages = pi->nr_pages;
	ret = page_pipe_read(pp, &pipe_read_dest, pi->vaddr, &nr_pages, PPB_LAZY);
	if (ret)
		return ret;

	/*
	 * The pi is reused for send_psi here, so .nr_pages, .vaddr and
	 * .dst_id all remain intact.
	 */

	pi->nr_pages = nr_pages;
	if (pi->nr_pages == 0) {
		pr_debug("no iovs found, zero pages\n");
		return -1;
	}

	pi->cmd = encode_ps_cmd(PS_IOV_ADD_F, PE_PRESENT);
	if (send_psi(sk, pi))
		return -1;

	len = pi->nr_pages * PAGE_SIZE;

	if (opts.tls) {
		if (tls_send_data_from_fd(pipe_read_dest.p[0], len))
			return -1;
	} else {
		ret = splice(pipe_read_dest.p[0], NULL, sk, NULL, len, SPLICE_F_MOVE);
		if (ret != len)
			return -1;
	}

	tcp_nodelay(sk, true);

	return 0;
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;
	bool receiving_pages = !opts.lazy_pages;

	if (receiving_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		pipe_read_dest_init(&pipe_read_dest);
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = __recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD_F:
		case PS_IOV_ADD:
		case PS_IOV_HOLE: {
			u32 flags;

			if (likely(cmd == PS_IOV_ADD_F))
				flags = decode_ps_flags(pi.cmd);
			else if (cmd == PS_IOV_ADD)
				flags = PE_PRESENT;
			else /* PS_IOV_HOLE */
				flags = PE_PARENT;

			ret = page_server_add(sk, &pi, flags);
			break;
		}
		case PS_IOV_CLOSE:
		case PS_IOV_FORCE_CLOSE: {
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (__send(sk, &status, sizeof(status), 0) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret)
			break;
		if (pi.cmd == PS_IOV_CLOSE || pi.cmd == PS_IOV_FORCE_CLOSE)
			break;
	}

	if (receiving_pages && !ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	tls_terminate_session(ret != 0);

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */
		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	page_server_close();

	pr_info("Session over\n");

	close(sk);
	return ret;
}

static int fill_page_pipe(struct page_read *pr, struct page_pipe *pp)
{
	struct page_pipe_buf *ppb;
	int i, ret;

	pr->reset(pr);

	while (pr->advance(pr)) {
		unsigned long vaddr = pr->pe->vaddr;

		for (i = 0; i < pr->pe->nr_pages; i++, vaddr += PAGE_SIZE) {
			if (pagemap_in_parent(pr->pe))
				ret = page_pipe_add_hole(pp, vaddr, PP_HOLE_PARENT);
			else
				ret = page_pipe_add_page(pp, vaddr, pagemap_lazy(pr->pe) ? PPB_LAZY : 0);
			if (ret) {
				pr_err("Failed adding page at %lx\n", vaddr);
				return -1;
			}
		}
	}

	list_for_each_entry(ppb, &pp->bufs, l) {
		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = ppb->iov[i];

			if (splice(img_raw_fd(pr->pi), NULL, ppb->p[1], NULL, iov.iov_len, SPLICE_F_MOVE) !=
			    iov.iov_len) {
				pr_perror("Splice failed");
				return -1;
			}
		}
	}

	debug_show_page_pipe(pp);

	return 0;
}

static int page_pipe_from_pagemap(struct page_pipe **pp, int pid)
{
	struct page_read pr;
	unsigned long nr_pages = 0;
	int ret = -1;

	if (open_page_read(pid, &pr, PR_TASK) <= 0) {
		pr_err("Failed to open page read for %d\n", pid);
		return -1;
	}

	while (pr.advance(&pr))
		if (pagemap_present(pr.pe))
			nr_pages += pr.pe->nr_pages;

	*pp = create_page_pipe(nr_pages, NULL, 0);
	if (!*pp) {
		pr_err("Cannot create page pipe for %d\n", pid);
		goto err;
	}

	if (fill_page_pipe(&pr, *pp))
		goto err_pp;

	ret = 0;
err:
	pr.close(&pr);
	return ret;
err_pp:
	destroy_page_pipe(*pp);
	*pp = NULL;
	goto err;
}

static int page_server_init_send(void)
{
	struct pstree_item *pi;
	struct page_pipe *pp;

	BUILD_BUG_ON(sizeof(struct dmp_info) > sizeof(struct rst_info));

	if (prepare_dummy_pstree())
		return -1;

	for_each_pstree_item(pi) {
		if (prepare_dummy_task_state(pi))
			return -1;

		if (!task_alive(pi))
			continue;

		if (page_pipe_from_pagemap(&pp, vpid(pi))) {
			pr_err("%d: failed to open page-read\n", vpid(pi));
			return -1;
		}

		/*
		 * prepare_dummy_pstree presumes 'restore' behaviour,
		 * but page_server_get_pages uses dmpi() to get access
		 * to the page-pipe, so we are faking it here.
		 */
		memset(rsti(pi), 0, sizeof(struct rst_info));
		dmpi(pi)->mem_pp = pp;
	}

	return 0;
}

int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

	if (init_stats(DUMP_STATS))
		return -1;

	if (!opts.lazy_pages)
		up_page_ids_base();
	else if (!lazy_dump)
		if (page_server_init_send())
			return -1;

	if (opts.ps_socket != -1) {
		ask = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page", opts.addr, &opts.port);
	if (sk == -1)
		return -1;
no_server:

	if (!daemon_mode && cfd >= 0) {
		struct ps_info info = { .pid = getpid(), .port = opts.port };
		int count;

		count = write(cfd, &info, sizeof(info));
		close_safe(&cfd);
		if (count != sizeof(info)) {
			pr_perror("Unable to write ps_info");
			exit(1);
		}
	}

	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret > 0 ? 0 : -1;

	if (tls_x509_init(ask, true)) {
		close_safe(&sk);
		return -1;
	}

	if (ask >= 0)
		ret = page_server_serve(ask);

	if (daemon_mode)
		exit(ret);

	return ret;
}

static int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Reusing ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;

	if (tls_x509_init(page_server_sk, false)) {
		close(page_server_sk);
		return -1;
	}
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

int connect_to_page_server_to_send(void)
{
	return connect_to_page_server();
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = {};
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server\n");

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FORCE_CLOSE;
	else
		pi.cmd = PS_IOV_CLOSE;

	if (send_psi(page_server_sk, &pi))
		goto out;

	if (__recv(page_server_sk, &status, sizeof(status), 0) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	tls_terminate_session(ret != 0);
	close_safe(&page_server_sk);

	return ret ?: status;
}

struct ps_async_read {
	unsigned long rb; /* read bytes */
	unsigned long goal;
	unsigned long nr_pages;

	struct page_server_iov pi;
	void *pages;

	ps_async_read_complete complete;
	void *priv;

	struct list_head l;
};

static LIST_HEAD(async_reads);

static inline void async_read_set_goal(struct ps_async_read *ar, unsigned long nr_pages)
{
	ar->goal = sizeof(ar->pi) + nr_pages * PAGE_SIZE;
	ar->nr_pages = nr_pages;
}

static void init_ps_async_read(struct ps_async_read *ar, void *buf, unsigned long nr_pages, ps_async_read_complete complete,
			       void *priv)
{
	ar->pages = buf;
	ar->rb = 0;
	ar->complete = complete;
	ar->priv = priv;
	async_read_set_goal(ar, nr_pages);
}

static int page_server_start_async_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read *ar;

	ar = xmalloc(sizeof(*ar));
	if (ar == NULL)
		return -1;

	init_ps_async_read(ar, buf, nr_pages, complete, priv);
	list_add_tail(&ar->l, &async_reads);
	return 0;
}

/*
 * There are two possible event types we need to handle:
 * - page info is available as a reply to request_remote_page
 * - page data is available, and it follows page info we've just received
 * Since the on dump side communications are completely synchronous,
 * we can return to epoll right after the reception of page info and
 * for sure the next time socket event will occur we'll get page data
 * related to info we've just received
 */
static int page_server_read(struct ps_async_read *ar, int flags)
{
	int ret, need;
	void *buf;

	if (ar->rb < sizeof(ar->pi)) {
		/* Header */
		buf = ((void *)&ar->pi) + ar->rb;
		need = sizeof(ar->pi) - ar->rb;
	} else {
		/* page-serer may return less pages than we asked for */
		if (ar->pi.nr_pages < ar->nr_pages)
			async_read_set_goal(ar, ar->pi.nr_pages);
		/* Page(s) data itself */
		buf = ar->pages + (ar->rb - sizeof(ar->pi));
		need = ar->goal - ar->rb;
	}

	ret = __recv(page_server_sk, buf, need, flags);
	if (ret < 0) {
		if (flags == MSG_DONTWAIT && (errno == EAGAIN || errno == EINTR)) {
			ret = 0;
		} else {
			pr_perror("Error reading data from page server");
			return -1;
		}
	}

	ar->rb += ret;
	if (ar->rb < ar->goal)
		return 1;

	/*
	 * IO complete -- notify the caller and drop the request
	 */
	BUG_ON(ar->rb > ar->goal);
	return ar->complete((int)ar->pi.dst_id, (unsigned long)ar->pi.vaddr, (int)ar->pi.nr_pages, ar->priv);
}

static int page_server_async_read(struct epoll_rfd *f)
{
	struct ps_async_read *ar;
	int ret;

	BUG_ON(list_empty(&async_reads));
	ar = list_first_entry(&async_reads, struct ps_async_read, l);
	ret = page_server_read(ar, MSG_DONTWAIT);

	if (ret > 0)
		return 0;
	if (!ret) {
		list_del(&ar->l);
		xfree(ar);
	}

	return ret;
}

static int page_server_hangup_event(struct epoll_rfd *rfd)
{
	pr_err("Remote side closed connection\n");
	return -1;
}

static struct epoll_rfd ps_rfd;

int connect_to_page_server_to_recv(int epfd)
{
	if (connect_to_page_server())
		return -1;

	ps_rfd.fd = page_server_sk;
	ps_rfd.read_event = page_server_async_read;
	ps_rfd.hangup_event = page_server_hangup_event;

	return epoll_add_rfd(epfd, &ps_rfd);
}

int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages)
{
	struct page_server_iov pi = {
		.cmd = PS_IOV_GET,
		.nr_pages = nr_pages,
		.vaddr = addr,
		.dst_id = img_id,
	};

	/* XXX: why MSG_DONTWAIT here? */
	if (send_psi_flags(page_server_sk, &pi, MSG_DONTWAIT))
		return -1;

	tcp_nodelay(page_server_sk, true);
	return 0;
}

static int page_server_start_sync_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv)
{
	struct ps_async_read ar;
	int ret = 1;

	init_ps_async_read(&ar, buf, nr, complete, priv);
	while (ret == 1)
		ret = page_server_read(&ar, MSG_WAITALL);
	return ret;
}

int page_server_start_read(void *buf, unsigned long nr, ps_async_read_complete complete, void *priv, unsigned flags)
{
	if (flags & PR_ASYNC)
		return page_server_start_async_read(buf, nr, complete, priv);
	else
		return page_server_start_sync_read(buf, nr, complete, priv);
}

/* ------------------------------------------------------------------------- */
/* Task-scoped DSA memory service                                             */

static int dsa_ms_send(int fd, struct cdp_dsa_memory_service_msg *msg)
{
	ssize_t ret;

	msg->magic = CDP_DSA_MEMORY_SERVICE_MAGIC;
	msg->version = CDP_DSA_MEMORY_SERVICE_VERSION;
	ret = send(fd, msg, sizeof(*msg), MSG_NOSIGNAL);
	if (ret != sizeof(*msg)) {
		if (ret >= 0)
			errno = EPROTO;
		return -1;
	}
	return 0;
}

static void dsa_ms_diag_init(struct cdp_dsa_memory_service_diag *diag,
			     const struct cdp_dsa_memory_service_msg *req)
{
	memset(diag, 0, sizeof(*diag));
	diag->magic = CDP_DSA_MEMORY_SERVICE_DIAG_MAGIC;
	diag->version = CDP_DSA_MEMORY_SERVICE_DIAG_VERSION;
	diag->size = sizeof(*diag);
	diag->request_op = req->op;
	diag->generation_id = req->generation_id;
	diag->arena_epoch = req->arena_epoch;
	diag->object_index = CDP_DSA_MS_DIAG_INVALID_OBJECT;
	diag->object_vaddr = CDP_DSA_MS_DIAG_INVALID_OBJECT;
	diag->expected_results = req->result_count;
}

static int dsa_ms_send_generation(
	int fd, struct cdp_dsa_memory_service_msg *msg, bool profile,
	struct cdp_dsa_memory_service_diag *diag)
{
	struct iovec iov[2];
	struct msghdr hdr = {};
	ssize_t ret;
	size_t total;

	if (!profile)
		return dsa_ms_send(fd, msg);
	if (!diag) {
		errno = EINVAL;
		return -1;
	}
	msg->magic = CDP_DSA_MEMORY_SERVICE_MAGIC;
	msg->version = CDP_DSA_MEMORY_SERVICE_VERSION;
	diag->reply_op = msg->op;
	diag->service_status = msg->status;
	iov[0] = (struct iovec) { .iov_base = msg, .iov_len = sizeof(*msg) };
	iov[1] = (struct iovec) { .iov_base = diag, .iov_len = sizeof(*diag) };
	hdr.msg_iov = iov;
	hdr.msg_iovlen = ARRAY_SIZE(iov);
	total = sizeof(*msg) + sizeof(*diag);
	ret = sendmsg(fd, &hdr, MSG_NOSIGNAL);
	if (ret != (ssize_t)total) {
		if (ret >= 0)
			errno = EPROTO;
		return -1;
	}
	return 0;
}

static int dsa_ms_recv(int fd, struct cdp_dsa_memory_service_msg *msg)
{
	ssize_t ret;

	ret = recv(fd, msg, sizeof(*msg), 0);
	if (!ret)
		return 1; /* clean peer EOF while IDLE */
	if (ret != sizeof(*msg)) {
		if (ret >= 0)
			errno = EPROTO;
		return -1;
	}
	if (msg->magic != CDP_DSA_MEMORY_SERVICE_MAGIC ||
	    msg->version != CDP_DSA_MEMORY_SERVICE_VERSION)
		return -1;
	return 0;
}

/* SESSION_PREPARE travels over the worker-owned control socket and carries
 * the service end of a fresh per-generation SOCK_SEQPACKET socket.  Keeping
 * that fd out of the fixed wire record gives the service a precise EOF when
 * CRIU dies, while the worker can still send READY only after its durable
 * generation commit. */
static int dsa_ms_recv_generation_fd(int fd,
				     struct cdp_dsa_memory_service_msg *msg,
				     int *generation_fd)
{
	char control[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = msg, .iov_len = sizeof(*msg) };
	struct msghdr hdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	ssize_t ret;

	*generation_fd = -1;
	ret = recvmsg(fd, &hdr, 0);
	if (!ret)
		return 1;
	if (ret != sizeof(*msg) || (hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
		if (ret >= 0)
			errno = EPROTO;
		return -1;
	}
	if (msg->magic != CDP_DSA_MEMORY_SERVICE_MAGIC ||
	    msg->version != CDP_DSA_MEMORY_SERVICE_VERSION ||
	    msg->op != CDP_DSA_MS_SESSION_PREPARE) {
		errno = EPROTO;
		return -1;
	}
	cmsg = CMSG_FIRSTHDR(&hdr);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
		errno = EPROTO;
		return -1;
	}
	memcpy(generation_fd, CMSG_DATA(cmsg), sizeof(*generation_fd));
	if (*generation_fd < 0) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static bool dsa_ms_range_valid(u32 off, u32 head, size_t arena_size)
{
	return head >= off && (u64)head <= (u64)arena_size;
}

static int dsa_ms_reply_error(int fd, const struct cdp_dsa_memory_service_msg *req,
				      u32 status)
{
	struct cdp_dsa_memory_service_msg reply = *req;

	reply.op = CDP_DSA_MS_ERROR;
	reply.status = status;
	return dsa_ms_send(fd, &reply);
}

static int dsa_ms_reply_generation_error(
	int fd, const struct cdp_dsa_memory_service_msg *req, u32 status,
	bool profile, u32 stage, int primary_errno,
	struct cdp_dsa_memory_service_diag *diag)
{
	struct cdp_dsa_memory_service_msg reply = *req;
	struct cdp_dsa_memory_service_diag local_diag;

	if (!profile)
		return dsa_ms_reply_error(fd, req, status);
	if (!diag) {
		dsa_ms_diag_init(&local_diag, req);
		diag = &local_diag;
	}
	if (diag->failure_stage == CDP_DSA_MS_STAGE_NONE)
		diag->failure_stage = stage;
	if (!diag->primary_errno)
		diag->primary_errno = primary_errno ? primary_errno :
			dsa_ms_status_errno(status);
	reply.op = CDP_DSA_MS_ERROR;
	reply.status = status;
	return dsa_ms_send_generation(fd, &reply, profile, diag);
}

static int dsa_ms_reclaim_unreferenced_owners(
	struct hot_apply_ctx *ctx, struct hot_memstore_seg *next, size_t nr_next)
{
	bool *keep;
	size_t *remap;
	size_t i;
	size_t nr_kept = 0;

	if (!ctx || (!next && nr_next)) {
		errno = EINVAL;
		return -1;
	}
	keep = xzalloc(ctx->nr_owners * sizeof(*keep));
	remap = xmalloc(ctx->nr_owners * sizeof(*remap));
	if ((ctx->nr_owners && !keep) || (ctx->nr_owners && !remap)) {
		xfree(keep);
		xfree(remap);
		return -1;
	}
	for (i = 0; i < nr_next; i++) {
		if (next[i].owner >= ctx->nr_owners) {
			pr_err("DSA memory service staged view has invalid owner=%zu count=%zu\n",
			       next[i].owner, ctx->nr_owners);
			xfree(keep);
			xfree(remap);
			errno = ERANGE;
			return -1;
		}
		keep[next[i].owner] = true;
	}

	/*
	 * No operation below can invalidate a retained view.  Allocate and
	 * validate the complete remap first, then release only owners absent from
	 * the next committed view.
	 */
	for (i = 0; i < ctx->nr_owners; i++) {
		struct hot_memstore_owner *owner = &ctx->owners[i];

		if (keep[i]) {
			remap[i] = nr_kept;
			if (nr_kept != i)
				ctx->owners[nr_kept] = *owner;
			nr_kept++;
			continue;
		}
		if (owner->map && owner->map != MAP_FAILED)
			munmap(owner->map, owner->map_size);
		if (owner->fd >= 0)
			close(owner->fd);
		if (owner->created && owner->file[0] &&
		    unlink(owner->file) && errno != ENOENT)
			pr_warn("DSA memory service cannot unlink obsolete backing %s: %s\n",
				owner->file, strerror(errno));
	}
	for (i = 0; i < nr_next; i++)
		next[i].owner = remap[next[i].owner];
	ctx->nr_owners = nr_kept;
	xfree(keep);
	xfree(remap);
	return 0;
}

/* The service never gives owners to a VMA view.  At READY we turn the staged
 * views into the next committed parent index while retaining the same owner
 * FDs and MAP_SHARED mappings.  This is the point that preserves PTEs across
 * generations; rebuilding from the manifest here would defeat P27. */
static int dsa_ms_promote_staged_views(struct hot_apply_ctx *ctx)
{
	struct hot_memstore_seg *next;
	size_t i;

	if (!ctx || !ctx->nr_vma_segments)
		return -1;
	next = xmalloc(ctx->nr_vma_segments * sizeof(*next));
	if (!next)
		return -1;
	for (i = 0; i < ctx->nr_vma_segments; i++) {
		const struct hot_vma_segment *view = &ctx->vma_segments[i];

		next[i] = (struct hot_memstore_seg) {
			.img_id = ctx->img_id,
			.vaddr = view->start,
			.len = view->end - view->start,
			.off = view->off,
			.owner = view->owner,
		};
	}
	if (dsa_ms_reclaim_unreferenced_owners(ctx, next,
					      ctx->nr_vma_segments)) {
		xfree(next);
		return -1;
	}
	xfree(ctx->old_memstore);
	ctx->old_memstore = next;
	ctx->nr_old_memstore = ctx->nr_vma_segments;
	ctx->old_memstore_cursor = 0;
	ctx->nr_vma_segments = 0;
	ctx->vmas_materialized = false;
	ctx->nr_vma_plans = 0;
	return 0;
}

static int dsa_ms_prepare_ctx(struct hot_apply_ctx **ctxp,
			      const struct cdp_dsa_memory_service_msg *req)
{
	struct hot_apply_ctx *ctx = *ctxp;
	size_t i;

	if (ctx) {
		/* A task owns exactly one root pagemap image.  Treat a changing image
		 * id as an identity violation instead of silently aliasing mappings. */
		return ctx->img_id == req->img_id ? 0 : -1;
	}
	ctx = hot_apply_alloc_ctx(CR_FD_PAGEMAP, req->img_id, 0);
	if (!ctx || !ctx->memstore || !ctx->fine_grained)
		goto err;
	if (hot_memstore_load(ctx, ctx->memory_manifest_path, &ctx->old_memstore,
			       &ctx->nr_old_memstore))
		goto err;
	ctx->parent_view_loaded = true;
	for (i = 0; i < ctx->nr_old_memstore; i++) {
		if (hot_memstore_old_map(ctx, &ctx->old_memstore[i]) == MAP_FAILED)
			goto err;
	}
	if (ctx->fine_output &&
	    (ctx->fg_compare_backend == HOT_FG_COMPARE_DSA ||
	     ctx->fg_compare_backend == HOT_FG_COMPARE_VALIDATE) &&
	    hot_dsa_open(ctx))
		goto err;
	/* The service stages only hot-memory.<generation>.next.  CDP alone owns
	 * latest.json and the durable READY commit, so generic CRIU cleanup must
	 * never overwrite that committed manifest with a local "failed" marker. */
	ctx->finished = true;
	ctx->pre_freeze_ready = true;
	*ctxp = ctx;
	return 0;
err:
	if (ctx) {
		struct page_xfer xfer = { .hot_apply = ctx };

		hot_apply_abort(&xfer);
	}
	return -1;
}

static int dsa_ms_open_next_manifest(struct hot_apply_ctx *ctx, u64 generation)
{
	char path[PATH_MAX];
	int fd;

	if (!ctx || !ctx->hot_root || !ctx->hot_root[0] ||
	    snprintf(path, sizeof(path), "%s/hot-memory.%" PRIu64 ".next",
		     ctx->hot_root, generation) >= (int)sizeof(path))
		return -1;
	if (hot_apply_mkdir_root(ctx->hot_root))
		return -1;
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, CR_FD_PERM);
	if (fd < 0)
		return -1;
	ctx->manifest_fd = fd;
	return 0;
}

static u64 dsa_ms_profile_phase_finish(bool profile, u64 start_us)
{
	if (!profile)
		return 0;
	return dsa_profile_delta_us(start_us, dsa_profile_wall_now_us());
}

static int dsa_ms_apply_generation_fast(
	struct hot_apply_ctx *ctx, const unsigned char *shared,
	bool already_applied, const struct cdp_dsa_memory_service_msg *req,
	struct cdp_dsa_memory_service_msg *reply)
{
	struct page_xfer xfer = {};

	*reply = *req;
	if (already_applied || req->result_head < req->result_off ||
	    req->result_head > req->result_limit ||
	    dsa_ms_open_next_manifest(ctx, req->generation_id)) {
		reply->op = CDP_DSA_MS_ERROR;
		reply->status = CDP_DSA_MS_ESTATE;
		return -1;
	}
	xfer.hot_apply = ctx;
	xfer.dsa_fg_shared = shared;
	xfer.dsa_fg_raw_capture = true;
	xfer.dsa_fg_desc_area_off = req->desc_off;
	xfer.dsa_fg_desc_head = req->desc_head;
	xfer.dsa_fg_raw_payload_base = req->raw_off;
	xfer.dsa_fg_raw_payload_head = req->raw_head;
	xfer.dsa_fg_result_meta_base = req->result_off;
	xfer.dsa_fg_result_meta_head = req->result_head;
	xfer.dsa_fg_result_meta_limit = req->result_limit;
	if (hot_fg_apply_published_results(&xfer, ctx, shared) ||
	    hot_memstore_finish(ctx) || close(ctx->manifest_fd)) {
		ctx->manifest_fd = -1;
		reply->op = CDP_DSA_MS_ERROR;
		reply->status = CDP_DSA_MS_EIO;
		return -1;
	}
	ctx->manifest_fd = -1;
	reply->op = CDP_DSA_MS_APPLY_DONE;
	reply->status = CDP_DSA_MS_OK;
	return 0;
}

static int dsa_ms_apply_generation(
	struct hot_apply_ctx *ctx, const unsigned char *shared, size_t arena_size,
	bool already_applied, const struct cdp_dsa_memory_service_msg *req,
	struct cdp_dsa_memory_service_msg *reply,
	struct cdp_dsa_memory_service_diag *diag)
{
	struct page_xfer xfer = {};
	struct hot_fg_raw_page *pages = NULL;
	size_t nr_pages = 0;
	size_t failure_index = SIZE_MAX;
	unsigned long failure_vaddr = ULONG_MAX;
	const bool profile = ctx->profile;
	u64 total_wall_start_us = 0;
	u64 total_cpu_start_us = 0;
	u64 phase_start_us = 0;
	u64 result_bytes;
	u32 failure_stage = CDP_DSA_MS_STAGE_NONE;
	u32 failure_status = CDP_DSA_MS_EIO;
	int primary_errno = 0;
	int cleanup_errno = 0;
	size_t i;

	dsa_ms_diag_init(diag, req);
	*reply = *req;
	if (profile) {
		total_wall_start_us = dsa_profile_wall_now_us();
		total_cpu_start_us = dsa_profile_thread_now_us();
	}

	failure_stage = CDP_DSA_MS_STAGE_APPLY_PRECHECK;
	failure_status = CDP_DSA_MS_ESTATE;
	if (already_applied) {
		primary_errno = EALREADY;
		goto error;
	}
	if (!dsa_ms_range_valid(req->desc_off, req->desc_head, arena_size) ||
	    !dsa_ms_range_valid(req->raw_off, req->raw_head, arena_size) ||
	    !dsa_ms_range_valid(req->result_off, req->result_head, arena_size) ||
	    req->result_head > req->result_limit ||
	    !dsa_ms_range_valid(req->result_off, req->result_limit, arena_size)) {
		failure_status = CDP_DSA_MS_EBOUNDS;
		primary_errno = ERANGE;
		goto error;
	}
	result_bytes = (u64)req->result_head - req->result_off;
	if (result_bytes % sizeof(struct parasite_dsa_fg_result) ||
	    req->result_count !=
		result_bytes / sizeof(struct parasite_dsa_fg_result)) {
		failure_status = CDP_DSA_MS_EBOUNDS;
		primary_errno = EBADMSG;
		goto error;
	}

	failure_status = CDP_DSA_MS_EIO;
	failure_stage = CDP_DSA_MS_STAGE_APPLY_OPEN_MANIFEST;
	errno = 0;
	if (dsa_ms_open_next_manifest(ctx, req->generation_id)) {
		primary_errno = errno ? errno : EIO;
		goto error;
	}

	xfer.hot_apply = ctx;
	xfer.dsa_fg_shared = shared;
	xfer.dsa_fg_raw_capture = true;
	xfer.dsa_fg_desc_area_off = req->desc_off;
	xfer.dsa_fg_desc_head = req->desc_head;
	xfer.dsa_fg_raw_payload_base = req->raw_off;
	xfer.dsa_fg_raw_payload_head = req->raw_head;
	xfer.dsa_fg_result_meta_base = req->result_off;
	xfer.dsa_fg_result_meta_head = req->result_head;
	xfer.dsa_fg_result_meta_limit = req->result_limit;

	failure_stage = CDP_DSA_MS_STAGE_APPLY_RESULT_VALIDATE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (hot_fg_pages_from_results(&xfer, ctx, shared, &pages, &nr_pages,
				       &failure_index, &failure_vaddr)) {
		diag->apply_validate_wall_us =
			dsa_ms_profile_phase_finish(profile, phase_start_us);
		primary_errno = errno ? errno : EBADMSG;
		diag->object_index = failure_index == SIZE_MAX ?
			CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_index;
		diag->object_vaddr = failure_vaddr == ULONG_MAX ?
			CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_vaddr;
		goto error;
	}
	diag->apply_validate_wall_us =
		dsa_ms_profile_phase_finish(profile, phase_start_us);
	if (nr_pages != req->result_count) {
		primary_errno = EBADMSG;
		diag->completed_results = nr_pages;
		goto error;
	}

	failure_stage = CDP_DSA_MS_STAGE_APPLY_VMA_MATERIALIZE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (hot_memstore_materialize_vmas(ctx, &failure_index, &failure_vaddr)) {
		diag->apply_materialize_wall_us =
			dsa_ms_profile_phase_finish(profile, phase_start_us);
		primary_errno = errno ? errno : EIO;
		diag->object_index = failure_index == SIZE_MAX ?
			CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_index;
		diag->object_vaddr = failure_vaddr == ULONG_MAX ?
			CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_vaddr;
		goto error;
	}
	diag->apply_materialize_wall_us =
		dsa_ms_profile_phase_finish(profile, phase_start_us);

	failure_stage = CDP_DSA_MS_STAGE_APPLY_PAGE_STORE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	for (i = 0; i < nr_pages; i++) {
		errno = 0;
		if (hot_fg_apply_raw_page(ctx, &pages[i])) {
			diag->apply_store_wall_us =
				dsa_ms_profile_phase_finish(profile, phase_start_us);
			primary_errno = errno ? errno : EIO;
			diag->object_index = i;
			diag->object_vaddr = pages[i].vaddr;
			diag->completed_results = i;
			goto error;
		}
	}
	diag->apply_store_wall_us =
		dsa_ms_profile_phase_finish(profile, phase_start_us);
	diag->completed_results = nr_pages;

	failure_stage = CDP_DSA_MS_STAGE_APPLY_MANIFEST_FINISH;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (hot_memstore_finish(ctx)) {
		diag->apply_manifest_finish_wall_us =
			dsa_ms_profile_phase_finish(profile, phase_start_us);
		primary_errno = errno ? errno : EIO;
		goto error;
	}
	diag->apply_manifest_finish_wall_us =
		dsa_ms_profile_phase_finish(profile, phase_start_us);

	failure_stage = CDP_DSA_MS_STAGE_APPLY_MANIFEST_CLOSE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (close(ctx->manifest_fd)) {
		diag->apply_manifest_close_wall_us =
			dsa_ms_profile_phase_finish(profile, phase_start_us);
		primary_errno = errno ? errno : EIO;
		ctx->manifest_fd = -1;
		goto error;
	}
	diag->apply_manifest_close_wall_us =
		dsa_ms_profile_phase_finish(profile, phase_start_us);
	ctx->manifest_fd = -1;
	diag->failure_stage = CDP_DSA_MS_STAGE_NONE;
	diag->apply_total_wall_us =
		dsa_ms_profile_phase_finish(profile, total_wall_start_us);
	if (profile)
		diag->apply_total_cpu_us =
			dsa_profile_delta_us(total_cpu_start_us,
					     dsa_profile_thread_now_us());
	reply->op = CDP_DSA_MS_APPLY_DONE;
	reply->status = CDP_DSA_MS_OK;
	reply->service_wall_us = diag->apply_total_wall_us;
	reply->service_cpu_us = diag->apply_total_cpu_us;
	reply->profile.hot_apply_us = diag->apply_total_wall_us;
	reply->profile.hot_apply_cpu_us = diag->apply_total_cpu_us;
	xfree(pages);
	return 0;

error:
	diag->failure_stage = failure_stage;
	diag->primary_errno = primary_errno ? primary_errno : EIO;
	if (ctx->manifest_fd >= 0) {
		if (close(ctx->manifest_fd))
			cleanup_errno = errno ? errno : EIO;
		ctx->manifest_fd = -1;
	}
	diag->cleanup_errno = cleanup_errno;
	diag->apply_total_wall_us =
		dsa_ms_profile_phase_finish(profile, total_wall_start_us);
	if (profile)
		diag->apply_total_cpu_us =
			dsa_profile_delta_us(total_cpu_start_us,
					     dsa_profile_thread_now_us());
	reply->op = CDP_DSA_MS_ERROR;
	reply->status = failure_status;
	reply->service_wall_us = diag->apply_total_wall_us;
	reply->service_cpu_us = diag->apply_total_cpu_us;
	reply->profile.hot_apply_us = diag->apply_total_wall_us;
	reply->profile.hot_apply_cpu_us = diag->apply_total_cpu_us;
	xfree(pages);
	return -1;
}

/* Full-control apply consumes the descriptor sequence directly.  Unlike fine
 * apply there is no result array: every captured page is authoritative, so
 * the service materialises the VMA plan and copies each raw descriptor into
 * the staged parent view in raw order. */
static int dsa_ms_full_apply_generation(
	struct hot_apply_ctx *ctx, const unsigned char *shared, size_t arena_size,
	bool already_applied, const struct cdp_dsa_memory_service_msg *req,
	struct cdp_dsa_memory_service_msg *reply,
	struct cdp_dsa_memory_service_diag *diag)
{
	u32 desc_off;
	u32 raw_off;
	size_t failure_index = SIZE_MAX;
	unsigned long failure_vaddr = ULONG_MAX;
	const bool profile = ctx->profile;
	u64 total_wall_start_us = 0;
	u64 total_cpu_start_us = 0;
	u64 phase_start_us = 0;
	u32 failure_stage = CDP_DSA_MS_STAGE_APPLY_PRECHECK;
	u32 failure_status = CDP_DSA_MS_ESTATE;
	int primary_errno = 0;
	int cleanup_errno = 0;
	size_t index = 0;

	dsa_ms_diag_init(diag, req);
	*reply = *req;
	/* Full output has no compare request, so its generation-local service
	 * counters must be reset here rather than in the compare dispatcher. */
	hot_service_profile_reset_generation(ctx);
	if (profile) {
		total_wall_start_us = dsa_profile_wall_now_us();
		total_cpu_start_us = dsa_profile_thread_now_us();
	}
	if (already_applied) {
		primary_errno = EALREADY;
		goto error;
	}
	if (!dsa_ms_range_valid(req->desc_off, req->desc_head, arena_size) ||
	    !dsa_ms_range_valid(req->raw_off, req->raw_head, arena_size) ||
	    !dsa_ms_range_valid(req->vma_plan_off, req->vma_plan_head, arena_size) ||
	    (req->desc_head - req->desc_off) % sizeof(struct dsa_dump_descriptor) ||
	    !req->vma_plan_count) {
		failure_status = CDP_DSA_MS_EBOUNDS;
		primary_errno = ERANGE;
		goto error;
	}

	failure_stage = CDP_DSA_MS_STAGE_COMPARE_VMA_PLAN;
	failure_status = CDP_DSA_MS_EIO;
	errno = 0;
	if (hot_fg_load_vma_plan(ctx, shared, req->vma_plan_off,
				 req->vma_plan_head, req->vma_plan_count)) {
		primary_errno = errno ? errno : EBADMSG;
		goto error;
	}
	failure_stage = CDP_DSA_MS_STAGE_APPLY_OPEN_MANIFEST;
	errno = 0;
	if (dsa_ms_open_next_manifest(ctx, req->generation_id)) {
		primary_errno = errno ? errno : EIO;
		goto error;
	}
	failure_stage = CDP_DSA_MS_STAGE_APPLY_VMA_MATERIALIZE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (hot_memstore_materialize_vmas(ctx, &failure_index, &failure_vaddr)) {
		primary_errno = errno ? errno : EIO;
		goto error;
	}
	if (profile)
		diag->apply_materialize_wall_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	failure_stage = CDP_DSA_MS_STAGE_APPLY_PAGE_STORE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	raw_off = req->raw_off;
	for (desc_off = req->desc_off; desc_off < req->desc_head;
	     desc_off += sizeof(struct dsa_dump_descriptor), index++) {
		const struct dsa_dump_descriptor *desc =
			(const struct dsa_dump_descriptor *)(shared + desc_off);

		if (!desc->copy_len || desc->copy_len % PAGE_SIZE ||
		    desc->src_addr & (PAGE_SIZE - 1) || raw_off > req->raw_head ||
		    desc->copy_len > req->raw_head - raw_off) {
			failure_status = CDP_DSA_MS_EBOUNDS;
			primary_errno = EBADMSG;
			failure_index = index;
			failure_vaddr = desc->src_addr;
			goto error;
		}
		if (hot_memstore_write_to_segments(ctx, shared + raw_off,
					 (unsigned long)desc->src_addr,
					 desc->copy_len)) {
			primary_errno = errno ? errno : EIO;
			failure_index = index;
			failure_vaddr = desc->src_addr;
			goto error;
		}
		raw_off += desc->copy_len;
		diag->completed_results += desc->copy_len / PAGE_SIZE;
	}
	if (raw_off != req->raw_head) {
		failure_status = CDP_DSA_MS_EBOUNDS;
		primary_errno = EBADMSG;
		goto error;
	}
	if (profile)
		diag->apply_store_wall_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	failure_stage = CDP_DSA_MS_STAGE_APPLY_MANIFEST_FINISH;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	errno = 0;
	if (hot_memstore_finish(ctx)) {
		primary_errno = errno ? errno : EIO;
		goto error;
	}
	if (profile)
		diag->apply_manifest_finish_wall_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());

	failure_stage = CDP_DSA_MS_STAGE_APPLY_MANIFEST_CLOSE;
	if (profile)
		phase_start_us = dsa_profile_wall_now_us();
	if (close(ctx->manifest_fd)) {
		primary_errno = errno ? errno : EIO;
		ctx->manifest_fd = -1;
		goto error;
	}
	ctx->manifest_fd = -1;
	if (profile)
		diag->apply_manifest_close_wall_us =
			dsa_profile_delta_us(phase_start_us, dsa_profile_wall_now_us());
	diag->failure_stage = CDP_DSA_MS_STAGE_NONE;
	if (profile) {
		diag->apply_total_wall_us =
			dsa_profile_delta_us(total_wall_start_us, dsa_profile_wall_now_us());
		diag->apply_total_cpu_us =
			dsa_profile_delta_us(total_cpu_start_us, dsa_profile_thread_now_us());
	}
	reply->op = CDP_DSA_MS_FULL_APPLY_DONE;
	reply->status = CDP_DSA_MS_OK;
	hot_service_profile_snapshot(ctx, &reply->profile);
	reply->service_wall_us = diag->apply_total_wall_us;
	reply->service_cpu_us = diag->apply_total_cpu_us;
	reply->profile.hot_apply_us = diag->apply_total_wall_us;
	reply->profile.hot_apply_cpu_us = diag->apply_total_cpu_us;
	return 0;

error:
	diag->failure_stage = failure_stage;
	diag->primary_errno = primary_errno ? primary_errno : EIO;
	diag->object_index = failure_index == SIZE_MAX ?
		CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_index;
	diag->object_vaddr = failure_vaddr == ULONG_MAX ?
		CDP_DSA_MS_DIAG_INVALID_OBJECT : failure_vaddr;
	if (ctx->manifest_fd >= 0) {
		if (close(ctx->manifest_fd))
			cleanup_errno = errno ? errno : EIO;
		ctx->manifest_fd = -1;
	}
	diag->cleanup_errno = cleanup_errno;
	if (profile) {
		diag->apply_total_wall_us =
			dsa_profile_delta_us(total_wall_start_us, dsa_profile_wall_now_us());
		diag->apply_total_cpu_us =
			dsa_profile_delta_us(total_cpu_start_us, dsa_profile_thread_now_us());
	}
	reply->op = CDP_DSA_MS_ERROR;
	reply->status = failure_status;
	reply->service_wall_us = diag->apply_total_wall_us;
	reply->service_cpu_us = diag->apply_total_cpu_us;
	return -1;
}

/* This function is called by the dedicated `criu dsa-memory-service` command
 * after the task worker has supplied one end of a SOCK_SEQPACKET pair.  The
 * client wiring is intentionally kept outside this file: CRIU dump owns the
 * two durable writer barriers, while this loop owns persistent WQ/PASID and
 * hot mappings only. */
int page_xfer_dsa_memory_service(int control_fd)
{
	const char *fd_value = getenv("CRIU_DSA_ARENA_FD");
	const char *size_value = getenv("CRIU_DSA_ARENA_SIZE");
	char *end = NULL;
	unsigned long long parsed_fd;
	unsigned long long parsed_size;
	unsigned char *shared = MAP_FAILED;
	struct hot_apply_ctx *ctx = NULL;
	struct cdp_dsa_memory_service_msg active = {};
	bool have_session = false;
	bool applied = false;
	bool raw_sealed = false;
	int ret = -1;

	if (control_fd < 0 || !fd_value || !size_value) {
		pr_err("DSA memory service has no control or arena environment\n");
		return -1;
	}
	errno = 0;
	parsed_fd = strtoull(fd_value, &end, 10);
	if (errno || !end || *end || parsed_fd > INT_MAX)
		return -1;
	errno = 0;
	parsed_size = strtoull(size_value, &end, 10);
	if (errno || !end || *end || !parsed_size || parsed_size > SIZE_MAX)
		return -1;
	shared = mmap(NULL, (size_t)parsed_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, (int)parsed_fd, 0);
	if (shared == MAP_FAILED) {
		pr_perror("DSA memory service can't map raw arena");
		return -1;
	}

	for (;;) {
		struct cdp_dsa_memory_service_msg req;
		struct cdp_dsa_memory_service_msg reply;
		int generation_fd = -1;
		int generation_ret = 0;
		int rc = dsa_ms_recv_generation_fd(control_fd, &req, &generation_fd);

		if (rc == 1) {
			ret = have_session ? -1 : 0;
			break;
		}
		if (rc < 0) {
			pr_err("DSA memory service received malformed control message\n");
			break;
		}
		if (have_session || dsa_ms_prepare_ctx(&ctx, &req)) {
			if (generation_fd >= 0)
				close(generation_fd);
			(void)dsa_ms_reply_error(control_fd, &req, CDP_DSA_MS_EIDENTITY);
			break;
		}
		active = req;
		have_session = true;
		applied = false;
		raw_sealed = false;
		reply = req;
		reply.op = CDP_DSA_MS_PREPARED;
		reply.status = CDP_DSA_MS_OK;
		if (dsa_ms_send(control_fd, &reply)) {
			close(generation_fd);
			break;
		}

		/* CRIU owns this endpoint only during one dump.  It can issue compare
		 * and apply requests, but never READY: that is deliberately retained
		 * by the worker on the long-lived control channel. */
		for (;;) {
			struct page_xfer xfer = {};
			struct cdp_dsa_memory_service_diag diag;

			rc = dsa_ms_recv(generation_fd, &req);
			if (rc == 1)
				break;
			if (rc < 0) {
				generation_ret = -1;
				break;
			}
			if (ctx->profile)
				dsa_ms_diag_init(&diag, &req);
			if (req.generation_id != active.generation_id ||
			    req.parent_generation_id != active.parent_generation_id ||
			    req.img_id != active.img_id || req.arena_id != active.arena_id ||
			    req.arena_epoch != active.arena_epoch) {
				(void)dsa_ms_reply_generation_error(
					generation_fd, &req, CDP_DSA_MS_EIDENTITY,
					ctx->profile, CDP_DSA_MS_STAGE_REQUEST_IDENTITY,
					ESTALE, &diag);
				generation_ret = -1;
				break;
			}

			if (req.op == CDP_DSA_MS_RAW_SEALED) {
				if (applied ||
				    !dsa_ms_range_valid(req.desc_off, req.desc_head,
							(size_t)parsed_size) ||
				    !dsa_ms_range_valid(req.raw_off, req.raw_head,
							(size_t)parsed_size) ||
				    (req.desc_head - req.desc_off) %
					sizeof(struct dsa_dump_descriptor)) {
					(void)dsa_ms_reply_generation_error(
						generation_fd, &req, CDP_DSA_MS_EBOUNDS,
						ctx->profile, CDP_DSA_MS_STAGE_COMPARE_BOUNDS,
						ERANGE, &diag);
					generation_ret = -1;
					break;
				}
				__atomic_thread_fence(__ATOMIC_ACQUIRE);
				reply = req;
				reply.op = CDP_DSA_MS_RAW_READY;
				reply.status = CDP_DSA_MS_OK;
				if ((ctx->profile && dsa_ms_send_generation(
					     generation_fd, &reply, true, &diag)) ||
				    (!ctx->profile && dsa_ms_send(generation_fd, &reply))) {
					generation_ret = -1;
					break;
				}
				raw_sealed = true;
				continue;
			}

			if (req.op == CDP_DSA_MS_COMPARE_REQ) {
			u64 service_wall_start_us = 0;
			u64 service_cpu_start_us = 0;
			u64 reconcile_start_us = 0;
			u64 reconcile_us = 0;
			bool mapping_warm;

			if (!raw_sealed || applied || !dsa_ms_range_valid(req.desc_off, req.desc_head,
						   (size_t)parsed_size) ||
			    !dsa_ms_range_valid(req.raw_off, req.raw_head,
						   (size_t)parsed_size) ||
			    !dsa_ms_range_valid(req.vma_plan_off, req.vma_plan_head,
						   (size_t)parsed_size) ||
			    !dsa_ms_range_valid(req.result_off, req.result_limit,
						   (size_t)parsed_size)) {
				(void)dsa_ms_reply_generation_error(
					generation_fd, &req, CDP_DSA_MS_EBOUNDS,
					ctx->profile, CDP_DSA_MS_STAGE_COMPARE_BOUNDS,
					ERANGE, &diag);
				generation_ret = -1;
				break;
			}
			/* parent_generation_id is an identity relation, not a residency
			 * proof.  This becomes true only after this service has itself
			 * promoted the previous staged views without dropping their maps. */
			mapping_warm = ctx->service_parent_mapping_warm &&
				ctx->nr_old_memstore != 0;
			hot_service_profile_reset_generation(ctx);
			if (ctx->profile) {
				service_wall_start_us = dsa_profile_wall_now_us();
				service_cpu_start_us = dsa_profile_thread_now_us();
				reconcile_start_us = service_wall_start_us;
			}
			xfer.hot_apply = ctx;
			xfer.pages_id = 0;
			xfer.dsa_fg_raw_capture = true;
			xfer.dsa_fg_shared = shared;
			xfer.dsa_fg_desc_area_off = req.desc_off;
			xfer.dsa_fg_desc_head = req.desc_head;
			xfer.dsa_fg_raw_payload_base = req.raw_off;
			xfer.dsa_fg_raw_payload_head = req.raw_head;
			xfer.dsa_fg_result_meta_base = req.result_off;
			xfer.dsa_fg_result_meta_limit = req.result_limit;
			errno = 0;
			if (hot_fg_load_vma_plan(ctx, shared, req.vma_plan_off,
						 req.vma_plan_head, req.vma_plan_count)) {
				int saved_errno = errno ? errno : EBADMSG;

				(void)dsa_ms_reply_generation_error(
					generation_fd, &req, CDP_DSA_MS_EHW,
					ctx->profile, CDP_DSA_MS_STAGE_COMPARE_VMA_PLAN,
					saved_errno, &diag);
				generation_ret = -1;
				break;
			}
			if (ctx->profile) {
				reconcile_us = dsa_profile_delta_us(reconcile_start_us,
							 dsa_profile_wall_now_us());
			}
			errno = 0;
			if (hot_fg_encode_raw_wavefront(&xfer, ctx, shared, true)) {
				int saved_errno = errno ? errno : EREMOTEIO;

				(void)dsa_ms_reply_generation_error(
					generation_fd, &req, CDP_DSA_MS_EHW,
					ctx->profile, CDP_DSA_MS_STAGE_COMPARE_ENGINE,
					saved_errno, &diag);
				generation_ret = -1;
				break;
			}
			reply = req;
			reply.op = CDP_DSA_MS_COMPARE_DONE;
			reply.status = CDP_DSA_MS_OK;
			reply.result_head = xfer.dsa_fg_result_meta_head;
			reply.result_count = (xfer.dsa_fg_result_meta_head -
					      xfer.dsa_fg_result_meta_base) /
					 sizeof(struct parasite_dsa_fg_result);
			hot_service_profile_snapshot(ctx, &reply.profile);
			reply.profile.mapping_warm = mapping_warm ? 1 : 0;
			reply.profile.hot_reconcile_us = reconcile_us;
			if (ctx->profile) {
				reply.service_wall_us =
					dsa_profile_delta_us(service_wall_start_us,
							     dsa_profile_wall_now_us());
				reply.service_cpu_us =
					dsa_profile_delta_us(service_cpu_start_us,
							     dsa_profile_thread_now_us());
				reply.profile.service_compare_wall_us =
					reply.service_wall_us;
				reply.profile.service_compare_cpu_us =
					reply.service_cpu_us;
			}
			if (dsa_ms_send_generation(generation_fd, &reply,
						   ctx->profile, &diag)) {
				generation_ret = -1;
				break;
			}
			continue;
			}

			if (req.op == CDP_DSA_MS_APPLY_REQ) {
				int apply_ret;

				if (!raw_sealed) {
					(void)dsa_ms_reply_generation_error(
						generation_fd, &req, CDP_DSA_MS_ESTATE,
						ctx->profile, CDP_DSA_MS_STAGE_APPLY_PRECHECK,
						EPROTO, &diag);
					generation_ret = -1;
					break;
				}
				if (ctx->profile)
					apply_ret = dsa_ms_apply_generation(
						ctx, shared, (size_t)parsed_size, applied,
						&req, &reply, &diag);
				else
					apply_ret = dsa_ms_apply_generation_fast(
						ctx, shared, applied, &req, &reply);
				if ((ctx->profile &&
				     dsa_ms_send_generation(generation_fd, &reply, true,
							    &diag)) ||
				    (!ctx->profile && dsa_ms_send(generation_fd, &reply))) {
					generation_ret = -1;
					break;
				}
				if (apply_ret) {
					generation_ret = -1;
					break;
				}
				applied = true;
				continue;
			}

			if (req.op == CDP_DSA_MS_FULL_APPLY_REQ) {
				int apply_ret;

				if (!raw_sealed) {
					(void)dsa_ms_reply_generation_error(
						generation_fd, &req, CDP_DSA_MS_ESTATE,
						ctx->profile, CDP_DSA_MS_STAGE_APPLY_PRECHECK,
						EPROTO, &diag);
					generation_ret = -1;
					break;
				}
				apply_ret = dsa_ms_full_apply_generation(
					ctx, shared, (size_t)parsed_size, applied,
					&req, &reply, &diag);
				if ((ctx->profile && dsa_ms_send_generation(
					     generation_fd, &reply, true, &diag)) ||
				    (!ctx->profile && dsa_ms_send(generation_fd, &reply))) {
					generation_ret = -1;
					break;
				}
				if (apply_ret) {
					generation_ret = -1;
					break;
				}
				applied = true;
				continue;
			}
			(void)dsa_ms_reply_generation_error(
				generation_fd, &req, CDP_DSA_MS_ESTATE, ctx->profile,
				CDP_DSA_MS_STAGE_APPLY_PRECHECK, EINVAL, &diag);
			generation_ret = -1;
			break;
		}
		close(generation_fd);
		if (generation_ret < 0) {
			ret = -1;
			break;
		}

		/* Only the task worker can make the staged hot state visible. */
		rc = dsa_ms_recv(control_fd, &req);
		if (rc || req.generation_id != active.generation_id ||
		    req.parent_generation_id != active.parent_generation_id ||
		    req.img_id != active.img_id || req.arena_id != active.arena_id ||
		    req.arena_epoch != active.arena_epoch) {
			ret = -1;
			break;
		}
		if (req.op == CDP_DSA_MS_TERMINAL_READY) {
			if (!applied || dsa_ms_promote_staged_views(ctx)) {
				(void)dsa_ms_reply_error(control_fd, &req, CDP_DSA_MS_ESTATE);
				ret = -1;
				break;
			}
			have_session = false;
			applied = false;
			raw_sealed = false;
			ctx->service_parent_mapping_warm = true;
			reply = req;
			reply.status = CDP_DSA_MS_OK;
			if (dsa_ms_send(control_fd, &reply)) {
				ret = -1;
				break;
			}
			continue;
		}
		if (req.op == CDP_DSA_MS_TERMINAL_ABORT) {
			/* Aborting after APPLY would leave an unpublished staged parent.
			 * Fail-stop and force CDP to rebuild instead of guessing. */
			reply = req;
			reply.status = applied ? CDP_DSA_MS_ESTATE : CDP_DSA_MS_OK;
			(void)dsa_ms_send(control_fd, &reply);
			ret = applied ? -1 : 0;
			break;
		}
		(void)dsa_ms_reply_error(control_fd, &req, CDP_DSA_MS_ESTATE);
		ret = -1;
		break;
	}

	if (ctx) {
		struct page_xfer xfer = { .hot_apply = ctx };

		hot_apply_abort(&xfer);
	}
	if (shared != MAP_FAILED)
		munmap(shared, (size_t)parsed_size);
	return ret;
}
