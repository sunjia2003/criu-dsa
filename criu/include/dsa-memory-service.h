#ifndef __CR_DSA_MEMORY_SERVICE_H__
#define __CR_DSA_MEMORY_SERVICE_H__

/*
 * Fixed-size control-plane wire format shared by the CDP task worker, a
 * short-lived CRIU dump, and the task-scoped DSA memory service.  Bulk data
 * never travels through this protocol: all offsets address the shared raw
 * arena.  Keep it independent of CRIU internal pointers and protobuf types.
 */

#include <stdint.h>

#define CDP_DSA_MEMORY_SERVICE_MAGIC   0x4350444dU /* "CDPM" */
#define CDP_DSA_MEMORY_SERVICE_VERSION 9U
#define CDP_DSA_MEMORY_SERVICE_DIAG_MAGIC 0x43445044U /* "CDPD" */
#define CDP_DSA_MEMORY_SERVICE_DIAG_VERSION 1U
#define CDP_DSA_MS_DIAG_INVALID_OBJECT UINT64_MAX

enum cdp_dsa_memory_service_op {
	CDP_DSA_MS_SESSION_PREPARE = 1,
	CDP_DSA_MS_PREPARED = 2,
	CDP_DSA_MS_COMPARE_REQ = 3,
	CDP_DSA_MS_COMPARE_DONE = 4,
	CDP_DSA_MS_APPLY_REQ = 5,
	CDP_DSA_MS_APPLY_DONE = 6,
	CDP_DSA_MS_TERMINAL_READY = 7,
	CDP_DSA_MS_TERMINAL_ABORT = 8,
	CDP_DSA_MS_ERROR = 9,
	CDP_DSA_MS_RAW_SEALED = 10,
	CDP_DSA_MS_RAW_READY = 11,
	CDP_DSA_MS_FULL_APPLY_REQ = 12,
	CDP_DSA_MS_FULL_APPLY_DONE = 13,
};

enum cdp_dsa_memory_service_status {
	CDP_DSA_MS_OK = 0,
	CDP_DSA_MS_EPROTO = 1,
	CDP_DSA_MS_EIDENTITY = 2,
	CDP_DSA_MS_EBOUNDS = 3,
	CDP_DSA_MS_ESTATE = 4,
	CDP_DSA_MS_EIO = 5,
	CDP_DSA_MS_EHW = 6,
};

enum cdp_dsa_memory_service_failure_stage {
	CDP_DSA_MS_STAGE_NONE = 0,
	CDP_DSA_MS_STAGE_REQUEST_IDENTITY = 1,
	CDP_DSA_MS_STAGE_COMPARE_BOUNDS = 2,
	CDP_DSA_MS_STAGE_COMPARE_VMA_PLAN = 3,
	CDP_DSA_MS_STAGE_COMPARE_ENGINE = 4,
	CDP_DSA_MS_STAGE_APPLY_PRECHECK = 10,
	CDP_DSA_MS_STAGE_APPLY_OPEN_MANIFEST = 11,
	CDP_DSA_MS_STAGE_APPLY_RESULT_VALIDATE = 12,
	CDP_DSA_MS_STAGE_APPLY_VMA_MATERIALIZE = 13,
	CDP_DSA_MS_STAGE_APPLY_PAGE_STORE = 14,
	CDP_DSA_MS_STAGE_APPLY_MANIFEST_FINISH = 15,
	CDP_DSA_MS_STAGE_APPLY_MANIFEST_CLOSE = 16,
	CDP_DSA_MS_STAGE_SEND_REPLY = 17,
};

/*
 * Profile/full mode appends this fixed diagnostic trailer to the same
 * SOCK_SEQPACKET generation reply.  The base control message and the OFF
 * mode packet size remain unchanged.
 */
struct cdp_dsa_memory_service_diag {
	uint32_t magic;
	uint16_t version;
	uint16_t size;
	uint16_t request_op;
	uint16_t reply_op;
	uint32_t service_status;
	uint32_t failure_stage;
	int32_t primary_errno;
	int32_t cleanup_errno;
	uint32_t reserved0;
	uint64_t generation_id;
	uint64_t arena_epoch;
	uint64_t object_index;
	uint64_t object_vaddr;
	uint64_t expected_results;
	uint64_t completed_results;
	uint64_t apply_validate_wall_us;
	uint64_t apply_materialize_wall_us;
	uint64_t apply_store_wall_us;
	uint64_t apply_manifest_finish_wall_us;
	uint64_t apply_manifest_close_wall_us;
	uint64_t apply_total_wall_us;
	uint64_t apply_total_cpu_us;
};

/*
 * Per-generation aggregate profile returned by the long-lived service.
 * There are deliberately no pointers and no per-descriptor timestamps here:
 * the same fixed-width record is carried by the worker, CRIU client and
 * service, while bulk capture/results remain in the shared arena.
 */
struct cdp_dsa_memory_service_profile {
	uint32_t enabled;
	uint32_t backend;
	uint32_t mapping_warm;
	uint32_t prq_profile_available;
	uint32_t prq_profile_sources;
	int32_t prq_setup_errno;
	uint32_t reserved0;
	uint32_t reserved1;

	uint64_t hot_reconcile_us;
	uint64_t service_compare_wall_us;
	uint64_t service_compare_cpu_us;
	uint64_t raw_index_us;
	uint64_t span_build_us;
	uint64_t compare_wall_us;
	uint64_t compare_cpu_us;
	uint64_t compare_engine_wall_us;
	uint64_t compare_engine_cpu_us;
	uint64_t result_publish_us;
	uint64_t parent_prefault_wall_us;
	uint64_t parent_prefault_cpu_us;
	uint64_t compare_core_wall_us;
	uint64_t compare_core_cpu_us;
	uint64_t hot_apply_us;
	uint64_t hot_apply_cpu_us;

	uint64_t raw_pages;
	uint64_t raw_bytes;
	uint64_t capture_runs;
	uint64_t spans;
	uint64_t span_pages;
	uint64_t max_span_pages;
	uint64_t compare_ops;
	uint64_t enq_retries;
	uint64_t poll_sweeps;
	uint64_t not_ready;
	uint64_t max_active;
	uint64_t completions_harvested;
	uint64_t completion_timeout_count;
	uint64_t max_completion_age_us;
	uint64_t prefault_spans;
	uint64_t prefault_pages;
	uint64_t parent_pages;
	uint64_t patch_pages;
	uint64_t full_pages;
	uint64_t patch_ranges;
	uint64_t patch_bytes;
	uint64_t prq_pg_requests;
	uint64_t prq_thread_cpu_us;

	uint64_t memcmp_calls;
	uint64_t memcmp_requested_bytes;
	uint64_t memcmp_scalar_bytes;
	uint64_t scalar64_calls;
	uint64_t scalar64_word_ops;
	uint64_t scalar64_refine_bytes;
	uint64_t scalar64_tail_bytes;
	uint64_t scalar64_bytes_examined;
	uint64_t simd_vector_ops;
	uint64_t simd_bytes_examined;
	uint64_t hybrid_dsa_claim_spans;
	uint64_t hybrid_dsa_claim_pages;
	uint64_t hybrid_cpu_claim_spans;
	uint64_t hybrid_cpu_claim_pages;
	uint64_t hybrid_cpu_waves;
	uint64_t hybrid_dsa_to_cpu_handoff_spans;
	uint64_t hybrid_dsa_to_cpu_handoff_pages;
	uint64_t hybrid_dsa_to_cpu_handoff_remaining_bytes;
	uint64_t hybrid_unclaimed_empty_count;
	uint64_t compare_nobof_faults;
	uint64_t compare_nobof_fault_source1;
	uint64_t compare_nobof_fault_source2;
	uint64_t compare_nobof_equal_prefix_bytes;
	uint64_t compare_fault_handoff_spans;
	uint64_t compare_fault_handoff_pages;
	uint64_t compare_fault_handoff_remaining_bytes;
	uint64_t compare_fault_queue_max;
	uint64_t compare_fresh_claim_throttles;
	uint64_t compare_cpu_fault_waves;
	uint64_t dsa_logical_progress_bytes;
	uint64_t simd_logical_progress_bytes;
	uint64_t normal_simd_logical_progress_bytes;
	uint64_t fault_simd_logical_progress_bytes;
	uint64_t dsa_fresh_submit_ops;
	/* Profile schema v10+: page-aligned extent suffix probes.  The field name
	 * is retained to keep the fixed-width service record layout stable. */
	uint64_t dsa_continuation_submit_ops;
	uint64_t dsa_submitted_bytes;
	uint64_t simd_progress_while_dsa_active_bytes;
	uint64_t simd_quanta_while_dsa_active;
	uint64_t dsa_fresh_claim_bytes;
	uint64_t dsa_active_zero_while_normal_cpu_work;
	/* Profile schema v12: aggregate ready slots immediately before and after
	 * each whole SIMD wave.  This is never sampled per page. */
	uint64_t ready_completions_before_simd;
	uint64_t ready_completions_after_simd;
	/* Dual-granularity extent/page scheduler diagnostics.  These are populated
	 * only when the task explicitly enables the profile path. */
	uint64_t scheduler_iterations;
	uint64_t dsa_refill_samples;
	uint64_t post_refill_active_sum;
	uint64_t post_refill_active_lt_32;
	uint64_t post_refill_active_lt_64;
	uint64_t post_refill_active_lt_96;
	uint64_t fresh_refill_spans;
	uint64_t fresh_refill_batches;
	uint64_t fresh_refill_blocked_fault_debt;
	uint64_t dsa_empty_with_claimable_fresh;
	uint64_t batch_outer_submits;
	uint64_t batch_child_submits;
	uint64_t batch_partial_submits;
	uint64_t batch_single_tail_submits;
	uint64_t batch_outer_success;
	uint64_t batch_outer_fail;
	uint64_t batch_child_success;
	uint64_t batch_child_nobof;
	uint64_t batch_max_active_outer;
	uint64_t batch_max_active_children;

	/* Filled by the short-lived durable writer after COMPARE_DONE. */
	uint64_t idx_write_calls;
	uint64_t idx_bytes;
	uint64_t dat_write_calls;
	uint64_t dat_writev_calls;
	uint64_t dat_bytes;
	/* CRIU client-owned sidecar breakdown.  These remain zero unless the
	 * explicit profile mode is enabled. */
	uint64_t sidecar_preflight_us;
	uint64_t sidecar_serialize_us;
	uint64_t sidecar_idx_write_us;
	uint64_t sidecar_dat_write_us;
	uint64_t idx_write_syscalls;
	uint64_t dat_write_syscalls;
	uint64_t dat_writev_syscalls;
	uint64_t sidecar_lseek_syscalls;
};

/*
 * The generation id is an integer CDP logical generation.  arena_id is a
 * stable hash/identity supplied by CDP; it is never a virtual address.  The
 * optional VMA plan and result regions are [off, head) byte ranges in the
 * arena.  result_count describes parasite_dsa_fg_result records.
 */
struct cdp_dsa_memory_service_msg {
	uint32_t magic;
	uint16_t version;
	uint16_t op;
	uint32_t status;
	uint32_t reserved0;
	uint64_t generation_id;
	uint64_t parent_generation_id;
	uint64_t img_id;
	uint64_t arena_id;
	uint64_t arena_epoch;
	uint32_t desc_off;
	uint32_t desc_head;
	uint32_t raw_off;
	uint32_t raw_head;
	uint32_t vma_plan_off;
	uint32_t vma_plan_head;
	uint32_t vma_plan_count;
	uint32_t result_off;
	uint32_t result_head;
	uint32_t result_limit;
	uint32_t result_count;
	uint64_t service_wall_us;
	uint64_t service_cpu_us;
	struct cdp_dsa_memory_service_profile profile;
};

#endif /* __CR_DSA_MEMORY_SERVICE_H__ */
