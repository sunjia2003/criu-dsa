#ifndef __CR_PAGE_XFER__H__
#define __CR_PAGE_XFER__H__
#include "pagemap.h"
#include "dsa-memory-service.h"

struct ps_info {
	int pid;
	unsigned short port;
};

struct hot_apply_ctx;

extern int cr_page_server(bool daemon_mode, bool lazy_dump, int cfd);

/* User buffer for read-mode pre-dump*/
#define PIPE_MAX_BUFFER_SIZE (PIPE_MAX_SIZE << PAGE_SHIFT)

#define DSA_DIRECT_METADATA_STAGE_BYTES (2U * 1024U * 1024U)
#define DSA_DIRECT_PAYLOAD_STAGE_BYTES  (4U * 1024U * 1024U)
#define DSA_DIRECT_SCRATCH_BYTES        \
	(2U * DSA_DIRECT_METADATA_STAGE_BYTES + DSA_DIRECT_PAYLOAD_STAGE_BYTES)

/*
 * page_xfer -- transfer pages into image file.
 * Two images backends are implemented -- local image file
 * and page-server image file.
 */

struct page_xfer {
	/* transfers one vaddr:len entry */
	int (*write_pagemap)(struct page_xfer *self, struct iovec *iov, u32 flags);
	/* transfers pages related to previous pagemap */
	int (*write_pages)(struct page_xfer *self, int pipe, unsigned long len);
	void (*close)(struct page_xfer *self);

	/*
	 * In case we need to dump pagemaps not as-is, but
	 * relative to some address. Used, e.g. by shmem.
	 */
	unsigned long offset;
	bool transfer_lazy;
	bool dsa_fine_grained;

	/* private data for every page-xfer engine */
	union {
		struct /* local */ {
			struct cr_img *pmi; /* pagemaps */
			struct cr_img *pi;  /* pages */
		};

		struct /* page-server */ {
			int sk;
			u64 dst_id;
		};
	};

	struct page_read *parent;
	struct hot_apply_ctx *hot_apply;
	u32 pages_id;

	const void *dsa_fg_shared;
	u32 dsa_fg_desc_area_off;
	u32 dsa_fg_desc_head;
	u32 dsa_fg_raw_payload_base;
	u32 dsa_fg_raw_payload_head;
	/* Reserved for the task-scoped memory-service protocol.  The legacy path
	 * leaves these zero and therefore keeps its existing layout/behavior. */
	u32 dsa_fg_result_meta_base;
	u32 dsa_fg_result_meta_head;
	u32 dsa_fg_result_meta_limit;
	/* Generation-exclusive O_DIRECT staging inside the persistent hugetlb
	 * arena. The raw producer's payload limit ends before idx_scratch_off. */
	u32 dsa_dio_idx_scratch_off;
	u32 dsa_dio_dat_scratch_off;
	u32 dsa_dio_pagemap_scratch_off;
	u32 dsa_dio_scratch_limit;
	u32 dsa_fg_vma_plan_base;
	u32 dsa_fg_vma_plan_head;
	u32 dsa_fg_vma_plan_limit;
	u32 dsa_fg_vma_plan_count;
	/* Client-owned temporary VMA list.  In memory-service mode it is copied
	 * into the reserved result tail after thaw, then freed before close. */
	void *dsa_fg_vma_plan_local;
	/* Set only for the short-lived CRIU side of the task-scoped service. */
	bool dsa_fg_service;
	u64 dsa_fg_service_generation;
	u64 dsa_fg_service_parent_generation;
	u64 dsa_fg_service_arena_id;
	u64 dsa_fg_service_arena_epoch;
	u64 dsa_fg_service_img_id;
	struct cdp_dsa_memory_service_profile dsa_fg_service_profile;
	struct cdp_dsa_memory_service_diag dsa_fg_service_diag;
	u64 dsa_fg_profile_total_start_us;
	u64 dsa_fg_profile_request_publish_us;
	u64 dsa_fg_profile_ipc_compare_us;
	u64 dsa_fg_profile_sidecar_us;
	u64 dsa_fg_profile_pagemap_us;
	u64 dsa_fg_profile_finish_us;
	u64 dsa_fg_profile_ipc_apply_us;
	/*
	 * Backend-neutral write-path ledger.  It is enabled only by the explicit
	 * profile mode and observes the existing writer; it never selects another
	 * output implementation.
	 */
	bool write_profile_enabled;
	bool write_profile_emitted;
	bool write_profile_target;
	u64 write_profile_start_wall_us;
	u64 write_profile_start_cpu_us;
	u64 write_profile_io_wall_us;
	u64 write_profile_io_cpu_us;
	u64 write_profile_input_pages;
	u64 write_profile_input_bytes;
	u64 write_profile_pagemap_records;
	u64 write_profile_pagemap_bytes;
	u64 write_profile_pages_bytes;
	u64 write_profile_pages_emit_calls;
	/* Aligned full output bypasses the legacy pipe replay and appends raw
	 * capture bytes to pages.img through this bounded sink.  It is deliberately
	 * separate from fine sidecar buffering: both consume the same frozen raw
	 * arena but preserve their native image formats. */
	u32 dsa_fg_raw_emit_cursor;
	bool dsa_fg_raw_capture;
	bool dsa_fg_materialized;
	/* Set only for the CDP-selected DSA full/fine transfer.  It never leaks
	 * into base, shmem or sibling-process page images. */
	bool dsa_output_direct;
};

extern int page_xfer_dsa_fg_enable(struct page_xfer *xfer);

extern int open_page_xfer(struct page_xfer *xfer, int fd_type, unsigned long id);
extern int open_page_xfer_no_parent(struct page_xfer *xfer, int fd_type, unsigned long id);
struct page_pipe;
struct vm_area_list;
extern int page_xfer_dump_pages(struct page_xfer *, struct page_pipe *);
extern int page_xfer_predump_pages(int pid, struct page_xfer *, struct page_pipe *);
extern int page_xfer_hot_set_vmas(struct page_xfer *, struct vm_area_list *);
/* Prepare only immutable fine-grained inputs before collect_pstree freezes the task. */
extern int page_xfer_hot_prepare_before_freeze(unsigned long img_id);
extern void page_xfer_hot_cleanup_before_freeze(void);
extern int connect_to_page_server_to_send(void);
extern int connect_to_page_server_to_recv(int epfd);
extern int disconnect_from_page_server(void);

extern int check_parent_page_xfer(int fd_type, unsigned long id);

extern int page_xfer_dsa_fg_apply_records(struct page_xfer *xfer,
					  const void *shared,
					  u32 desc_area_off, u32 desc_head);

/* Entry point for the task-scoped DSA memory-service command.  It receives a
 * SOCK_SEQPACKET control fd whose peer is the CDP task worker/CRIU client. */
extern int page_xfer_dsa_memory_service(int control_fd);

/*
 * The post-copy migration makes it necessary to receive pages from
 * remote dump. The protocol we use for that is quite simple:
 * - lazy-pages sends request containing PS_IOV_GET(nr_pages, vaddr, pid)
 * - dump-side page server responds with PS_IOV_ADD(nr_pages, vaddr,
     pid) or PS_IOV_ADD(0, 0, 0) if it failed to locate the required
     pages
 * - dump-side page server sends the raw page data
 */

/* async request/receive of remote pages */
extern int request_remote_pages(unsigned long img_id, unsigned long addr, unsigned long nr_pages);

typedef int (*ps_async_read_complete)(unsigned long img_id, unsigned long vaddr, unsigned long nr_pages, void *);
extern int page_server_start_read(void *buf, unsigned long nr_pages, ps_async_read_complete complete, void *priv, unsigned flags);

#endif /* __CR_PAGE_XFER__H__ */
