#ifndef __CR_PARASITE_H__
#define __CR_PARASITE_H__

#define PARASITE_MAX_SIZE (64 << 10)

#ifndef __ASSEMBLY__

#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "linux/rseq.h"

#include "image.h"
#include "util-pie.h"
#include "common/lock.h"
#include "infect-rpc.h"

#include "images/vma.pb-c.h"
#include "images/tty.pb-c.h"

#define __head __used __section(.head.text)

enum {
	PARASITE_CMD_DUMP_THREAD = PARASITE_USER_CMDS,
	PARASITE_CMD_MPROTECT_VMAS,
	PARASITE_CMD_DUMPPAGES,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_POSIX_TIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,
	PARASITE_CMD_DUMP_TTY,
	PARASITE_CMD_CHECK_VDSO_MARK,
	PARASITE_CMD_CHECK_AIOS,
	PARASITE_CMD_DUMP_CGROUP,
	PARASITE_CMD_DSA_DUMP_PAGES,

	PARASITE_CMD_MAX,
};

struct parasite_vma_entry {
	unsigned long start;
	unsigned long len;
	int prot;
};

struct parasite_vdso_vma_entry {
	unsigned long start;
	unsigned long len;
	unsigned long orig_vdso_addr;
	unsigned long orig_vvar_addr;
	unsigned long rt_vvar_addr;
	int is_marked;
	bool try_fill_symtable;
	bool is_vdso;
};

struct parasite_dump_pages_args {
	unsigned int nr_vmas;
	unsigned int add_prot;
	unsigned int off;
	unsigned int nr_segs;
	unsigned long nr_pages;
};

static inline struct parasite_vma_entry *pargs_vmas(struct parasite_dump_pages_args *a)
{
	return (struct parasite_vma_entry *)(a + 1);
}

static inline struct iovec *pargs_iovs(struct parasite_dump_pages_args *a)
{
	return (struct iovec *)(pargs_vmas(a) + a->nr_vmas);
}

struct parasite_dump_sa_args {
	rt_sigaction_t sas[SIGMAX];
};

struct parasite_dump_itimers_args {
	struct itimerval real;
	struct itimerval virt;
	struct itimerval prof;
};

struct posix_timer {
	int it_id;
	struct itimerspec val;
	int overrun;
};

struct parasite_dump_posix_timers_args {
	int timer_n;
	struct posix_timer timer[0];
};

struct parasite_aio {
	unsigned long ctx;
	unsigned int size;
};

struct parasite_check_aios_args {
	unsigned nr_rings;
	struct parasite_aio ring[0];
};

static inline int posix_timers_dump_size(int timer_n)
{
	return sizeof(int) + sizeof(struct posix_timer) * timer_n;
}

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	bool has_membarrier_get_registrations; /* this is sent from criu to parasite. */

	unsigned long brk;

	u32 pid;
	u32 sid;
	u32 pgid;
	u32 umask;

	int dumpable;
	int thp_disabled;
	int child_subreaper;
	int membarrier_registration_mask;
};

/*
 * Calculate how long we can make the groups array in parasite_dump_creds
 * and still fit the struct in one page
 */
#define PARASITE_MAX_GROUPS                                                                                 \
	((PAGE_SIZE - sizeof(struct parasite_dump_thread) - offsetof(struct parasite_dump_creds, groups)) / \
	 sizeof(unsigned int)) /* groups */

struct parasite_dump_creds {
	unsigned int cap_last_cap;

	u32 cap_inh[CR_CAP_SIZE];
	u32 cap_prm[CR_CAP_SIZE];
	u32 cap_eff[CR_CAP_SIZE];
	u32 cap_bnd[CR_CAP_SIZE];
	u32 cap_amb[CR_CAP_SIZE];

	int uids[4];
	int gids[4];
	int no_new_privs;
	unsigned int secbits;
	unsigned int ngroups;
	/*
	 * FIXME -- this structure is passed to parasite code
	 * through parasite args area so in parasite_dump_creds()
	 * call we check for size of this data fits the size of
	 * the area. Unfortunately, we _actually_ use more bytes
	 * than the sizeof() -- we put PARASITE_MAX_GROUPS int-s
	 * in there, so the size check is not correct.
	 *
	 * However, all this works simply because we make sure
	 * the PARASITE_MAX_GROUPS is so, that the total amount
	 * of memory in use doesn't exceed the PAGE_SIZE and the
	 * args area is at least one page (PARASITE_ARG_SIZE_MIN).
	 */
	unsigned int groups[0];
};

struct parasite_check_rseq {
	bool has_rseq;
	bool has_ptrace_get_rseq_conf; /* no need to check if supported */
	bool rseq_inited;
};

struct parasite_dump_thread {
	unsigned int *tid_addr;
	pid_t tid;
	tls_t tls;
	struct parasite_check_rseq rseq;
	stack_t sas;
	int pdeath_sig;
	unsigned long timerslack_ns;
	char comm[TASK_COMM_LEN];
	struct parasite_dump_creds creds[0];
};

static inline void copy_sas(ThreadSasEntry *dst, const stack_t *src)
{
	dst->ss_sp = encode_pointer(src->ss_sp);
	dst->ss_size = (u64)src->ss_size;
	dst->ss_flags = src->ss_flags;
}

/*
 * How many descriptors can be transferred from parasite:
 *
 * 1) struct parasite_drain_fd + all descriptors should fit into one page
 * 2) The value should be a multiple of CR_SCM_MAX_FD, because descriptors
 *    are transferred with help of send_fds and recv_fds.
 * 3) criu should work with a default value of the file limit (1024)
 */
#define PARASITE_MAX_FDS CR_SCM_MAX_FD * 3

struct parasite_drain_fd {
	int nr_fds;
	int fds[0];
};

struct fd_opts {
	char flags;
	struct {
		uint32_t uid;
		uint32_t euid;
		uint32_t signum;
		uint32_t pid_type;
		uint32_t pid;
	} fown;
};

static inline int drain_fds_size(struct parasite_drain_fd *dfds)
{
	int nr_fds = min((int)PARASITE_MAX_FDS, dfds->nr_fds);
	return sizeof(*dfds) + nr_fds * (sizeof(dfds->fds[0]) + sizeof(struct fd_opts));
}

struct parasite_tty_args {
	int fd;
	int type;

	int sid;
	int pgrp;
	bool hangup;

	int st_pckt;
	int st_lock;
	int st_excl;
};

struct parasite_dump_cgroup_args {
	/*
	 * 4K should be enough for most cases.
	 *
	 * The string is null terminated.
	 */
	char contents[(1 << 12) - 32];
	/*
	 * Contains the path to thread cgroup procfs.
	 * "self/task/<tid>/cgroup"
	 */
	char thread_cgrp[32];
};

/* DSA dump pages batch structure */
#define DSA_DUMP_BATCH_SIZE    128
#define DSA_DUMP_MAX_WQ        16
#define DSA_SHARED_DATA_ALIGN  4096U
#define PARASITE_DSA_SHM_HDR_MAGIC   0x4453414dU
#define PARASITE_DSA_SHM_HDR_VERSION 2U
#define PARASITE_DSA_SHM_F_STREAM    0x1U
#ifdef CRIU_DSA_ENABLE_LEGACY_SINGLE_RPC
#define PARASITE_DSA_SHM_F_SINGLE_RPC 0x2U
#endif
#define PARASITE_DSA_SHM_F_FINE_GRAINED 0x4U
#define DSA_STREAM_SLOT_COUNT        8U
#define DSA_STREAM_SLOT_DESC_CAP     DSA_DUMP_BATCH_SIZE
#ifndef DSA_FG_PATCH_SIZE
#define DSA_FG_PATCH_SIZE            128U
#endif
#ifndef DSA_FG_MAX_PATCHES
#define DSA_FG_MAX_PATCHES           8U
#endif
#ifndef DSA_FG_MAX_BYTES
#define DSA_FG_MAX_BYTES             1024U
#endif
#ifndef DSA_FG_MAX_OLD_SEGMENTS
#define DSA_FG_MAX_OLD_SEGMENTS      256U
#endif
#ifndef DSA_FG_PAGE_PATCH
#define DSA_FG_PAGE_PATCH            1U
#endif
#ifndef DSA_FG_PAGE_FULL
#define DSA_FG_PAGE_FULL             2U
#endif
#ifndef DSA_FG_PAGE_PARENT
#define DSA_FG_PAGE_PARENT           3U
#endif

enum dsa_stream_slot_state {
	DSA_STREAM_SLOT_EMPTY = 0,
	DSA_STREAM_SLOT_READY = 1,
	DSA_STREAM_SLOT_COPYING = 2,
	DSA_STREAM_SLOT_DONE = 3,
	DSA_STREAM_SLOT_ERROR = 4,
};

enum dsa_wq_policy {
	DSA_WQ_POLICY_LPT = 0,
	DSA_WQ_POLICY_RR = 1,
};

struct dsa_dump_descriptor {
	u64 src_addr;		/* Source address in target process */
	u32 copy_len;		/* Length to copy */
	u32 reserved0;
};

struct dsa_fg_old_segment {
	u64 img_id;
	u64 vaddr;
	u64 len;
	u64 file_off;
	u32 fd_index;
	u32 flags;
};

struct dsa_fg_descriptor {
	u64 src_addr;		/* Source address in target process */
	u32 old_seg_idx;	/* Index in dsa_fg_old_segment table */
	u32 page_count;		/* Number of contiguous pages in this descriptor */
	u32 record_off;		/* Result metadata area in shared buffer */
	u32 record_stride;	/* Bytes reserved for each page metadata record */
};

struct parasite_dsa_fg_patch_entry {
	u16 off;
	u16 len;
};

struct parasite_dsa_fg_record {
	u64 vaddr;
	u32 data_len;
	u16 patch_count;
	u16 flags;
};

struct parasite_dsa_fg_result_entry {
	u16 off;
	u16 len;
	u32 data_off;		/* Offset in the shared result-data arena */
};

struct parasite_dsa_fg_result {
	u64 vaddr;
	u32 data_off;		/* Full-page data offset for DSA_FG_PAGE_FULL */
	u32 data_len;
	u16 patch_count;
	u16 flags;
	struct parasite_dsa_fg_result_entry entries[DSA_FG_MAX_PATCHES];
};

struct parasite_dsa_shm_hdr {
	u32 magic;
	u32 version;
	u32 flags;
	u32 desc_bytes;
	u32 desc_count;
	u32 data_off;
	u32 data_bytes;
	u32 fg_old_seg_off;
	u32 fg_old_seg_count;
	u32 fg_record_stride;
	u32 reserved;
};

struct parasite_dsa_stream_slot {
	volatile u32 state;
	u32 seq;
	u32 desc_off;
	u32 desc_count;
	u32 payload_off;
	u32 payload_bytes;
	u32 copied_bytes;
	u32 status;
};

struct parasite_dsa_stream_hdr {
	struct parasite_dsa_shm_hdr base;
	volatile u32 producer_seq;
	volatile u32 consumer_seq;
	volatile u32 finish;
	volatile u32 error;
	volatile u32 consumer_ready;
	u32 slot_count;
	u32 slot_desc_cap;
	u32 slots_off;
	u32 desc_area_off;
	u32 payload_base;
	volatile u32 payload_head;
	u32 payload_limit;
	u32 fg_result_meta_base;
	u32 fg_result_meta_head;
	u32 fg_result_meta_limit;
	u32 fg_result_data_base;
	volatile u32 fg_result_data_head;
	u32 fg_result_data_limit;
	u32 reserved;
	s32 result_op_ret;
	u32 result_total_copied;
	u32 result_completed_count;
	s32 result_failed_idx;
	u32 result_failed_status;
	u32 result_new_buf_offset;
	u64 result_setup_shared_recv_fd_us;
	u64 result_setup_shared_mmap_us;
	u64 result_cleanup_munmap_us;
	u64 result_cleanup_close_us;
	u64 result_setup_shared_us;
	u64 result_prefault_us;
	u64 result_submit_us;
	u64 result_poll_us;
	u32 result_submit_enqcmd;
	u32 result_submit_write;
	u32 result_fg_compare_ops;
	u32 result_fg_copy_ops;
};

struct parasite_dsa_dump_pages_args {
	/* Input from CRIU */
	u64 shared_buf_addr;	/* Shared buffer address in parasite */
	u32 shared_buf_size;	/* Total shared buffer size */
	u64 shared_map_size;	/* Actual mmap/munmap size for the shared buffer */
	u32 hdr_off;		/* Header offset inside shared buffer */
	u32 buf_write_offset;	/* Current buffer write position */
	u32 is_last_batch;	/* Is this the last batch */
	u32 wq_count;		/* Number of available DSA workqueues */
	u32 use_shared_buf_fd;  /* Shared buffer is passed as FD and mmap-ed in parasite */
	u32 use_wq_fd;		/* Use FD instead of path */
	u32 batch_id;		/* Monotonic batch id from host */
	u32 wq_policy;		/* enum dsa_wq_policy, default LPT */
	u32 fg_enabled;		/* Fine-grained DSA compare/copy mode */
	u32 fg_old_seg_count;	/* Number of old segment FDs sent over RPC */
	char wq_paths[DSA_DUMP_MAX_WQ][64];  /* WQ paths or empty if using FD */

	/* Output from PARASITE */
	s32 op_ret;		/* Operation result (0 = success) */
	u32 total_copied;	/* Total bytes copied in this batch */
	u32 completed_count;	/* Number of completed descriptors */
	s32 failed_idx;		/* Failed descriptor index (-1 = all success) */
	u32 failed_status;	/* Failed descriptor DSA status */
	u32 new_buf_offset;	/* New buffer write offset after this batch */
	u32 submit_enqcmd;	/* Number of descriptors submitted via enqcmd */
	u32 submit_write;	/* Number of descriptors submitted via write() */
	u32 fg_compare_ops;	/* Number of fine-grained compare ops */
	u32 fg_copy_ops;	/* Number of fine-grained memmove ops */
	u32 map_populate_fallbacks;	/* MAP_POPULATE -> MAP_SHARED fallbacks */
	u64 prefault_us;	/* Total time spent in source prefault for this batch */
	u64 submit_us;	/* Total time spent in DSA submit for this batch */
	u64 poll_us;	/* Total time spent in DSA completion poll for this batch */
	u64 setup_us;	/* Total setup time before descriptor processing */
	u64 setup_shared_us;	/* Shared buffer setup time */
	u64 setup_wq_us;	/* Workqueue setup time */
	u64 setup_shared_recv_fd_us;	/* Shared FD receive time */
	u64 setup_shared_mmap_us;	/* Shared mmap time */
	u64 setup_wq_recv_fd_us;	/* WQ FD receive time */
	u64 setup_wq_open_us;	/* WQ path open time */
	u64 setup_wq_mmap_us;	/* WQ portal mmap time */
	u64 cleanup_munmap_us;	/* Cleanup munmap time */
	u64 cleanup_close_us;	/* Cleanup close time */
};

#endif /* !__ASSEMBLY__ */

#endif /* __CR_PARASITE_H__ */
