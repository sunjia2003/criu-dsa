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
#define PARASITE_DSA_SHM_HDR_VERSION 1U

enum dsa_wq_policy {
	DSA_WQ_POLICY_LPT = 0,
	DSA_WQ_POLICY_RR = 1,
};

struct dsa_dump_descriptor {
	u64 src_addr;		/* Source address in target process */
	u32 copy_len;		/* Length to copy */
	u32 reserved0;
};

struct parasite_dsa_shm_hdr {
	u32 magic;
	u32 version;
	u32 flags;
	u32 desc_bytes;
	u32 desc_count;
	u32 data_off;
	u32 data_bytes;
	u32 reserved;
};

struct parasite_dsa_dump_pages_args {
	/* Input from CRIU */
	u64 shared_buf_addr;	/* Shared buffer address in parasite */
	u32 shared_buf_size;	/* Total shared buffer size */
	u32 hdr_off;		/* Header offset inside shared buffer */
	u32 buf_write_offset;	/* Current buffer write position */
	u32 is_last_batch;	/* Is this the last batch */
	u32 wq_count;		/* Number of available DSA workqueues */
	u32 use_shared_buf_fd;  /* Shared buffer is passed as FD and mmap-ed in parasite */
	u32 use_wq_fd;		/* Use FD instead of path */
	u32 batch_id;		/* Monotonic batch id from host */
	u32 wq_policy;		/* enum dsa_wq_policy, default LPT */
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
	u32 map_populate_fallbacks;	/* MAP_POPULATE -> MAP_SHARED fallbacks */
};

#endif /* !__ASSEMBLY__ */

#endif /* __CR_PARASITE_H__ */

