#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/idxd.h>
#include <linux/memfd.h>
#include <linux/mman.h>

#include "linux/rseq.h"

#include "common/config.h"
#include "int.h"
#include "types.h"
#include <compel/plugins/std/syscall.h>
#include "linux/mount.h"
#include "parasite.h"
#include "fcntl.h"
#include "prctl.h"
#include "common/lock.h"
#include "parasite-vdso.h"
#include "criu-log.h"
#include "tty.h"
#include "aio.h"

#include "asm/parasite.h"
#include "restorer.h"
#include "infect-pie.h"

/*
 * PARASITE_CMD_DUMPPAGES is called many times and the parasite args contains
 * an array of VMAs at this time, so VMAs can be unprotected in any moment
 */
static struct parasite_dump_pages_args *mprotect_args = NULL;

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 0x08
#endif

#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG 2
#endif

#ifndef PR_GET_TIMERSLACK
#define PR_GET_TIMERSLACK 30
#endif

#ifndef PR_GET_CHILD_SUBREAPER
#define PR_GET_CHILD_SUBREAPER 37
#endif

#ifndef MAP_POPULATE
#define MAP_POPULATE 0
#endif

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

#define DSA_PORTAL_MAP_SIZE 0x1000UL
#define DSA_MAX_ENQ_RETRY   1000000U
#define HUGEPAGE_2MB_SIZE   (2UL * 1024UL * 1024UL)

static inline unsigned long dsa_align_up(unsigned long x, unsigned long align)
{
	return (x + align - 1UL) & ~(align - 1UL);
}

static inline void dsa_memzero(void *ptr, unsigned long len)
{
	unsigned char *p = (unsigned char *)ptr;
	unsigned long i;

	for (i = 0; i < len; ++i)
		p[i] = 0;
}

static inline int dsa_enqcmd_local(void *portal_slot, const void *desc)
{
#if defined(__x86_64__)
	unsigned char retry = 0;

	asm volatile(
		"sfence\n\t"
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

static inline void dsa_cpu_relax(void)
{
#if defined(__x86_64__)
	asm volatile("pause" ::: "memory");
#else
	asm volatile("" ::: "memory");
#endif
}

static inline void dsa_prefault_range(uint8_t *buf, uint32_t len)
{
	uint32_t i;
	const uint32_t step = 4096;
	volatile uint8_t sink = 0;

	if (!buf || !len)
		return;

	for (i = 0; i < len; i += step)
		sink ^= buf[i];
	(void)sink;
}

static uint32_t dsa_checksum32(const uint8_t *buf, uint32_t len)
{
	uint32_t i;
	uint32_t acc = 0;

	for (i = 0; i < len; ++i)
		acc = (acc * 16777619u) ^ buf[i];

	return acc;
}

static int parasite_dsa_copy(struct parasite_dsa_copy_args *a)
{
	int wq_fd = -1;
	int memfd = -1;
	int use_portal = 0;
	uint8_t *src;
	uint8_t *dst = (uint8_t *)-1;
	unsigned long map_len;
	unsigned long portal_mask = 0;
	unsigned long portal_offset = 0;
	void *portal = (void *)-1;
	struct dsa_hw_desc desc __attribute__((aligned(64)));
	volatile struct dsa_completion_record comp __attribute__((aligned(32)));
	uint32_t i;

	a->op_ret = -1;
	a->stage = 0;
	a->detail = 0;
	a->dsa_status = 0;
	a->bytes_completed = 0;
	a->used_hugetlb = 0;
	a->checksum_before = 0;
	a->checksum_after = 0;
	a->fault_addr = 0;
	a->comp_result = 0;

	if (!a->src_addr || !a->copy_len || !a->wq_path[0]) {
		a->stage = 1;
		a->op_ret = -EINVAL;
		return 0;
	}

	if (a->use_wq_fd) {
		a->stage = 2;
		wq_fd = recv_fd(parasite_get_rpc_sock());
		if (wq_fd < 0) {
			a->op_ret = wq_fd;
			a->detail = wq_fd;
			return 0;
		}
	} else {
		a->stage = 3;
		wq_fd = sys_open(a->wq_path, O_RDWR, 0);
		if (wq_fd < 0) {
			a->op_ret = wq_fd;
			a->detail = wq_fd;
			return 0;
		}
	}

	a->stage = 4;
	portal = (void *)sys_mmap(NULL, DSA_PORTAL_MAP_SIZE, PROT_WRITE, MAP_SHARED | MAP_POPULATE, wq_fd, 0);
	if ((long)portal < 0)
		portal = (void *)sys_mmap(NULL, DSA_PORTAL_MAP_SIZE, PROT_WRITE, MAP_SHARED, wq_fd, 0);

	if ((long)portal >= 0) {
		use_portal = 1;
		portal_mask = ((unsigned long)portal) & ~0xfffUL;
		portal_offset = ((unsigned long)portal) & 0xfffUL;
	} else {
		a->stage = 5;
	}

	a->stage = 6;
	map_len = dsa_align_up(a->copy_len, HUGEPAGE_2MB_SIZE);
	if (a->prefer_hugetlb) {
		memfd = sys_memfd_create("criu_dsa_copy_huge", MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
		if (memfd >= 0 && sys_fallocate(memfd, 0, 0, map_len) == 0) {
			dst = (uint8_t *)sys_mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
			if ((long)dst >= 0)
				a->used_hugetlb = 1;
		}
	}

	if ((long)dst < 0) {
		a->stage = 7;
		if (memfd >= 0) {
			sys_close(memfd);
			memfd = -1;
		}
		memfd = sys_memfd_create("criu_dsa_copy", MFD_CLOEXEC);
		if (memfd < 0) {
			a->op_ret = memfd;
			a->detail = memfd;
			goto out;
		}
		if (sys_fallocate(memfd, 0, 0, map_len) < 0) {
			a->op_ret = (int)sys_fallocate(memfd, 0, 0, map_len);
			a->detail = a->op_ret;
			goto out;
		}
		dst = (uint8_t *)sys_mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
		if ((long)dst < 0) {
			a->op_ret = (int)(long)dst;
			a->detail = (int)(long)dst;
			goto out;
		}
		sys_madvise((unsigned long)dst, map_len, MADV_HUGEPAGE);
	}

	a->stage = 8;
	src = (uint8_t *)(unsigned long)a->src_addr;
	dsa_prefault_range(src, a->copy_len);
	a->checksum_before = dsa_checksum32(src, a->copy_len);
	dsa_memzero(dst, a->copy_len);

	dsa_memzero(&desc, sizeof(desc));
	dsa_memzero((void *)&comp, sizeof(comp));

	desc.opcode = DSA_OPCODE_MEMMOVE;
	desc.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	desc.src_addr = (uint64_t)(unsigned long)src;
	desc.dst_addr = (uint64_t)(unsigned long)dst;
	desc.xfer_size = a->copy_len;
	desc.completion_addr = (uint64_t)(unsigned long)&comp;

	a->stage = 9;
	if (use_portal) {
		for (i = 0; i < DSA_MAX_ENQ_RETRY; ++i) {
			unsigned long off = ((unsigned long)portal_offset++ << 6) & 0xfffUL;
			void *slot = (void *)(portal_mask | off);

			if (dsa_enqcmd_local(slot, &desc) == 0)
				break;
			dsa_cpu_relax();
		}
	} else {
		for (i = 0; i < DSA_MAX_ENQ_RETRY; ++i) {
			long wr = sys_write(wq_fd, &desc, sizeof(desc));

			if (wr == (long)sizeof(desc))
				break;
			dsa_cpu_relax();
		}
	}

	if (i == DSA_MAX_ENQ_RETRY) {
		a->stage = 10;
		a->op_ret = -EAGAIN;
		a->detail = a->op_ret;
		goto out;
	}

	a->stage = 11;
	for (i = 0; i < DSA_MAX_ENQ_RETRY; ++i) {
		uint8_t st = comp.status;
		uint8_t code = (uint8_t)DSA_COMP_STATUS(st);

		if (st != 0 && code != DSA_COMP_NONE) {
			a->stage = 12;
			a->dsa_status = code;
			a->bytes_completed = comp.bytes_completed;
			a->fault_addr = comp.fault_addr;
			a->comp_result = comp.result;
			if (code == DSA_COMP_SUCCESS || code == DSA_COMP_SUCCESS_PRED) {
				a->checksum_after = dsa_checksum32(dst, a->copy_len);
				a->op_ret = (a->checksum_before == a->checksum_after) ? 0 : -EBADMSG;
				a->detail = a->op_ret;
			} else {
				a->op_ret = -(int)code;
				a->detail = a->op_ret;
			}
			goto out;
		}
		dsa_cpu_relax();
	}

	a->stage = 13;
	a->op_ret = -ETIMEDOUT;
	a->detail = a->op_ret;

out:
	if ((long)dst >= 0)
		sys_munmap(dst, map_len);
	if ((long)portal >= 0)
		sys_munmap(portal, DSA_PORTAL_MAP_SIZE);
	if (memfd >= 0)
		sys_close(memfd);
	if (wq_fd >= 0)
		sys_close(wq_fd);

	return 0;
}

static int mprotect_vmas(struct parasite_dump_pages_args *args)
{
	struct parasite_vma_entry *vmas, *vma;
	int ret = 0, i;

	vmas = pargs_vmas(args);
	for (i = 0; i < args->nr_vmas; i++) {
		vma = vmas + i;
		ret = sys_mprotect((void *)vma->start, vma->len, vma->prot | args->add_prot);
		if (ret) {
			pr_err("mprotect(%08lx, %ld) failed with code %d\n", vma->start, vma->len, ret);
			break;
		}
	}

	if (args->add_prot)
		mprotect_args = args;
	else
		mprotect_args = NULL;

	return ret;
}

static int dump_pages(struct parasite_dump_pages_args *args)
{
	int p, ret, tsock;
	struct iovec *iovs;
	int off, nr_segs;
	unsigned long spliced_bytes = 0;

	tsock = parasite_get_rpc_sock();
	p = recv_fd(tsock);
	if (p < 0)
		return -1;

	iovs = pargs_iovs(args);
	off = 0;
	nr_segs = args->nr_segs;
	if (nr_segs > UIO_MAXIOV)
		nr_segs = UIO_MAXIOV;
	while (1) {
		ret = sys_vmsplice(p, &iovs[args->off + off], nr_segs, SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
		if (ret < 0) {
			sys_close(p);
			pr_err("Can't splice pages to pipe (%d/%d/%d)\n", ret, nr_segs, args->off + off);
			return -1;
		}
		spliced_bytes += ret;
		off += nr_segs;
		if (off == args->nr_segs)
			break;
		if (off + nr_segs > args->nr_segs)
			nr_segs = args->nr_segs - off;
	}
	if (spliced_bytes != args->nr_pages * PAGE_SIZE) {
		sys_close(p);
		pr_err("Can't splice all pages to pipe (%ld/%ld)\n", spliced_bytes, args->nr_pages);
		return -1;
	}

	sys_close(p);
	return 0;
}

static int dump_sigact(struct parasite_dump_sa_args *da)
{
	int sig, ret = 0;

	for (sig = 1; sig <= SIGMAX; sig++) {
		int i = sig - 1;

		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = sys_sigaction(sig, NULL, &da->sas[i], sizeof(k_rtsigset_t));
		if (ret < 0) {
			pr_err("sys_sigaction failed (%d)\n", ret);
			break;
		}
	}

	return ret;
}

static int dump_itimers(struct parasite_dump_itimers_args *args)
{
	int ret;

	ret = sys_getitimer(ITIMER_REAL, &args->real);
	if (!ret)
		ret = sys_getitimer(ITIMER_VIRTUAL, &args->virt);
	if (!ret)
		ret = sys_getitimer(ITIMER_PROF, &args->prof);

	if (ret)
		pr_err("getitimer failed (%d)\n", ret);

	return ret;
}

static int dump_posix_timers(struct parasite_dump_posix_timers_args *args)
{
	int i;
	int ret = 0;

	for (i = 0; i < args->timer_n; i++) {
		ret = sys_timer_gettime(args->timer[i].it_id, &args->timer[i].val);
		if (ret < 0) {
			pr_err("sys_timer_gettime failed (%d)\n", ret);
			return ret;
		}
		ret = sys_timer_getoverrun(args->timer[i].it_id);
		if (ret < 0) {
			pr_err("sys_timer_getoverrun failed (%d)\n", ret);
			return ret;
		}
		args->timer[i].overrun = ret;
		ret = 0;
	}

	return ret;
}

static int dump_creds(struct parasite_dump_creds *args);
static int check_rseq(struct parasite_check_rseq *rseq);

static int dump_thread_common(struct parasite_dump_thread *ti)
{
	int ret;

	arch_get_tls(&ti->tls);
	ret = sys_prctl(PR_GET_TID_ADDRESS, (unsigned long)&ti->tid_addr, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the clear_child_tid address: %d\n", ret);
		goto out;
	}

	ret = sys_sigaltstack(NULL, &ti->sas);
	if (ret) {
		pr_err("Unable to get signal stack context: %d\n", ret);
		goto out;
	}

	ret = sys_prctl(PR_GET_PDEATHSIG, (unsigned long)&ti->pdeath_sig, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the parent death signal: %d\n", ret);
		goto out;
	}

	{
		long slack = sys_prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
		if (slack < 0) {
			pr_err("Unable to get timer slack: %ld\n", slack);
			ret = (int)slack;
			goto out;
		}
		ti->timerslack_ns = (unsigned long)slack;
	}

	ret = sys_prctl(PR_GET_NAME, (unsigned long)&ti->comm, 0, 0, 0);
	if (ret) {
		pr_err("Unable to get the thread name: %d\n", ret);
		goto out;
	}

	ret = check_rseq(&ti->rseq);
	if (ret) {
		pr_err("Unable to check if rseq() is initialized: %d\n", ret);
		goto out;
	}

	ret = dump_creds(ti->creds);
out:
	return ret;
}

/*
 * Returns a membarrier() registration command (it is a bitmask) if the process
 * was registered for specified (as a bit index) membarrier()-issuing command;
 * returns zero otherwise.
 */
static int get_membarrier_registration_mask(int cmd_bit)
{
	unsigned cmd = 1 << cmd_bit;
	int ret;

	/*
	 * Issuing a barrier will be successful only if the process was registered
	 * for this type of membarrier. All errors are a sign that the type issued
	 * was not registered (EPERM) or not supported by kernel (EINVAL or ENOSYS).
	 */
	ret = sys_membarrier(cmd, 0, 0);
	if (ret && ret != -EPERM && ret != -EINVAL && ret != -ENOSYS) {
		pr_err("membarrier(1 << %d) returned %d\n", cmd_bit, ret);
		return -1;
	}
	pr_debug("membarrier(1 << %d) returned %d\n", cmd_bit, ret);
	/*
	 * For supported registrations, MEMBARRIER_CMD_REGISTER_xxx = MEMBARRIER_CMD_xxx << 1.
	 * See: enum membarrier_cmd in include/uapi/linux/membarrier.h in kernel sources.
	 */
	return ret ? 0 : cmd << 1;
}

/*
 * It would be better to check the following with BUILD_BUG_ON, but we might
 * have an old linux/membarrier.h header without necessary enum values.
 */
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED	      3
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_SYNC_CORE 5
#define MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_RSEQ      7
#define MEMBARRIER_CMDBIT_GET_REGISTRATIONS	      9

static int dump_membarrier_compat(int *membarrier_registration_mask)
{
	int ret;

	*membarrier_registration_mask = 0;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_SYNC_CORE);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	ret = get_membarrier_registration_mask(MEMBARRIER_CMDBIT_PRIVATE_EXPEDITED_RSEQ);
	if (ret < 0)
		return -1;
	*membarrier_registration_mask |= ret;
	return 0;
}

static int dump_misc(struct parasite_dump_misc *args)
{
	int ret;

	args->brk = sys_brk(0);

	args->pid = sys_getpid();
	args->sid = sys_getsid();
	args->pgid = sys_getpgid(0);
	args->umask = sys_umask(0);
	sys_umask(args->umask); /* never fails */
	args->dumpable = sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	args->thp_disabled = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);

	if (args->has_membarrier_get_registrations) {
		ret = sys_membarrier(1 << MEMBARRIER_CMDBIT_GET_REGISTRATIONS, 0, 0);
		if (ret < 0) {
			pr_err("membarrier(1 << %d) returned %d\n", MEMBARRIER_CMDBIT_GET_REGISTRATIONS, ret);
			return -1;
		}
		args->membarrier_registration_mask = ret;
	} else {
		ret = dump_membarrier_compat(&args->membarrier_registration_mask);
		if (ret)
			return ret;
	}

	ret = sys_prctl(PR_GET_CHILD_SUBREAPER, (unsigned long)&args->child_subreaper, 0, 0, 0);
	if (ret)
		pr_err("PR_GET_CHILD_SUBREAPER failed (%d)\n", ret);

	return ret;
}

static int dump_creds(struct parasite_dump_creds *args)
{
	int ret, i, j;
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];
	struct cap_header hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };

	ret = sys_capget(&hdr, data);
	if (ret < 0) {
		pr_err("Unable to get capabilities: %d\n", ret);
		return -1;
	}

	/*
	 * Loop through the capability constants until we reach cap_last_cap.
	 * The cap_bnd set is stored as a bitmask comprised of CR_CAP_SIZE number of
	 * 32-bit uints, hence the inner loop from 0 to 32.
	 */
	for (i = 0; i < CR_CAP_SIZE; i++) {
		args->cap_eff[i] = data[i].eff;
		args->cap_prm[i] = data[i].prm;
		args->cap_inh[i] = data[i].inh;
		args->cap_bnd[i] = 0;
		args->cap_amb[i] = 0;

		for (j = 0; j < 32; j++) {
			if (j + i * 32 > args->cap_last_cap)
				break;
			ret = sys_prctl(PR_CAPBSET_READ, j + i * 32, 0, 0, 0);
			if (ret < 0) {
				pr_err("Unable to read capability %d: %d\n", j + i * 32, ret);
				return -1;
			}
			if (ret)
				args->cap_bnd[i] |= (1 << j);
		}

		for (j = 0; j < 32; j++) {
			if (j + i * 32 > args->cap_last_cap)
				break;
			ret = sys_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, j + i * 32, 0, 0);
			if (ret < 0) {
				pr_err("Unable to read ambient capability %d: %d\n", j + i * 32, ret);
				return -1;
			}
			if (ret)
				args->cap_amb[i] |= (1 << j);
		}
	}

	args->no_new_privs = sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	args->secbits = sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);

	ret = sys_getgroups(0, NULL);
	if (ret < 0)
		goto grps_err;

	args->ngroups = ret;
	if (args->ngroups >= PARASITE_MAX_GROUPS) {
		pr_err("Too many groups in task %d\n", (int)args->ngroups);
		return -1;
	}

	ret = sys_getgroups(args->ngroups, args->groups);
	if (ret < 0)
		goto grps_err;

	if (ret != args->ngroups) {
		pr_err("Groups changed on the fly %d -> %d\n", args->ngroups, ret);
		return -1;
	}

	ret = sys_getresuid(&args->uids[0], &args->uids[1], &args->uids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->uids[3] = sys_setfsuid(-1L);

	/*
	 * FIXME In https://github.com/checkpoint-restore/criu/issues/95 it is
	 * been reported that only low 16 bits are set upon syscall
	 * on ARMv7.
	 *
	 * We may rather need implement builtin-memset and clear the
	 * whole memory needed here.
	 */
	args->gids[0] = args->gids[1] = args->gids[2] = args->gids[3] = 0;

	ret = sys_getresgid(&args->gids[0], &args->gids[1], &args->gids[2]);
	if (ret) {
		pr_err("Unable to get uids: %d\n", ret);
		return -1;
	}

	args->gids[3] = sys_setfsgid(-1L);

	return 0;

grps_err:
	pr_err("Error calling getgroups (%d)\n", ret);
	return -1;
}

static int check_rseq(struct parasite_check_rseq *rseq)
{
	int ret;
	unsigned long rseq_abi_pointer;
	unsigned long rseq_abi_size;
	uint32_t rseq_signature;
	void *addr;

	/* no need to do hacky check if we can get all info from ptrace() */
	if (!rseq->has_rseq || rseq->has_ptrace_get_rseq_conf)
		return 0;

	/*
	 * We need to determine if victim process has rseq()
	 * initialized, but we have no *any* proper kernel interface
	 * supported at this point.
	 * Our plan:
	 * 1. We know that if we call rseq() syscall and process already
	 * has current->rseq filled, then we get:
	 * -EINVAL if current->rseq != rseq || rseq_len != sizeof(*rseq),
	 * -EPERM  if current->rseq_sig != sig),
	 * -EBUSY  if current->rseq == rseq && rseq_len == sizeof(*rseq) &&
	 *            current->rseq_sig != sig
	 * if current->rseq == NULL (rseq() wasn't used) then we go to:
	 * IS_ALIGNED(rseq ...) check, if we fail it we get -EINVAL and it
	 * will be hard to distinguish case when rseq() was initialized or not.
	 * Let's construct arguments payload
	 * with:
	 * 1. correct rseq_abi_size
	 * 2. aligned and correct rseq_abi_pointer
	 * And see what rseq() return to us.
	 * If ret value is:
	 * 0: it means that rseq *wasn't* used and we successfully registered it,
	 * -EINVAL or : it means that rseq is already initialized,
	 * so we *have* to dump it. But as we have has_ptrace_get_rseq_conf = false,
	 * we should just fail dump as it's unsafe to skip rseq() dump for processes
	 * with rseq() initialized.
	 * -EPERM or -EBUSY: should not happen as we take a fresh memory area for rseq
	 */
	addr = (void *)sys_mmap(NULL, sizeof(struct criu_rseq), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
				0);
	if (addr == MAP_FAILED) {
		pr_err("mmap() failed for struct rseq ret = %lx\n", (unsigned long)addr);
		return -1;
	}

	memset(addr, 0, sizeof(struct criu_rseq));

	/* sys_mmap returns page aligned addresses */
	rseq_abi_pointer = (unsigned long)addr;
	rseq_abi_size = (unsigned long)sizeof(struct criu_rseq);
	/* it's not so important to have unique signature for us,
	 * because rseq_abi_pointer is guaranteed to be unique
	 */
	rseq_signature = 0x12345612;

	pr_info("\ttrying sys_rseq(%lx, %lx, %x, %x)\n", rseq_abi_pointer, rseq_abi_size, 0, rseq_signature);
	ret = sys_rseq((void *)rseq_abi_pointer, rseq_abi_size, 0, rseq_signature);
	if (ret) {
		if (ret == -EINVAL) {
			pr_info("\trseq is initialized in the victim\n");
			rseq->rseq_inited = true;

			ret = 0;
		} else {
			pr_err("\tunexpected failure of sys_rseq(%lx, %lx, %x, %x) = %d\n", rseq_abi_pointer,
			       rseq_abi_size, 0, rseq_signature, ret);

			ret = -1;
		}
	} else {
		ret = sys_rseq((void *)rseq_abi_pointer, sizeof(struct criu_rseq), RSEQ_FLAG_UNREGISTER,
			       rseq_signature);
		if (ret) {
			pr_err("\tfailed to unregister sys_rseq(%lx, %lx, %x, %x) = %d\n", rseq_abi_pointer,
			       rseq_abi_size, RSEQ_FLAG_UNREGISTER, rseq_signature, ret);

			ret = -1;
			/* we can't do munmap() because rseq is registered and we failed to unregister it */
			goto out_nounmap;
		}

		rseq->rseq_inited = false;
		ret = 0;
	}

	sys_munmap(addr, sizeof(struct criu_rseq));
out_nounmap:
	return ret;
}

static int fill_fds_fown(int fd, struct fd_opts *p)
{
	int flags, ret;
	struct f_owner_ex owner_ex;
	uint32_t v[2];

	/*
	 * For O_PATH opened files there is no owner at all.
	 */
	flags = sys_fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		pr_err("fcntl(%d, F_GETFL) -> %d\n", fd, flags);
		return -1;
	}
	if (flags & O_PATH) {
		p->fown.pid = 0;
		return 0;
	}

	ret = sys_fcntl(fd, F_GETOWN_EX, (long)&owner_ex);
	if (ret) {
		pr_err("fcntl(%d, F_GETOWN_EX) -> %d\n", fd, ret);
		return -1;
	}

	/*
	 * Simple case -- nothing is changed.
	 */
	if (owner_ex.pid == 0) {
		p->fown.pid = 0;
		return 0;
	}

	ret = sys_fcntl(fd, F_GETOWNER_UIDS, (long)&v);
	if (ret) {
		pr_err("fcntl(%d, F_GETOWNER_UIDS) -> %d\n", fd, ret);
		return -1;
	}

	p->fown.uid = v[0];
	p->fown.euid = v[1];
	p->fown.pid_type = owner_ex.type;
	p->fown.pid = owner_ex.pid;

	return 0;
}

static int fill_fds_opts(struct parasite_drain_fd *fds, struct fd_opts *opts)
{
	int i;

	for (i = 0; i < fds->nr_fds; i++) {
		int flags, fd = fds->fds[i];
		struct fd_opts *p = opts + i;

		flags = sys_fcntl(fd, F_GETFD, 0);
		if (flags < 0) {
			pr_err("fcntl(%d, F_GETFD) -> %d\n", fd, flags);
			return -1;
		}

		p->flags = (char)flags;

		if (fill_fds_fown(fd, p))
			return -1;
	}

	return 0;
}

static int drain_fds(struct parasite_drain_fd *args)
{
	int ret, tsock;
	struct fd_opts *opts;

	/*
	 * See the drain_fds_size() in criu code, the memory
	 * for this args is ensured to be large enough to keep
	 * an array of fd_opts at the tail.
	 */
	opts = ((void *)args) + sizeof(*args) + args->nr_fds * sizeof(args->fds[0]);
	ret = fill_fds_opts(args, opts);
	if (ret)
		return ret;

	tsock = parasite_get_rpc_sock();
	ret = send_fds(tsock, NULL, 0, args->fds, args->nr_fds, opts, sizeof(struct fd_opts));
	if (ret)
		pr_err("send_fds failed (%d)\n", ret);

	return ret;
}

static int dump_thread(struct parasite_dump_thread *args)
{
	args->tid = sys_gettid();
	return dump_thread_common(args);
}

static char proc_mountpoint[] = "proc.crtools";

static int pie_atoi(char *str)
{
	int ret = 0;

	while (*str) {
		ret *= 10;
		ret += *str - '0';
		str++;
	}

	return ret;
}

static int get_proc_fd(void)
{
	int ret;
	char buf[11];

	ret = sys_readlinkat(AT_FDCWD, "/proc/self", buf, sizeof(buf) - 1);
	if (ret < 0 && ret != -ENOENT) {
		pr_err("Can't readlink /proc/self (%d)\n", ret);
		return ret;
	}
	if (ret > 0) {
		buf[ret] = 0;

		/* Fast path -- if /proc belongs to this pidns */
		if (pie_atoi(buf) == sys_getpid())
			return sys_open("/proc", O_RDONLY, 0);
	}

	ret = sys_mkdir(proc_mountpoint, 0700);
	if (ret) {
		pr_err("Can't create a directory (%d)\n", ret);
		return -1;
	}

	ret = sys_mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL);
	if (ret) {
		if (ret == -EPERM)
			pr_err("can't dump unprivileged task whose /proc doesn't belong to it\n");
		else
			pr_err("mount failed (%d)\n", ret);
		sys_rmdir(proc_mountpoint);
		return -1;
	}

	return open_detach_mount(proc_mountpoint);
}

static int parasite_get_proc_fd(void)
{
	int fd, ret, tsock;

	fd = get_proc_fd();
	if (fd < 0) {
		pr_err("Can't get /proc fd\n");
		return -1;
	}

	tsock = parasite_get_rpc_sock();
	ret = send_fd(tsock, NULL, 0, fd);
	sys_close(fd);
	return ret;
}

static inline int tty_ioctl(int fd, int cmd, int *arg)
{
	int ret;

	ret = sys_ioctl(fd, cmd, (unsigned long)arg);
	if (ret < 0) {
		if (ret != -ENOTTY)
			return ret;
		*arg = 0;
	}
	return 0;
}

/*
 * Stolen from kernel/fs/aio.c
 *
 * Is it valid to go to memory and check it? Should be,
 * as libaio does the same.
 */

#define AIO_RING_MAGIC		   0xa10a10a1
#define AIO_RING_COMPAT_FEATURES   1
#define AIO_RING_INCOMPAT_FEATURES 0

static int sane_ring(struct parasite_aio *aio)
{
	struct aio_ring *ring = (struct aio_ring *)aio->ctx;
	unsigned nr;

	nr = (aio->size - sizeof(struct aio_ring)) / sizeof(struct io_event);

	return ring->magic == AIO_RING_MAGIC && ring->compat_features == AIO_RING_COMPAT_FEATURES &&
	       ring->incompat_features == AIO_RING_INCOMPAT_FEATURES &&
	       ring->header_length == sizeof(struct aio_ring) && ring->nr == nr;
}

static int parasite_check_aios(struct parasite_check_aios_args *args)
{
	int i;

	for (i = 0; i < args->nr_rings; i++) {
		struct aio_ring *ring;

		ring = (struct aio_ring *)args->ring[i].ctx;
		if (!sane_ring(&args->ring[i])) {
			pr_err("Not valid ring #%d\n", i);
			pr_info(" `- magic %x\n", ring->magic);
			pr_info(" `- cf    %d\n", ring->compat_features);
			pr_info(" `- if    %d\n", ring->incompat_features);
			pr_info(" `- header size  %d (%zd)\n", ring->header_length, sizeof(struct aio_ring));
			pr_info(" `- nr    %d\n", ring->nr);
			return -1;
		}

		/* XXX: wait aio completion */
	}

	return 0;
}

static int parasite_dump_tty(struct parasite_tty_args *args)
{
	int ret;

#ifndef TIOCGPKT
#define TIOCGPKT _IOR('T', 0x38, int)
#endif

#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif

#ifndef TIOCGEXCL
#define TIOCGEXCL _IOR('T', 0x40, int)
#endif

	args->sid = 0;
	args->pgrp = 0;
	args->st_pckt = 0;
	args->st_lock = 0;
	args->st_excl = 0;

#define __tty_ioctl(cmd, arg)                         \
	do {                                          \
		ret = tty_ioctl(args->fd, cmd, &arg); \
		if (ret < 0) {                        \
			if (ret == -ENOTTY)           \
				arg = 0;              \
			else if (ret == -EIO)         \
				goto err_io;          \
			else                          \
				goto err;             \
		}                                     \
	} while (0)

	__tty_ioctl(TIOCGSID, args->sid);
	__tty_ioctl(TIOCGPGRP, args->pgrp);
	__tty_ioctl(TIOCGEXCL, args->st_excl);

	if (args->type == TTY_TYPE__PTY) {
		__tty_ioctl(TIOCGPKT, args->st_pckt);
		__tty_ioctl(TIOCGPTLCK, args->st_lock);
	}

	args->hangup = false;
	return 0;

err:
	pr_err("tty: Can't fetch params: err = %d\n", ret);
	return -1;
err_io:

	/* kernel reports EIO for get ioctls on pair-less ptys */
	pr_debug("tty: EIO on tty\n");
	args->hangup = true;
	return 0;
#undef __tty_ioctl
}

static int parasite_check_vdso_mark(struct parasite_vdso_vma_entry *args)
{
	struct vdso_mark *m = (void *)args->start;

	if (is_vdso_mark(m)) {
		/*
		 * Make sure we don't meet some corrupted entry
		 * where signature matches but versions do not!
		 */
		if (m->version != VDSO_MARK_CUR_VERSION) {
			pr_err("vdso: Mark version mismatch!\n");
			return -EINVAL;
		}
		args->is_marked = 1;
		args->orig_vdso_addr = m->orig_vdso_addr;
		args->orig_vvar_addr = m->orig_vvar_addr;
		args->rt_vvar_addr = m->rt_vvar_addr;
	} else {
		args->is_marked = 0;
		args->orig_vdso_addr = VDSO_BAD_ADDR;
		args->orig_vvar_addr = VVAR_BAD_ADDR;
		args->rt_vvar_addr = VVAR_BAD_ADDR;

		if (args->try_fill_symtable) {
			struct vdso_symtable t;

			if (vdso_fill_symtable(args->start, args->len, &t))
				args->is_vdso = false;
			else
				args->is_vdso = true;
		}
	}

	return 0;
}

static int parasite_dump_cgroup(struct parasite_dump_cgroup_args *args)
{
	int proc, cgroup, len;

	proc = get_proc_fd();
	if (proc < 0) {
		pr_err("can't get /proc fd\n");
		return -1;
	}

	cgroup = sys_openat(proc, args->thread_cgrp, O_RDONLY, 0);
	sys_close(proc);
	if (cgroup < 0) {
		pr_err("can't get /proc/self/cgroup fd\n");
		sys_close(cgroup);
		return -1;
	}

	len = sys_read(cgroup, args->contents, sizeof(args->contents));
	sys_close(cgroup);
	if (len < 0) {
		pr_err("can't read /proc/self/cgroup %d\n", len);
		return -1;
	}

	if (len == sizeof(args->contents)) {
		pr_warn("/proc/self/cgroup was bigger than the page size\n");
		return -1;
	}

	/* null terminate */
	args->contents[len] = 0;
	return 0;
}

void parasite_cleanup(void)
{
	if (mprotect_args) {
		mprotect_args->add_prot = 0;
		mprotect_vmas(mprotect_args);
	}
}

int parasite_daemon_cmd(int cmd, void *args)
{
	int ret;

	switch (cmd) {
	case PARASITE_CMD_DUMPPAGES:
		ret = dump_pages(args);
		break;
	case PARASITE_CMD_MPROTECT_VMAS:
		ret = mprotect_vmas(args);
		break;
	case PARASITE_CMD_DUMP_SIGACTS:
		ret = dump_sigact(args);
		break;
	case PARASITE_CMD_DUMP_ITIMERS:
		ret = dump_itimers(args);
		break;
	case PARASITE_CMD_DUMP_POSIX_TIMERS:
		ret = dump_posix_timers(args);
		break;
	case PARASITE_CMD_DUMP_THREAD:
		ret = dump_thread(args);
		break;
	case PARASITE_CMD_DUMP_MISC:
		ret = dump_misc(args);
		break;
	case PARASITE_CMD_DRAIN_FDS:
		ret = drain_fds(args);
		break;
	case PARASITE_CMD_GET_PROC_FD:
		ret = parasite_get_proc_fd();
		break;
	case PARASITE_CMD_DUMP_TTY:
		ret = parasite_dump_tty(args);
		break;
	case PARASITE_CMD_CHECK_AIOS:
		ret = parasite_check_aios(args);
		break;
	case PARASITE_CMD_CHECK_VDSO_MARK:
		ret = parasite_check_vdso_mark(args);
		break;
	case PARASITE_CMD_DUMP_CGROUP:
		ret = parasite_dump_cgroup(args);
		break;
	case PARASITE_CMD_DSA_COPY:
		ret = parasite_dsa_copy(args);
		break;
	default:
		pr_err("Unknown command in parasite daemon thread leader: %d\n", cmd);
		ret = -1;
		break;
	}

	return ret;
}

int parasite_trap_cmd(int cmd, void *args)
{
	switch (cmd) {
	case PARASITE_CMD_DUMP_THREAD:
		return dump_thread(args);
	}

	pr_err("Unknown command to parasite: %d\n", cmd);
	return -EINVAL;
}
