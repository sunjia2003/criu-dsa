"""Compile actual worker/classifier/emitter code against deterministic page states."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HostScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='dsa-host-scan-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        mem = (ROOT / 'criu/mem.c').read_text()
        begin = mem.index('/* Experimental: read-only classification')
        end = mem.index('static int generate_vma_iovs_dsa_desc_scan(', begin)
        production = mem[begin:end]
        # Smaller blocks exercise many transitions and short tails quickly.
        production = production.replace('(2U * 1024U * 1024U)', '(8U * 4096U)')
        fixture = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include "dsa-host-scan.h"
#include "dsa-host-prefetch.h"
#include "dsa-host-perf.h"
#include "common/list.h"
typedef uint64_t u64;
typedef uint32_t u32;
#define PAGE_SIZE 4096UL
#define PPB_LAZY 1
#define PP_HOLE_PARENT 2
#define PROT_READ 1
#define MAP_HUGETLB 2
#define MAP_DROPPABLE 4
#define VMA_AREA_REGULAR 1
#define VMA_ANON_PRIVATE 2
#define VMA_AREA_VVAR 4
#define VMA_AREA_GUARD 8
#define CNT_PAGES_SCANNED 0
#define CNT_PAGES_SKIPPED_PARENT 1
#define CNT_PAGES_LAZY 2
#define CNT_PAGES_WRITTEN 3
#define xmalloc malloc
#define xzalloc(n) calloc(1,n)
#define xfree free
#define pr_info(...) ((void)0)
typedef struct { u64 start,end; u32 flags,prot,kind; } VmaEntry;
struct vma_area { VmaEntry *e; struct list_head list; };
typedef struct { u64 start,end; } pmc_t;
struct pstree_item { struct { int real; } *pid; };
struct page_info { u64 next; bool softdirty; };
struct record { u64 address; u32 action,flags; };
struct page_pipe { struct record output[4096]; u32 count; };
struct dsa_desc_scan_ctx { u64 scan_pages,scan_hole_pages,scan_lazy_pages,scan_dump_pages; u32 copies; };
static struct { bool lazy_pages; } opts;
static struct { u64 task_size; } kdat = { .task_size = UINT64_MAX };
static int dsa_parent_coverage_prev, forced_error, delayed, sparse_mode;
static bool spin_enabled, cross_enabled, use_barrier;
static u32 prefetch_depth;
static pthread_barrier_t cross_barrier;
static u64 counters[4];
static u64 dsa_wall_now_us(void) { return 1; }
static u64 dsa_wall_delta_us(u64 a,u64 b) { return b-a; }
static u32 dsa_parse_env_u32(const char *name,u32 value,u32 low,u32 high) {
    (void)low;(void)high;
    return !strcmp(name,"CRIU_DSA_HOST_SCAN_PREFETCH_DEPTH") ? prefetch_depth:value;
}
static bool dsa_env_enabled(const char *name) {
    return (!strcmp(name,"CRIU_DSA_HOST_SCAN_SPIN") && spin_enabled) ||
           (!strcmp(name,"CRIU_DSA_HOST_SCAN_CROSS_VMA") && cross_enabled);
}
static void cnt_add(int c,u64 value) { counters[c]+=value; }
static int pmc_init(pmc_t *p,int pid,const struct list_head *h,size_t size) {
    (void)pid;(void)h;(void)size;memset(p,0,sizeof(*p));return 0;
}
static void pmc_fini(pmc_t *p) { (void)p; }
static int pmc_fill(pmc_t *p,u64 start,u64 end) {
    p->start=start;p->end=end;
    if(use_barrier && (start==4096 || start==17*4096))
        pthread_barrier_wait(&cross_barrier);
    if(delayed && ((start/4096)/8)%2==1)usleep(500);
    return forced_error ? -1:0;
}
static bool vma_entry_is(VmaEntry *e,u32 kind) { return (e->kind&kind)!=0; }
static bool vma_area_is_private(struct vma_area *v,u64 size) { return v->e->end<=size; }
static bool should_dump_entire_vma(VmaEntry *e) { (void)e;return false; }
static bool vma_entry_can_be_lazy(VmaEntry *e) { (void)e;return true; }
static bool is_stack(struct pstree_item *item,u64 address) { (void)item;return address/4096%17==0; }
static bool page_in_parent(bool dirty) { return !dirty; }
static bool dsa_parent_coverage_contains_range(void *cov,u64 address,u64 length) {
    (void)cov;(void)length;return address/4096%5!=0;
}
static int should_dump_page(pmc_t *p,VmaEntry *e,u64 address,struct page_info *info) {
    if(address>=p->end && pmc_fill(p,address,e->end))return -1;
    u64 number=address/4096;
    if(sparse_mode==2) { info->next=e->end;return 0; }
    if(sparse_mode==1 && number%32<24) {
        info->next=min((number/32*32+24)*4096,e->end);return 0;
    }
    info->next=number%7==0 ? address+4096:address;
    info->softdirty=number%3==0;return 0;
}
static int page_pipe_add_hole(struct page_pipe *p,u64 address,u32 flags) {
    (void)flags;p->output[p->count++]=(struct record){address,1,0};return 0;
}
static int page_pipe_add_page_unbounded(struct page_pipe *p,u64 address,u32 flags) {
    p->output[p->count++]=(struct record){address,2,flags};return 0;
}
static int dsa_desc_scan_batch_append(struct dsa_desc_scan_ctx *sc,u64 address,u32 size) {
    (void)address;assert(size==4096);sc->copies++;return 0;
}
static int increment(void *context) { usleep(100);(*(int *)context)++;return 0; }
__PRODUCTION__
static void check_cross_vmas(int scenario) {
    cross_enabled=true;spin_enabled=scenario%2;
    prefetch_depth=scenario>=22 ? (scenario>=26 ? 2:8):0;
    sparse_mode=scenario==18 || scenario==19 || scenario==24 || scenario==25 ? 1:0;
    for(u32 count=1;count<=2;count++) {
        struct { int real; } pid={42};
        struct pstree_item item={.pid=(void *)&pid};
        LIST_HEAD(head);
        struct dsa_host_scan *scan=NULL;
        VmaEntry entries[6]={0};struct vma_area vmas[6]={0};
        const u32 sizes[]={3,19,1,5,25,2};u64 next=4096;
        for(u32 i=0;i<6;i++) {
            u32 n=scenario<=15 ? (i%4+1):sizes[i];
            if(i==0)n=3;
            entries[i]=(VmaEntry){.start=next,.end=next+n*4096UL,.prot=PROT_READ,
                         .kind=VMA_AREA_REGULAR|VMA_ANON_PRIVATE};
            if(i==3)entries[i].kind=VMA_AREA_VVAR;
            next=entries[i].end+13*4096UL;
            vmas[i].e=&entries[i];list_add_tail(&vmas[i].list,&head);
        }
        struct page_pipe a={0},b={0};struct dsa_desc_scan_ctx sa={0},sb={0};
        pmc_t pmc={0};bool parent=scenario!=16;
        for(u32 i=0;i<6;i++) {
            u64 address=entries[i].start;
            assert(!generate_iovs_dsa_desc_scan(&item,&vmas[i],&a,&pmc,&address,parent,&sa));
        }
        assert(!dsa_host_scan_init(&scan,&item,&head,count));
        /* First two small VMAs must run concurrently, not merely in two threads. */
        use_barrier=count==2 && (scenario<=15 || scenario==22 || scenario==23);
        if(use_barrier)assert(!pthread_barrier_init(&cross_barrier,NULL,2));
        delayed=scenario==17 || scenario==19;
        forced_error=scenario==20 || scenario==21 || scenario==28 || scenario==29;
        for(u32 i=0;i<6;i++) {
            int ret;
            if(dsa_host_scan_eligible(&vmas[i]))
                ret=dsa_host_scan_vma(scan,&vmas[i],&b,parent,&sb);
            else {
                u64 address=entries[i].start;
                ret=generate_iovs_dsa_desc_scan(&item,&vmas[i],&b,&pmc,&address,parent,&sb);
            }
            if(forced_error) { assert(ret<0);break; }
            assert(!ret);
        }
        dsa_host_scan_fini(scan);
        if(use_barrier)pthread_barrier_destroy(&cross_barrier);
        use_barrier=false;forced_error=0;
        if(scenario==20 || scenario==21 || scenario==28 || scenario==29)continue;
        assert(a.count==b.count);
        assert(!memcmp(a.output,b.output,a.count*sizeof(a.output[0])));
        assert(sa.copies==sb.copies && sa.scan_hole_pages==sb.scan_hole_pages &&
               sa.scan_lazy_pages==sb.scan_lazy_pages && sa.scan_dump_pages==sb.scan_dump_pages);
    }
}
int main(int argc,char **argv) {
    assert(argc==2);
    const int scenario=atoi(argv[1]);
    if(scenario>=14) { check_cross_vmas(scenario);return 0; }
    if(scenario==8 || scenario==9) {
        struct dsa_host_job job={0};int value=0;
        assert(!dsa_host_job_init(&job,increment,&value,scenario==9));
        assert(!dsa_host_job_submit(&job));
        assert(dsa_host_job_submit(&job)==-EBUSY);
        assert(!dsa_host_job_wait(&job) && value==1);
        assert(dsa_host_job_submit(&job)==-EBUSY);
        dsa_host_job_release(&job);value=5;
        assert(!dsa_host_job_submit(&job));assert(!dsa_host_job_wait(&job) && value==6);
        dsa_host_job_release(&job);dsa_host_job_fini(&job);return 0;
    }
    spin_enabled=(scenario>=4 && scenario<=9) || scenario>=12;
    sparse_mode=scenario>=10 ? (scenario%2 ? 2:1):0;
    for(u32 count=1;count<=2;count++) {
        struct { int real; } pid={42};
        struct pstree_item item={.pid=(void *)&pid};
        LIST_HEAD(head);
        struct dsa_host_scan *scan=NULL;
        assert(!dsa_host_scan_init(&scan,&item,&head,count));
        for(u32 n=1;n<=257;n+=scenario==0?1:17) {
            VmaEntry entry={.start=4096,.end=(n+1UL)*4096,.prot=PROT_READ,
                            .kind=VMA_AREA_REGULAR|VMA_ANON_PRIVATE};
            struct vma_area vma={.e=&entry};
            struct page_pipe a={0},b={0};
            struct dsa_desc_scan_ctx sa={0},sb={0};
            pmc_t pmc={0};u64 address=entry.start;
            opts.lazy_pages=scenario%2;delayed=scenario%4==1;
            bool parent=scenario!=2;
            assert(dsa_host_scan_eligible(&vma));
            assert(!generate_iovs_dsa_desc_scan(&item,&vma,&a,&pmc,&address,parent,&sa));
            assert(!dsa_host_scan_vma(scan,&vma,&b,parent,&sb));
            assert(a.count==b.count);
            assert(!memcmp(a.output,b.output,a.count*sizeof(a.output[0])));
            assert(sa.copies==sb.copies && sa.scan_hole_pages==sb.scan_hole_pages &&
                   sa.scan_lazy_pages==sb.scan_lazy_pages && sa.scan_dump_pages==sb.scan_dump_pages);
        }
        if(scenario%4==3) {
            VmaEntry entry={.start=4096,.end=40*4096,.prot=PROT_READ};
            struct vma_area vma={.e=&entry};struct page_pipe pp={0};struct dsa_desc_scan_ctx sc={0};
            forced_error=1;assert(dsa_host_scan_vma(scan,&vma,&pp,true,&sc)<0);
            /* Match production: all workers join before the VMA owner goes away. */
            dsa_host_scan_fini(scan);scan=NULL;
        }
        dsa_host_scan_fini(scan);forced_error=0;
    }
    return 0;
}
'''
        source = directory / 'check.c'
        source.write_text(fixture.replace('__PRODUCTION__', production))
        cls.binary = directory / 'check'
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        *shlex.split(os.environ.get('DSA_HOST_SCAN_TEST_CFLAGS', '')),
                        '-pthread', '-iquote', str(ROOT/'criu/include'), '-iquote', str(ROOT/'include'),
                        str(source), '-o', str(cls.binary)], check=True)

    def check(self, scenario):
        subprocess.run([str(self.binary), str(scenario)], check=True, timeout=20)

    def test_scalar_and_worker_actions_match_across_block_boundaries(self): self.check(0)
    def test_delayed_odd_blocks_preserve_order_and_lazy_flags(self): self.check(1)
    def test_no_parent_capture_matches_scalar(self): self.check(2)
    def test_worker_error_aborts_and_joins(self): self.check(3)
    def test_spin_handoff_matches_scalar(self): self.check(4)
    def test_spin_delayed_odd_blocks_preserve_order(self): self.check(5)
    def test_spin_worker_error_aborts_and_joins(self): self.check(7)
    def test_condition_result_cannot_be_overwritten_before_release(self): self.check(8)
    def test_spin_result_cannot_be_overwritten_before_release(self): self.check(9)
    def test_sparse_results_skip_long_empty_regions(self): self.check(10)
    def test_condition_empty_results_advance_to_the_next_block(self): self.check(11)
    def test_spin_sparse_results_preserve_addresses(self): self.check(12)
    def test_spin_empty_results_advance_to_the_next_block(self): self.check(13)
    def test_cross_vma_small_jobs_overlap_with_condition(self): self.check(14)
    def test_cross_vma_small_jobs_overlap_with_spin(self): self.check(15)
    def test_cross_vma_mixed_blocks_and_scalar_fallback(self): self.check(16)
    def test_cross_vma_delayed_results_keep_address_order(self): self.check(17)
    def test_cross_vma_sparse_condition_matches_scalar(self): self.check(18)
    def test_cross_vma_sparse_spin_matches_scalar(self): self.check(19)
    def test_cross_vma_error_joins_prefetched_condition_job(self): self.check(20)
    def test_cross_vma_error_joins_prefetched_spin_job(self): self.check(21)
    def test_prefetch_workers_advance_before_ordered_consumption(self): self.check(22)
    def test_prefetch_spin_preserves_cross_vma_order(self): self.check(23)
    def test_prefetch_sparse_condition_preserves_actions(self): self.check(24)
    def test_prefetch_sparse_spin_preserves_actions(self): self.check(25)
    def test_prefetch_two_slots_wrap_without_overwriting(self): self.check(26)
    def test_prefetch_two_slots_spin_preserves_order(self): self.check(27)
    def test_prefetch_error_joins_all_condition_workers(self): self.check(28)
    def test_prefetch_error_joins_all_spin_workers(self): self.check(29)


if __name__ == '__main__':
    unittest.main()
