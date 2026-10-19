"""Exercise the production bounded queue without requiring DSA hardware."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PrefetchQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='dsa-prefetch-')
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        source = directory/'check.c'
        source.write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
static void dsa_host_relax(void) { __asm__ __volatile__("pause" ::: "memory"); }
#include "dsa-host-prefetch.h"
struct result { uint64_t before, value, after; };
struct context { unsigned int count[1024], produced; int mode; };
static int classify(void *data,unsigned int worker,uint64_t seq,void *output) {
    struct context *ctx=data;struct result *result=output;
    (void)worker;
    assert(seq<1024 && result->before==0x1234 && result->after==0x5678);
    if(ctx->mode==3 && seq==17)return -EIO;
    if(ctx->mode==1 && seq%7==0)usleep(100);
    assert(__atomic_add_fetch(&ctx->count[seq],1,__ATOMIC_RELAXED)==1);
    result->value=seq*19+3;
    __atomic_add_fetch(&ctx->produced,1,__ATOMIC_RELEASE);
    return 0;
}
int main(int argc,char **argv) {
    assert(argc==2);int mode=atoi(argv[1]);int full_spin=mode>=5;
    if(full_spin)mode=mode==5?1:mode==6?2:3;
    for(unsigned int spin=0;spin<2;spin++)for(unsigned int workers=1;workers<=2;workers++)
    for(unsigned int depth=2;depth<=8;depth*=2) {
        struct dsa_prefetch pool={0};struct context ctx={.mode=mode};
        pool.spin_limit=full_spin?UINT_MAX:0;
        struct result results[8];void *data[8];unsigned int tasks=mode==4?1:257;
        for(unsigned int i=0;i<depth;i++) {
            results[i]=(struct result){.before=0x1234,.after=0x5678};data[i]=&results[i];
        }
        assert(!dsa_prefetch_init(&pool,workers,depth,tasks,data,&ctx,classify,spin));
        if(mode==0 || mode==2) {
            unsigned int tries;
            for(tries=0;tries<2000 && __atomic_load_n(&ctx.produced,__ATOMIC_ACQUIRE)<depth;tries++)usleep(100);
            assert(tries<2000 && pool.consumed==0);
            /* All window slots filled before consuming any result. */
            for(unsigned int i=0;i<depth;i++)assert(ctx.count[i]==1);
        }
        if(mode==2) { dsa_prefetch_fini(&pool);continue; }
        int error=0;
        for(unsigned int seq=0;seq<tasks;seq++) {
            void *output;int ret=dsa_prefetch_wait(&pool,seq,&output);
            if(ret) { error=ret;break; }
            struct result *result=output;
            assert(result->value==seq*19+3 && result->before==0x1234 && result->after==0x5678);
            if(mode==1 && seq%11==0)usleep(50);
            dsa_prefetch_release(&pool,seq);
        }
        dsa_prefetch_fini(&pool);
        if(mode==3)assert(error==-EIO);
        else { assert(!error);for(unsigned int i=0;i<tasks;i++)assert(ctx.count[i]==1); }
    }
    return 0;
}
''')
        cls.binary = directory/'check'
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-pthread',
                        *shlex.split(os.environ.get('DSA_HOST_SCAN_TEST_CFLAGS','')),
                        '-iquote',str(ROOT/'criu/include'),str(source),'-o',str(cls.binary)],check=True)

    def check(self, scenario):
        subprocess.run([str(self.binary),str(scenario)],check=True,timeout=20)

    def test_producers_fill_bounded_window_without_main_handoffs(self): self.check(0)
    def test_reordering_and_slow_consumer_preserve_every_ticket(self): self.check(1)
    def test_cancellation_joins_workers_blocked_by_a_full_window(self): self.check(2)
    def test_error_releases_consumer_and_joins_other_worker(self): self.check(3)
    def test_single_task_and_idle_second_worker(self): self.check(4)
    def test_full_spin_reordering_and_slow_consumer(self): self.check(5)
    def test_full_spin_cancellation_while_window_is_full(self): self.check(6)
    def test_full_spin_error_unblocks_consumer(self): self.check(7)


if __name__ == '__main__':
    unittest.main()
