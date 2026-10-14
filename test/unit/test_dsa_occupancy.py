"""Exercise the production scan/intake snippets and compare the old exact sum."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class OccupancyTests(unittest.TestCase):
    def test_folded_count_matches_old_scan_after_completion_retry_and_intake(self):
        text=(ROOT/'criu/pie/parasite.c').read_text()
        body=text[text.index('static int dsa_stream_consume_hw_runway('):
                  text.index('static int dsa_legacy_single_rpc_consume(')]
        first=body[body.index('\t\tfor (i = 0; i < DSA_HW_BATCH_OUTER_DEPTH; i++) {'):
                   body.index('\t\twhile (retire_seq < accept_seq)')]
        intake=body[body.index('\t\twhile (accept_seq < produced) {'):
                    body.index('\t\t/* finish is the producer')]
        code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define DSA_HW_BATCH_OUTER_DEPTH 128
#define DSA_PIPELINE_HARVEST 5
#define DSA_FLOW_COMPLETE_OBSERVED 14
struct dsa_pipeline_scope { int unused; };
struct { u64 last_ns; } *dsa_pipeline;
struct batch { u32 active, child_count, poll_count, owner_seq; struct { u32 id,child_count; } pipeline; };
static struct batch dsa_raw_stream_batches[128];
static u64 dsa_copy_batch_bytes[128];
static int ready[128], result[128];
struct args { int failed_idx,op_ret; u32 raw_faults,batch_enq_retries,batch_max_active_outer,batch_max_active_children; };
struct parasite_dsa_stream_slot { u32 desc_count; };
struct hdr { u32 slot_count; };
static struct dsa_pipeline_scope dsa_pipeline_enter(int phase) {(void)phase;return (struct dsa_pipeline_scope){0};}
static void dsa_pipeline_resume(struct dsa_pipeline_scope scope) {(void)scope;}
static void dsa_flow_cons_event(int kind,...) {(void)kind;}
static void dsa_pipeline_record_batch(struct batch *batch,u64 observed) {(void)batch;(void)observed;}
static int dsa_raw_stream_batch_ready(u32 i) {return ready[i];}
static int dsa_raw_stream_batch_harvest(struct args *a,u32 i,...) {
  (void)a;
  if (result[i] == 1) dsa_raw_stream_batches[i].active=0;
  if (result[i] == 0) dsa_raw_stream_batches[i].child_count=(dsa_raw_stream_batches[i].child_count+1)/2;
  return result[i];
}
static int dsa_raw_stream_accept_slot(struct args *a,void *memory,struct hdr *hdr,
                                    struct parasite_dsa_stream_slot *slots,u32 seq,u32 *active,...) {
  (void)a;(void)memory;
  u32 children=slots[seq%hdr->slot_count].desc_count;
  u32 available=0;
  for (u32 i=0;i<128;i++) if (!dsa_raw_stream_batches[i].active) available++;
  if (available < (children+31)/32) return 0;
  for (u32 i=0;i<128 && children;i++) if (!dsa_raw_stream_batches[i].active) {
    u32 count=children>32?32:children;
    dsa_raw_stream_batches[i].active=1;dsa_raw_stream_batches[i].child_count=count;
    (*active)++;children-=count;
  }
  return 1;
}
static u32 seed=42;
static u32 random_value(void) {seed=seed*1664525U+1013904223U;return seed;}
static void run_case(void) {
  struct args output={0},*a=&output;
  struct hdr header={.slot_count=4},*hdr=&header;
  struct parasite_dsa_stream_slot slots[4]={{1},{32},{64},{128}};
  u32 i,active_children=0,active_outer=0,active_wq_count=0;
  u32 *active_wq_idx=0;u64 *active_wq_load=0;
  int *use_portal=0;unsigned long *portal_mask=0,*portal_offset=0;
  void *shared_buf=0;
  u32 accepted_descs=0,accept_seq=0,produced=4,blocked=0;
  bool progressed=false;
  for (i=0;i<128;i++) {
    dsa_raw_stream_batches[i]=(struct batch){.active=(random_value()>>16)%2,.child_count=(random_value()>>16)%32+1};
    ready[i]=(random_value()>>16)%2;result[i]=(random_value()>>16)%2;
    active_outer+=dsa_raw_stream_batches[i].active;
  }
__FIRST__
__INTAKE__
  u32 reference=0,active_reference=0;
  for (i=0;i<128;i++) if (dsa_raw_stream_batches[i].active) {
    reference+=dsa_raw_stream_batches[i].child_count;active_reference++;
  }
  assert(active_children == reference && a->batch_max_active_children == reference);
  assert(active_outer == active_reference);
  (void)accepted_descs;(void)blocked;(void)progressed;
  return;
fail:
  assert(0);
}
int main(void) {for (unsigned i=0;i<10000;i++) run_case();return 0;}
'''.replace('__FIRST__',first).replace('__INTAKE__',intake)
        with tempfile.TemporaryDirectory(prefix='dsa-occupancy-') as temporary:
            source=Path(temporary)/'occupancy.c';binary=Path(temporary)/'occupancy'
            source.write_text(code)
            subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True)

    def test_runway_has_only_one_full_management_scan(self):
        text=(ROOT/'criu/pie/parasite.c').read_text()
        body=text[text.index('static int dsa_stream_consume_hw_runway('):
                  text.index('static int dsa_legacy_single_rpc_consume(')]
        iteration=body[:body.index('\t\t/* finish is the producer')]
        self.assertEqual(iteration.count('for (i = 0; i < DSA_HW_BATCH_OUTER_DEPTH; i++)'),1)
        self.assertIn('1000000U',body)
        self.assertIn('a->batch_max_active_children = active_children;',body)


if __name__ == '__main__':
    unittest.main()
