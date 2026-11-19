#!/usr/bin/env python3
"""Compare explicitly planned suites with shared native-stat/archive parsing."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys

WORKSPACE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WORKSPACE/'cdp'))
from scripts.analyze_checkpoint_probes import collect_suite
from scripts.result_paths import prepare_analysis_dir, analysis_provenance


def mean(values):
    values = list(values)
    return statistics.mean(values) if values and all(v is not None for v in values) else None


def block_overlap(blocks):
    """Intersect measured classifier wall intervals; not worker CPU utilization."""
    total = same = cross = 0
    for index, block in enumerate(blocks):
        begin, end = block['classify_start_us'], block['classify_end_us']
        if end < begin:
            raise ValueError('Backwards classifier block clock')
        total += end-begin
        for other in blocks[:index]:
            overlap = max(0, min(end, other['classify_end_us'])-
                          max(begin, other['classify_start_us']))
            if block['worker'] == other['worker']:
                if overlap:
                    raise ValueError('A worker has overlapping classifier blocks')
            elif block['vma_start'] == other['vma_start']:
                same += overlap
            else:
                cross += overlap
    return {'block_count':len(blocks), 'vma_count':len({b['vma_start'] for b in blocks}),
            'worker_wall_sum_us':total, 'same_vma_overlap_us':same,
            'cross_vma_overlap_us':cross, 'classifier_union_us':total-same-cross}


def block_pipeline(blocks):
    """Readiness and scope overlap; neither is a CPU-utilization measurement."""
    merged = []
    for begin, end in sorted((b['classify_start_us'],b['classify_end_us']) for b in blocks):
        if merged and begin <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1],end)
        else:
            merged.append([begin,end])
    overlap = 0
    ready = []
    previous_end = 0
    for index, block in enumerate(blocks):
        begin,end = block['consume_start_us'],block['consume_end_us']
        if block['sequence'] != index or begin < previous_end or end < begin or block['classify_end_us'] > begin:
            raise ValueError('Invalid ordered consume interval')
        previous_end = end
        ready.append(sum(other['classify_end_us'] <= begin for other in blocks[index:]))
        overlap += sum(max(0,min(end,b)-max(begin,a)) for a,b in merged)
    result = {'ready_blocks_at_consume_max':max(ready,default=0),
            'ready_blocks_at_consume_mean':mean(ready),
            'classifier_and_consumer_scope_overlap_us':overlap,
            'classifier_thread_cpu_sum_us':sum(b['classify_cpu_us'] for b in blocks),
            'observed_worker_cpus':sorted({b['worker_cpu'] for b in blocks})}
    if all('read_cpu_us' in b for b in blocks):
        result['initial_pagemap_fill_cpu_sum_us']=sum(b['read_cpu_us'] for b in blocks)
        result['remaining_classify_cpu_sum_us']=sum(b['classify_cpu_us']-b['read_cpu_us'] for b in blocks)
    if all('cycles' in b for b in blocks) and any(b['cycles'] for b in blocks):
        for key in ('cycles','instructions','perf_enabled_ns','perf_running_ns'):
            result['hardware_'+key+'_sum']=sum(b[key] for b in blocks)
        result['counted_cycles_per_thread_cpu_us']=result['hardware_cycles_sum']/result['classifier_thread_cpu_sum_us']
    return result


def timing_suite(root, out):
    """Explain one task using opt-in block timers, not a performance cohort."""
    data, used = collect_suite(root, WORKSPACE/'cdp/thirdparty/criu-dsa/scripts')
    if len(data['rows']) != 1:
        raise ValueError('Block-timing analysis requires one selected DSA task')
    records = []
    for path in used:
        if Path(path).suffix != '.log': continue
        text = Path(path).read_text().splitlines()
        lines = [s for s in text if 'DSA_HOST_SCAN:' in s]
        if len(lines) != 1: raise ValueError('Missing or ambiguous Host block timers')
        values = {k:int(v) for k,v in re.findall(r'(\w+)=(\d+)', lines[0])}
        if values.get('timing') != 1: raise ValueError('Block timing was not enabled')
        record = {'log':str(path), **values}
        blocks = [{k:int(v) for k,v in re.findall(r'(\w+)=(\d+)', line)}
                  for line in text if 'DSA_HOST_SCAN_BLOCK:' in line]
        if blocks:
            if len(blocks) != values['blocks']:
                raise ValueError('Incomplete block interval trace')
            record.update(block_trace=blocks, overlap=block_overlap(blocks))
            if record['overlap']['worker_wall_sum_us'] != values['worker_us']:
                raise ValueError('Block intervals differ from worker wall accumulator')
            if all('consume_start_us' in block for block in blocks):
                record['pipeline'] = block_pipeline(blocks)
                if record['pipeline']['classifier_thread_cpu_sum_us'] != values['worker_cpu_us']:
                    raise ValueError('Block CPU times differ from accumulator')
                if values.get('prefetch_depth',0) and record['pipeline']['ready_blocks_at_consume_max'] > values['prefetch_depth']:
                    raise ValueError('Measured readiness exceeds bounded window')
        records.append(record)
    samples = data['rows'][0]['checkpoints']
    if len(records) != len(samples): raise ValueError('Incomplete block-timing samples')
    directory = prepare_analysis_dir(out, [root])
    result = {'checkpoints':[s['checkpoint'] for s in samples], 'independent_processes':1,
        'mean_frozen_ms':data['rows'][0]['mean_incremental_frozen_ms'],
        'mean_csv_scan_ms':mean(s['scan_build_us']/1000 for s in samples),
        'mean_block_fields':{key:mean(r[key] for r in records) for key in
            ('worker_us','result_wait_us','emit_us','init_us','scan_build_us','blocks','pages','result_pages')},
        'samples':records,
        'method':'CP2-10, one process. worker_us sums overlapping worker block wall times; wait is main-thread synchronization/result wait, not CPU idle. This diagnostic is excluded from performance cohorts.'}
    if all('overlap' in r for r in records):
        result['mean_block_overlap'] = {key:mean(r['overlap'][key] for r in records)
                                        for key in records[0]['overlap']}
    if all('pipeline' in r for r in records):
        result['mean_block_pipeline'] = {key:mean(r['pipeline'][key] for r in records)
            for key in records[0]['pipeline'] if key != 'observed_worker_cpus'}
        result['observed_worker_cpus'] = sorted({cpu for r in records for cpu in r['pipeline']['observed_worker_cpus']})
    (directory/'timing.json').write_text(json.dumps(result,indent=2))
    provenance = analysis_provenance(used, {'raw':str(root),'out':str(out)},[Path(__file__)])
    (directory/'analysis-manifest.json').write_text(json.dumps(provenance,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='samples'},indent=2))


def probe_batch(root, out):
    """Summarize deterministic restored probes, keeping independent runs distinct."""
    batch_path = root/'batch.json'
    batch = json.loads(batch_path.read_text())
    finished = {r['case']:r for r in batch['results']}
    inputs, rows = [batch_path], []
    for case in batch['plan']['cases']:
        if finished.get(case['name'],{}).get('state') != 'PASSED':
            raise ValueError('Incomplete probe case: '+case['name'])
        path = root/case['name']/'manifest.json'
        trial = json.loads(path.read_text())
        inputs.append(path)
        if trial['state'] != 'PASSED' or trial.get('external_verification',{}).get('byte_errors') != 0:
            raise ValueError('Missing successful external restore oracle')
        samples = [c for c in trial['checkpoints'] if c['checkpoint'] >= 2]
        if not samples:
            raise ValueError('No incremental probe checkpoints')
        for sample in samples:
            metrics = sample['metrics']
            if metrics['frozen_us'] != metrics['frozen_timeline']['stats_frozen_us']:
                raise ValueError('Probe freeze accounting mismatch')
        distribution, label = case['name'].rsplit('-r',1)[0].split('-',1)
        rows.append({'case':case['name'],'distribution':distribution,'condition':label,
                     'frozen_ms':mean(s['metrics']['frozen_us']/1000 for s in samples),
                     'scan_ms':mean(s['metrics']['memdump_timeline']['scan_build_us']/1000 for s in samples),
                     'elf_sha256':trial['criu_sha256'],'environment':trial['environment'],
                     'checkpoints':[s['checkpoint'] for s in samples],
                     'external_checked_bytes':trial['external_verification']['checked_bytes']})
    groups = []
    for distribution, condition in sorted({(r['distribution'],r['condition']) for r in rows}):
        chosen = [r for r in rows if (r['distribution'],r['condition'])==(distribution,condition)]
        groups.append({'distribution':distribution,'condition':condition,'independent_processes':len(chosen),
                       'frozen_ms':mean(r['frozen_ms'] for r in chosen),'scan_ms':mean(r['scan_ms'] for r in chosen)})
    for group in groups:
        base = next(g for g in groups if g['distribution']==group['distribution'] and g['condition']=='base')
        group['frozen_reduction_percent']=100*(base['frozen_ms']-group['frozen_ms'])/base['frozen_ms']
    directory=prepare_analysis_dir(out,[root])
    (directory/'verification.json').write_text(json.dumps({'groups':groups,'processes':rows,
        'method':'Incremental native frozen time; mean within process then across independent processes. All probes actually restored and externally byte-checked.'},indent=2))
    (directory/'analysis-manifest.json').write_text(json.dumps(analysis_provenance(inputs,{'root':str(root)},[Path(__file__)]),indent=2))
    print(json.dumps(groups,indent=2))


def scalar_timing_suite(root, out):
    data,used=collect_suite(root,WORKSPACE/'cdp/thirdparty/criu-dsa/scripts')
    if len(data['rows']) != 1:
        raise ValueError('Scalar diagnostic requires one task')
    records=[]
    for path in used:
        if Path(path).suffix != '.log': continue
        text=Path(path).read_text().splitlines()
        values=[{k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',line)}
                for line in text if 'DSA_HOST_SCALAR:' in line]
        if not values: raise ValueError('Missing scalar timing scopes')
        records.append({'log':str(path),'vmas':len(values),
            **{key:sum(v[key] for v in values) for key in
               ('read_wall_us','read_cpu_us','loop_wall_us','loop_cpu_us')},'scopes':values})
        if all('read_cycles' in v for v in values) and any(v['read_cycles'] for v in values):
            records[-1].update({key:sum(v[key] for v in values) for key in
                ('read_cycles','read_instructions','loop_cycles','loop_instructions','perf_enabled_ns','perf_running_ns')})
    samples=data['rows'][0]['checkpoints']
    if len(records) != len(samples): raise ValueError('Incomplete scalar timing')
    result={'mean_frozen_ms':data['rows'][0]['mean_incremental_frozen_ms'],
        'mean_csv_scan_ms':mean(s['scan_build_us']/1000 for s in samples),
        'mean_scopes':{key:mean(r[key] for r in records) for key in
            ('vmas','read_wall_us','read_cpu_us','loop_wall_us','loop_cpu_us')},'samples':records,
        'method':'One process, CP2-10. Initial pmc_get_map and selection/emission loop CPU/wall scopes; loop may include subsequent pagemap refills. Shmem early returns are not covered. Diagnostic only, not performance cohort.'}
    if all('read_cycles' in r for r in records):
        result['mean_hardware']={key:mean(r[key] for r in records) for key in
            ('read_cycles','read_instructions','loop_cycles','loop_instructions','perf_enabled_ns','perf_running_ns')}
    directory=prepare_analysis_dir(out,[root])
    (directory/'timing.json').write_text(json.dumps(result,indent=2))
    (directory/'analysis-manifest.json').write_text(json.dumps(analysis_provenance(used,{'root':str(root)},[Path(__file__)]),indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='samples'},indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--runs', type=Path)
    parser.add_argument('--timing-suite', type=Path)
    parser.add_argument('--probe-batch', type=Path)
    parser.add_argument('--scalar-timing-suite', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--plot', action='store_true')
    args = parser.parse_args()
    if args.scalar_timing_suite:
        if args.plan or args.runs or args.timing_suite or args.probe_batch or args.plot: parser.error('Scalar timing is separate')
        scalar_timing_suite(args.scalar_timing_suite,args.out)
        return
    if args.probe_batch:
        if args.plan or args.runs or args.timing_suite or args.plot: parser.error('Probe analysis is separate')
        probe_batch(args.probe_batch,args.out)
        return
    if args.timing_suite:
        if args.plan or args.runs or args.plot: parser.error('Timing analysis is a separate diagnostic')
        timing_suite(args.timing_suite,args.out)
        return
    if not args.plan or not args.runs: parser.error('--plan and --runs are required for a comparison')
    plan, runs = json.loads(args.plan.read_text()), json.loads(args.runs.read_text())
    if hashlib.sha256(args.plan.read_bytes()).hexdigest() != runs['plan_sha256']:
        raise ValueError('Plan differs from the executed plan')
    actual = {r['id']: r for r in runs['runs']}
    if len(actual) != len(runs['runs']) or set(actual) != {c['id'] for c in plan['cases']}:
        raise ValueError('Missing, duplicate, or unexpected suite execution')
    if plan.get('host_only_affinity') and len({r.get('launcher_sha256') for r in actual.values()}) != 1:
        raise ValueError('Affinity launcher changed within the comparison')
    rows, checkpoints, inputs = [], [], [args.plan, args.runs]
    raw_roots = [WORKSPACE/'result-rawdata'/c['id'] for c in plan['cases']]
    for case, raw in zip(plan['cases'], raw_roots):
        execution = actual[case['id']]
        if execution.get('returncode') != 0: raise ValueError('Unfinished suite: '+case['id'])
        expected_hash = case.get('sha256') or (plan.get('baseline_sha256') if not case['workers'] else plan.get('candidate_sha256'))
        if expected_hash is None:
            original = Path(execution.get('actual_executable', Path(execution['source'])/'criu/criu'))
            expected_hash = hashlib.sha256(original.read_bytes()).hexdigest()
        if execution['binary_sha256'] != expected_hash:
            raise ValueError('Unexpected executable: '+case['id'])
        data, used = collect_suite(raw, WORKSPACE/'cdp/thirdparty/criu-dsa/scripts')
        workloads = [row['checkpoints'][0]['workload'] for row in data['rows']]
        expected_workloads = (['hnswlib', 'liquibook', 'orbslam3', 'redis']
                              if plan.get('workload', 'all') == 'all' else plan['workload'].split(','))
        if sorted(workloads) != sorted(expected_workloads):
            raise ValueError('Expected one completed task for each selected workload')
        for row in data['rows']:
            if [c['checkpoint'] for c in row['checkpoints']] != list(range(2, 11)):
                raise ValueError('Incomplete incremental checkpoints: '+row['case'])
            if any(c['diagnostics'] != 'off' for c in row['checkpoints']):
                raise ValueError('Unexpected diagnostic mode')
        inputs.extend(used)
        label = case.get('label') or ('base' if not case['workers'] else ('spin' if case.get('spin') else 'condition'))
        markers = []
        for path in used:
            if Path(path).suffix != '.log': continue
            lines = [line for line in Path(path).read_text().splitlines() if 'DSA_HOST_SCAN:' in line]
            for line in lines: markers.append({k:int(v) for k,v in re.findall(r'(\w+)=(\d+)', line)})
        if case['workers']:
            if len(markers) != sum(len(row['checkpoints']) for row in data['rows']):
                raise ValueError('Missing or duplicated effective worker configuration: '+case['id'])
            if any(m['workers'] != case['workers'] or m['spin'] != case.get('spin', 0) or m['timing'] != 0 or
                   m['block_bytes'] != case['block_bytes'] or
                   m.get('cross_vma', 0) != case.get('cross_vma', 0) or
                   m.get('prefetch_depth', 0) != case.get('prefetch_depth', 0) for m in markers):
                raise ValueError('Requested and effective Host scan parameters differ')
        elif markers: raise ValueError('Unexpected workers in baseline')
        for row in data['rows']:
            samples = row['checkpoints']
            for sample in samples:
                summary = sample['stream_summary'] or {}
                checkpoints.append({'suite':case['id'], 'condition':label,
                    'workload':sample['workload'], 'task_id':sample['task_id'],
                    'checkpoint':sample['checkpoint'], 'frozen_ms':sample['frozen_ms'],
                    'scan_build_us':sample['scan_build_us'],
                    **{key:summary.get(key) for key in ('payload_bytes','descriptors','slots',
                        'raw_fault_source','producer_wait_slot_us')}})
            def stream(key):
                return mean(c['stream_summary'].get(key) if c['stream_summary'] else None for c in samples)
            rows.append({'suite':case['id'], 'workload':samples[0]['workload'], 'condition':label,
                         'task_id':samples[0]['task_id'], 'checkpoints':[c['checkpoint'] for c in samples],
                         'frozen_ms':row['mean_incremental_frozen_ms'],
                         'scan_ms':mean(c['scan_build_us']/1000 if c['scan_build_us'] is not None else None for c in samples),
                         'copy_mib':stream('payload_bytes')/1048576 if stream('payload_bytes') is not None else None,
                         'source_faults':stream('raw_fault_source'),
                         'host_slot_wait_ms':stream('producer_wait_slot_us')/1000 if stream('producer_wait_slot_us') is not None else None,
                         'software_batches':stream('slots'), 'descriptors':stream('descriptors'),
                         'actual_elf_sha256':execution['binary_sha256'],
                         'reported_source_versions':data['source_versions']})
    groups = []
    for workload, condition in sorted({(r['workload'],r['condition']) for r in rows}):
        selected = [r for r in rows if (r['workload'],r['condition'])==(workload,condition)]
        values = [r['frozen_ms'] for r in selected]
        samples = [r for r in checkpoints if (r['workload'],r['condition'])==(workload,condition)]
        groups.append({'workload':workload, 'condition':condition, 'independent_processes':len(values),
                       'frozen_ms':mean(values), 'sample_sd_ms':statistics.stdev(values) if len(values)>1 else None,
                       'checkpoint_count':len(samples),
                       'checkpoint_median_frozen_ms':statistics.median(r['frozen_ms'] for r in samples),
                       'checkpoint_median_scan_ms':(statistics.median(r['scan_build_us']/1000 for r in samples)
                           if all(r['scan_build_us'] is not None for r in samples) else None),
                       **{key:mean(r[key] for r in selected) for key in
                          ('scan_ms','copy_mib','source_faults','host_slot_wait_ms','software_batches','descriptors')}})
    for group in groups:
        base = next(g for g in groups if g['workload']==group['workload'] and g['condition']=='base')
        group['frozen_reduction_percent'] = 100*(base['frozen_ms']-group['frozen_ms'])/base['frozen_ms']
    out = prepare_analysis_dir(args.out, raw_roots)
    (out/'verification.json').write_text(json.dumps({'groups':groups,'processes':rows,
        'aggregation':'CP2-10 mean per independent task, then mean of task means; SD across tasks. Checkpoint medians are descriptive pooled values, not independent repetitions.',
        'host_only_affinity':plan.get('host_only_affinity',False)},indent=2))
    with (out/'comparison.csv').open('w') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(groups[0]));writer.writeheader();writer.writerows(groups)
    with (out/'checkpoints.csv').open('w') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(checkpoints[0]));writer.writeheader();writer.writerows(checkpoints)
    provenance=analysis_provenance(inputs,vars(args),[Path(__file__),
        WORKSPACE/'cdp/scripts/analyze_checkpoint_probes.py',WORKSPACE/'cdp/scripts/experiment_results.py'])
    (out/'analysis-manifest.json').write_text(json.dumps(provenance,indent=2))
    if args.plot:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        workloads=['redis','liquibook','orbslam3','hnswlib']
        labels=[c for c in ('base','condition','spin') if any(g['condition']==c for g in groups)]
        figure,axis=plt.subplots(figsize=(10,4.5))
        width=.24
        for i,label in enumerate(labels):
            values=[next(g for g in groups if g['workload']==w and g['condition']==label) for w in workloads]
            positions=[x+(i-(len(labels)-1)/2)*width for x in range(len(workloads))]
            axis.bar(positions,[v['frozen_ms'] for v in values],width,
                     yerr=[v['sample_sd_ms'] or 0 for v in values],capsize=3,
                     color={'base':'#6b7280','condition':'#d79527','spin':'#2e75b6'}[label],
                     label={'base':'475d75078 baseline','condition':'2 workers: condition variable',
                            'spin':'2 workers: spin'}[label])
        axis.set_xticks(range(len(workloads)),['Redis','Liquibook','ORB-SLAM3','HNSW'])
        axis.set_ylabel('Native whole frozen time (ms)')
        axis.set_title('Independent process means; error bars = between-process SD')
        axis.legend(fontsize=8);axis.grid(axis='y',alpha=.2);axis.set_axisbelow(True)
        figure.tight_layout()
        for suffix in ('png','svg'):figure.savefig(out/('frozen-comparison.'+suffix),dpi=180)
        plt.close(figure)
    print(json.dumps(groups,indent=2))


if __name__ == '__main__': main()
