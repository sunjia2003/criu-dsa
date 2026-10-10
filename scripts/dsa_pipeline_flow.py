#!/usr/bin/env python3
"""Validate FULL point observations and correlate software slots with DSA requests.

Publish/acquire are bracketed CPU observations, not a device execution trace.
Completion times mean READY was observed, not the instant the device finished.
"""
import argparse
import json
from pathlib import Path
import re
import struct

MAGIC = 0x44534654
HEADER = struct.Struct('<4I4Q4I')
EVENT = struct.Struct('<6Q4I')
NO_ID = 0xffffffff
KINDS = ('begin', 'first_task', 'publish_pre', 'publish_post',
         'wait_slot_begin', 'wait_slot_end', 'ready', 'accept', 'h_create',
         'prepare_begin', 'prepare_end', 'submit_begin', 'submit_end',
         'complete_observed', 'recycle', 'loop_begin', 'loop_end', 'snapshot',
         'finish_pre', 'finish_post', 'join_begin', 'join_end', 'cleanup_begin', 'end',
         'empty_input_begin', 'empty_input_end')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(HEADER.size)
        require(len(raw) == HEADER.size, 'Truncated flow header')
        h = HEADER.unpack(raw)
        require(h[:4] == (MAGIC, 1, HEADER.size, EVENT.size), 'Unsupported flow layout')
        begin, end, count, dropped, pid, role, valid, flags = h[4:]
        require(valid == flags == 1 and dropped == 0 and pid and role in (1, 2),
                'Incomplete/dropped/invalid-clock flow')
        require(begin > 0 and end >= begin and count > 0, 'Invalid flow window')
        require(path.stat().st_size == HEADER.size + count*EVENT.size,
                'Flow file length differs from declared count')
        events, previous = [], begin
        for raw in iter(lambda: stream.read(EVENT.size*16384), b''):
            for ns, a, b, c, d, e, kind, seq, identifier, event_flags in EVENT.iter_unpack(raw):
                require(previous <= ns <= end and 1 <= kind <= len(KINDS),
                        'Backwards/out-of-window/unknown flow observation')
                require(event_flags in (0, 1), 'Unknown observation flags')
                events.append(dict(ns=ns, a=a, b=b, c=c, d=d, e=e,
                                   kind=KINDS[kind-1], seq=seq, id=identifier, flags=event_flags))
                previous = ns
        require(events[0]['ns'] == begin and events[0]['kind'] == 'begin',
                'Missing lifecycle beginning')
    return dict(pid=pid, role=role, begin_ns=begin, end_ns=end, events=events,
                source=str(path), count=count)


def singleton(events, kind):
    rows = [row for row in events if row['kind'] == kind]
    require(len(rows) == 1, 'Expected exactly one '+kind)
    return rows[0]


def indexed(events, kind, field='seq'):
    result = {}
    for event in events:
        if event['kind'] == kind:
            require(event[field] not in result, 'Duplicate '+kind)
            result[event[field]] = event
    return result


def correlate(host, parasite, dump_log=None):
    require(host['role'] == 1 and parasite['role'] == 2 and host['pid'] == parasite['pid'],
            'Flow roles/PIDs do not match')
    he, pe = host['events'], parasite['events']
    pre, post, first = (indexed(he, k) for k in ('publish_pre', 'publish_post', 'first_task'))
    accepted, recycled = (indexed(pe, k) for k in ('accept', 'recycle'))
    expected = set(range(len(pre)))
    require(all(set(table) == expected for table in (pre, post, first, accepted, recycled)),
            'Missing/duplicate/non-contiguous software slots')
    slots = []
    for seq in range(len(pre)):
        p, q, f, a, r = (table[seq] for table in (pre, post, first, accepted, recycled))
        require(f['ns'] <= p['ns'] <= q['ns'] and a['a'] <= a['ns'] <= r['ns'],
                'Invalid slot lifecycle chronology')
        # Accept can legitimately precede publish_post: the CPUs run concurrently.
        require(a['ns'] >= p['ns'], 'Consumer accepted before release bracket')
        require((p['a'], p['b'], p['c']) == (q['a'], q['b'], q['c']),
                'Publication bracket metadata changed')
        require((p['a'], p['b']) == (a['b'], a['c']) == (r['a'], r['b']),
                'Host/consumer descriptor counts or payload bytes differ')
        require(p['a'] > 0 and p['b'] > 0 and a['d'] == (p['a']+31)//32,
                'Invalid descriptor-to-hardware grouping')
        lower = max(0, a['a']-q['ns'])
        upper = a['ns']-p['ns']
        slots.append(dict(seq=seq, first_task_ns=f['ns'], publish_pre_ns=p['ns'],
                          publish_post_ns=q['ns'], accept_pre_ns=a['a'], accept_post_ns=a['ns'],
                          recycle_ns=r['ns'], descriptors=p['a'], payload_bytes=p['b'],
                          payload_offset=p['c'], handoff_lower_ns=lower, handoff_upper_ns=upper,
                          hardware_groups=a['d']))
    creates = indexed(pe, 'h_create', 'id')
    completes = indexed(pe, 'complete_observed', 'id')
    require(set(creates) == set(range(len(creates))) == set(completes),
            'Missing/duplicate/non-contiguous logical hardware requests')
    groups, pending, attempts = {}, {}, {}
    for event in pe:
        kind, identifier = event['kind'], event['id']
        if kind not in ('prepare_begin', 'prepare_end', 'submit_begin', 'submit_end'):
            continue
        require(identifier in creates and event['seq'] == creates[identifier]['seq'],
                'Request phase references unknown/wrong software slot')
        phase, boundary = kind.split('_')
        key = (identifier, phase)
        if boundary == 'begin':
            require(key not in pending, 'Nested request phase')
            pending[key] = event
        else:
            require(key in pending, 'Request phase end without beginning')
            start = pending.pop(key)
            require(start['ns'] <= event['ns'], 'Backwards request phase')
            require(event['ns'] <= completes[identifier]['ns'], 'Request phase after completion')
            attempts.setdefault(identifier, []).append(dict(id=identifier, seq=event['seq'], phase=phase,
                                 begin_ns=start['ns'], end_ns=event['ns'], children=event['a'],
                                 bytes=event['b'], wq=event['c']))
    require(not pending, 'Incomplete prepare/submit phase')
    for identifier, create in creates.items():
        done = completes[identifier]
        seq = create['seq']
        require(seq in expected and create['b'] > 0 and create['a'] > 0,
                'Invalid request owner/count/bytes')
        require((done['seq'], done['b'], done['c']) == (seq, create['a'], create['b']),
                'Logical request identity/count/bytes changed')
        phases = attempts.get(identifier, [])
        prepare = [item for item in phases if item['phase'] == 'prepare']
        submit = [item for item in phases if item['phase'] == 'submit']
        require(prepare and len(prepare) == len(submit), 'Missing prepare/submission attempts')
        for p, s in zip(prepare, submit):
            require(create['ns'] <= p['begin_ns'] <= p['end_ns'] <= s['begin_ns'] <= s['end_ns'],
                    'Hardware prepare/submit chronology violated')
        require(submit[-1]['end_ns'] <= done['a'] <= done['ns'] <= slots[seq]['recycle_ns'],
                'READY observation outside final submit/retirement boundary')
        groups[identifier] = dict(id=identifier, seq=seq, children=create['a'], bytes=create['b'],
                                 create_ns=create['ns'], first_submit_begin_ns=submit[0]['begin_ns'],
                                 first_submit_end_ns=submit[0]['end_ns'], observed_ready_ns=done['a'],
                                 harvest_end_ns=done['ns'], attempts=len(submit), phases=phases)
    for slot in slots:
        owned = [group for group in groups.values() if group['seq'] == slot['seq']]
        require(len(owned) == slot['hardware_groups'] and
                sum(group['bytes'] for group in owned) == slot['payload_bytes'] and
                sum(group['children'] for group in owned) == slot['descriptors'],
                'Request groups do not reproduce software slot counts/bytes')
        slot['first_submit_ns'] = min(group['first_submit_begin_ns'] for group in owned)
        slot['last_ready_ns'] = max(group['observed_ready_ns'] for group in owned)
    finish = singleton(he, 'finish_pre')
    finish_post = singleton(he, 'finish_post')
    loop_begin, loop_end = singleton(pe, 'loop_begin'), singleton(pe, 'loop_end')
    require(finish['seq'] == finish_post['seq'] == loop_end['seq'] == len(slots),
            'Finish counts differ from flow')
    total_bytes = sum(slot['payload_bytes'] for slot in slots)
    total_desc = sum(slot['descriptors'] for slot in slots)
    require((finish['a'], finish['b']) == (finish_post['a'], finish_post['b']) ==
            (total_bytes, total_desc) == (loop_end['b'], loop_end['a']),
            'Finished payload/descriptors differ from flow')
    # The consumer may finish after the release store but before the producer
    # records FINISH_POST (e.g. the producer is descheduled at that boundary).
    require(finish['ns'] <= finish_post['ns'] and finish['ns'] <= loop_end['ns'],
            'Finish/end ordering invalid')
    wait = None
    waits = []
    for event in he:
        if event['kind'] == 'wait_slot_begin':
            require(wait is None, 'Nested producer slot wait')
            wait = event
        if event['kind'] == 'wait_slot_end':
            require(wait is not None and wait['seq'] == event['seq'], 'Unpaired producer slot wait')
            waits.append(dict(seq=event['seq'], begin_ns=wait['ns'], end_ns=event['ns']))
            wait = None
    require(wait is None, 'Unfinished producer slot wait')
    snapshots = [event for event in pe if event['kind'] == 'snapshot']
    for event in snapshots:
        require(loop_begin['ns'] <= event['ns'] <= loop_end['ns'] and
                0 <= event['c'] <= event['b'] <= event['a'] <= len(slots) and event['d'] <= 128,
                'Invalid observed queue state')
    require(snapshots and (snapshots[-1]['a'], snapshots[-1]['b'], snapshots[-1]['c'], snapshots[-1]['d']) ==
            (len(slots), len(slots), len(slots), 0) and snapshots[-1]['flags'] == 1,
            'No observed fully drained terminal state')
    empty_intervals, empty = [], None
    for event in pe:
        if event['kind'] == 'empty_input_begin':
            require(empty is None and event['a'] == event['seq'] and event['b'] == event['c'] == 0,
                    'Invalid/nested observed empty input period')
            empty = event
        elif event['kind'] == 'empty_input_end':
            require(empty is not None and loop_begin['ns'] <= empty['ns'] <= event['ns'] <= loop_end['ns'],
                    'Unpaired empty input observation')
            empty_intervals.append((empty['ns'], event['ns']))
            empty = None
    require(empty is None, 'Incomplete empty input observation')
    result = dict(pid=host['pid'], complete=True, slots=slots, groups=list(groups.values()),
                  snapshots=snapshots, producer_waits=waits, empty_input_observation_intervals=empty_intervals,
                  total_bytes=total_bytes, total_descriptors=total_desc, software_slots=len(slots),
                  hardware_groups=len(groups), submit_attempts=sum(g['attempts'] for g in groups.values()),
                  host_begin_ns=host['begin_ns'], host_end_ns=host['end_ns'],
                  parasite_begin_ns=parasite['begin_ns'], parasite_end_ns=parasite['end_ns'],
                  loop_begin_ns=loop_begin['ns'], loop_end_ns=loop_end['ns'],
                  producer_finish_pre_ns=finish['ns'], producer_finish_post_ns=finish_post['ns'])
    if dump_log is not None:
        text = Path(dump_log).read_text()
        lines = [line for line in text.splitlines() if 'DSA_MEMDUMP_DETAIL:' in line]
        require(len(lines) == 1, 'Expected exactly one stream detail log')
        values = dict((key, int(value)) for key, value in re.findall(r'(\w+)=(\d+)', lines[0]))
        submitted = [phase for group in groups.values() for phase in group['phases']
                     if phase['phase'] == 'submit']
        outer_submits = sum(phase['children'] > 1 for phase in submitted)
        single_submits = len(submitted)-outer_submits
        outer_success = sum(next(phase for phase in reversed(group['phases'])
                                 if phase['phase'] == 'submit')['children'] > 1 for group in groups.values())
        require(values.get('stream_payload_bytes') == total_bytes and
                values.get('stream_desc_count') == total_desc and
                values.get('stream_flush_count') == len(slots) and
                values.get('batch_outer_submits') == outer_submits and
                values.get('batch_single_tail_submits') == single_submits and
                values.get('batch_outer_success') == outer_success and
                values.get('batch_outer_fail') == outer_submits-outer_success and
                values.get('batch_child_submits') == sum(phase['children'] for phase in submitted) and
                values.get('batch_child_success') == total_desc,
                'Flow and native stream ledger differ')
        result['dump_log_verified'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', type=Path)
    parser.add_argument('parasite', type=Path)
    parser.add_argument('--dump-log', type=Path)
    parser.add_argument('--details', action='store_true')
    args = parser.parse_args()
    try:
        result = correlate(load(args.host), load(args.parasite), args.dump_log)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if not args.details:
        result = {key:value for key, value in result.items() if key not in
                  ('slots', 'groups', 'snapshots', 'producer_waits', 'empty_input_observation_intervals')}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
