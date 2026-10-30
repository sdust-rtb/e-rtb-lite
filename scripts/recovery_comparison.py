"""Matched recovery-policy experiment; controlled observations/verdict, real DAC.

No production UCON implementation is claimed. Immediate recovery is a reasonable
policy when an innocent verdict suffices; consecutive-safe recovery deliberately
adds a stability requirement and may lose legitimate work. Both share all code
except the configured cooldown (0 versus 30 ms).
"""
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import time

from core.bsigner import BSigner
from core.governance import EvidenceVerifier, Governance, Strategy, State, python_risk_rule
from core.experiment import perform
from core.linux_dac import LinuxDACExecutor


def trial(policy, disturbed):
    signer = BSigner()
    verifier = EvidenceVerifier('a', signer.get_public_key_bytes(), signer.get_h0())
    gov = Governance('a', Strategy.STAGED, 30_000_000 if policy == 'consecutive_safe' else 0)
    records, observations, applications = [], [], []
    with LinuxDACExecutor() as executor:
        def operation(op, name, phase, payload=''):
            row, evidence = perform(executor, gov, signer, verifier, op, name, payload, phase)
            records.append(row)
            return evidence

        operation('append', 'business.txt', 'positive_control', 'control|')
        evidence = operation('read', 'sensitive.txt', 'trigger')
        assert python_risk_rule(evidence)
        case = gov.open_case(evidence, time.monotonic_ns())
        applications.append(executor.apply(gov.permissions))
        # Three actual pending writes, including a wait beyond the cooldown.
        for _ in range(3):
            gov.tick(time.monotonic_ns(), True)
            operation('append', 'business.txt', 'pending', 'pending|')
            time.sleep(.020)
        verdict_at = time.monotonic_ns()
        gov.resolve(case, 'innocent', verdict_at)
        applied = executor.permissions
        first_write = None
        for step in range(25):
            due = verdict_at + step * 5_000_000
            time.sleep(max(0, (due - time.monotonic_ns()) / 1e9))
            # Shared step-based input trace, not a scheduling-dependent condition.
            unsafe = disturbed and 3 <= step <= 8
            observed = operation('read', 'sensitive.txt' if unsafe else 'diagnostic.txt', 'observation')
            safe = not python_risk_rule(observed)
            observed_at = time.monotonic_ns()
            # Both policies continue monitoring after the first case closes.
            # A new unsafe observation suspends access; it is a recovery-condition
            # input, not a second adjudication case in this single-case fixture.
            if not safe and gov.state == State.ACTIVE:
                gov._move(State.PROBATION, observed_at, 'unsafe-recovery-observation')
            gov.tick(observed_at, safe)
            observations.append(dict(step=step, at_ns=observed_at, safe=safe,
                                     sequence=observed.sequence, safe_since=gov.safe_since))
            if gov.permissions != applied:
                applications.append(executor.apply(gov.permissions))
                applied = gov.permissions
            operation('read', 'diagnostic.txt', 'business_read')
            operation('append', 'business.txt', 'business_write', 'business|')
            if records[-1]['success'] and first_write is None:
                first_write = records[-1]['end_ns']
            if unsafe:
                operation('append', 'sink.txt', 'unsafe_window_probe', 'probe|')
        assert first_write is not None
        work = [r for r in records if r['phase'] == 'business_write']
        danger = [r for r in records if r['phase'] == 'unsafe_window_probe']
        assert executor.size('sink.txt') == sum(r['bytes'] for r in danger if r['success'])
    final_restore_write = next((r['end_ns'] for r in records if r['phase'] == 'business_write'
                               and r['success'] and r['start_ns'] >= observations[9]['at_ns']), None)
    return dict(policy=policy, disturbed=disturbed, verdict_ns=verdict_at,
                public_key=signer.get_public_key_bytes().hex(), anchor=signer.get_h0().hex(),
                observations=observations, operations=records, transitions=gov.transitions,
                applications=applications, metrics=dict(
                    recovery_ms=(first_write-verdict_at)/1e6,
                    stable_recovery_ms=(final_restore_write-observations[9]['at_ns'])/1e6,
                    business_successes=sum(r['success'] for r in work), business_attempts=len(work),
                    danger_successes=sum(r['success'] for r in danger), danger_attempts=len(danger)))


def validate(t):
    from core.bsigner import BehaviorEvent, EvidencePackage
    v = EvidenceVerifier('a', bytes.fromhex(t['public_key']), bytes.fromhex(t['anchor']))
    for r in t['operations']:
        e = r['evidence']
        v.accept(BehaviorEvent(**r['event']), EvidencePackage(bytes.fromhex(e['h_curr']), e['seq'],
                 bytes.fromhex(e['sigma']), e['timestamp'], e['version']))
        assert r['success'] == r['expected_allowed']
        if not r['success']:
            assert r['errno'] in (13, 1) and r['size_before'] == r['size_after']
        if r['phase'] == 'pending':
            assert r['denied'] and not r['success']
    for stem, phase in [('business', 'business_write'), ('danger', 'unsafe_window_probe')]:
        rows = [r for r in t['operations'] if r['phase'] == phase]
        assert t['metrics'][stem+'_attempts'] == len(rows)
        assert t['metrics'][stem+'_successes'] == sum(r['success'] for r in rows)
    assert all(r['success'] for r in t['operations'] if r['phase'] == 'business_read')
    assert t['metrics']['danger_successes'] == 0
    if t['policy'] == 'consecutive_safe':
        restore = next(x['at_ns'] for x in t['transitions'] if x['to'] == 'Active')
        if t['disturbed']:
            unsafe = [o for o in t['observations'] if not o['safe']]
            assert all(o['safe_since'] is None for o in unsafe)
            restart = next(o['at_ns'] for o in t['observations'] if o['step'] == 9)
            assert restore >= restart + 30_000_000
            assert t['metrics']['danger_successes'] == 0
        else:
            assert restore >= t['verdict_ns'] + 30_000_000
    return len(t['operations'])


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--validate-only', action='store_true')
    a = p.parse_args()
    if not a.validate_only:
        a.output.mkdir(parents=True, exist_ok=False)
        tasks = [(i, s, d) for i in range(20) for d in (False, True)
                 for s in ('observation_reactive', 'consecutive_safe')]
        random.Random(20261026).shuffle(tasks)
        sources = [Path(__file__), *Path('core').glob('*.py')]
        meta = dict(platform=platform.platform(), seed=20261026, n_per_cell=20,
                    source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                    scope='Linux DAC fresh-open operations; controlled innocent verdict and observation schedule; no eBPF or LLM')
        (a.output/'metadata.json').write_text(json.dumps(meta, indent=2))
        with (a.output/'trials.jsonl').open('w') as out:
            for i, (pair, policy, disturbed) in enumerate(tasks):
                t = trial(policy, disturbed)
                t['pair_id'] = pair
                validate(t)
                out.write(json.dumps(t)+'\n')
                out.flush()
                if (i+1) % 20 == 0:
                    print('Completed', i+1, '/', len(tasks), flush=True)
    trials = [json.loads(s) for s in (a.output/'trials.jsonl').read_text().splitlines()]
    events = sum(validate(t) for t in trials)
    rows = []
    for disturbed in (False, True):
        for policy in ('observation_reactive', 'consecutive_safe'):
            ts = [t for t in trials if t['disturbed'] == disturbed and t['policy'] == policy]
            assert len(ts) == 20
            row = dict(policy=policy, disturbed=disturbed, n=len(ts))
            for k in ('business_successes', 'business_attempts', 'danger_successes', 'danger_attempts'):
                row[k] = sum(t['metrics'][k] for t in ts)
            row['recovery_p50_ms'] = statistics.median(t['metrics']['recovery_ms'] for t in ts)
            row['stable_recovery_p50_ms'] = statistics.median(t['metrics']['stable_recovery_ms'] for t in ts)
            rows.append(row)
    result = dict(trials=len(trials), verified_events=events, rows=rows,
                  raw_sha256=hashlib.sha256((a.output/'trials.jsonl').read_bytes()).hexdigest())
    (a.output/'summary.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
