"""Trial-level clustered confidence intervals for operation-level rates.

The manuscript's statistics paragraph states that, unless stated otherwise,
the trial -- not the individual operation -- is the repetition unit. Three
reported rates were originally given operation-level Clopper--Pearson
intervals that treat every write attempt as an independent Bernoulli trial.
Because attempts within a trial share case state, scheduling and host
conditions, this script recomputes those three intervals treating the TRIAL
as the resampling unit (trial-level percentile bootstrap).

Sources (all in this repository):
  1. results/revalidated_linux_dac_20261026/trials.jsonl
     - zero-success dangerous writes during Pending-Arbitration (all 720 trials)
     - staged / false_positive / jury=200ms / scoring=0 cell legitimate-write
       completion (20 trials, 101/580)
  2. results/recovery_fair_20261026/trials.jsonl
     - disturbed-trace legitimate-write completion under observation_reactive
       (380/500) and consecutive_safe (193/500) policies (20 trials each)

Method: resample trials with replacement (B=20000), recompute the pooled
operation-level proportion from the resampled trials, take percentile
intervals. For the zero-success quantity we additionally report the exact
Clopper--Pearson upper bound treating the trial as the unit.
"""
import json
import numpy as np

B = 20000
rng = np.random.default_rng(20261105)


def cp_zero_upper(n, alpha=0.05):
    """Exact one-sided/upper Clopper-Pearson bound for zero events out of n."""
    return 1.0 - (alpha / 2.0) ** (1.0 / n) if False else 1.0 - (alpha / 2.0) ** (1.0 / n)


def boot_pooled_rate(att, suc, B=B, seed=rng):
    """Trial-level cluster bootstrap for a pooled proportion.

    att, suc: arrays of per-trial attempts and successes (paired by trial).
    Primary estimator (reviewer-requested): resample TRIALS with replacement,
    average the per-trial success RATE over the resampled trials, take
    percentiles. This treats the trial as the only source of variability and
    never counts individual operations as independent.
    Returns point (mean per-trial rate), (lo, hi), and the per-trial rates.
    """
    att = np.asarray(att, dtype=float)
    suc = np.asarray(suc, dtype=float)
    with np.errstate(invalid='ignore', divide='ignore'):
        per_trial = np.where(att > 0, suc / np.where(att > 0, att, 1), np.nan)
    per_trial = per_trial[~np.isnan(per_trial)]
    n = len(per_trial)
    idx = seed.integers(0, n, size=(B, n))
    means = per_trial[idx].mean(axis=1)
    point = float(per_trial.mean())
    lo, hi = np.percentile(means, [2.5, 97.5])
    return point, (float(lo), float(hi)), per_trial


# ---------- Source 1: Linux DAC ----------
dac = [json.loads(l) for l in open(
    'results/revalidated_linux_dac_20261026/trials.jsonl', encoding='utf-8')]

# (1) zero-success dangerous writes during Pending-Arbitration, all trials
trial_pending_att, trial_pending_suc = [], []
for t in dac:
    a = s = 0
    for o in t.get('operations', []):
        if (o.get('phase') == 'workload' and o.get('op') == 'append'
                and o.get('expected_allowed') is False
                and o.get('state') == 'Pending-Arbitration'):
            a += 1
            if o.get('success'):
                s += 1
    trial_pending_att.append(a)
    trial_pending_suc.append(s)
trial_pending_att = np.array(trial_pending_att)
trial_pending_suc = np.array(trial_pending_suc)
tot_a = int(trial_pending_att.sum())
tot_s = int(trial_pending_suc.sum())
n_trials = len(dac)
n_trials_with_success = int((trial_pending_suc > 0).sum())
print('=== (1) zero-success dangerous writes, Pending-Arbitration ===')
print('attempts=%d successes=%d across %d trials; trials with >=1 success=%d'
      % (tot_a, tot_s, n_trials, n_trials_with_success))
print('operation-level CP upper (old, per attempt, n=%d): %.6f' % (tot_a, cp_zero_upper(tot_a)))
print('trial-level  CP upper (new, per trial,  n=%d): %.6f' % (n_trials, cp_zero_upper(n_trials)))

# (2) staged/false_positive/200ms/scoring=0 legitimate-write completion
cell_att, cell_suc = [], []
for t in dac:
    if (t['strategy'] == 'staged' and t['scenario'] == 'false_positive'
            and t['jury_delay_ms'] == 200.0 and t['scoring_delay_ms'] == 0.0):
        cell_att.append(t['metrics']['business_attempts'])
        cell_suc.append(t['metrics']['business_successes'])
cell_att = np.array(cell_att, dtype=float)
cell_suc = np.array(cell_suc, dtype=float)
pt, (lo, hi), per_trial = boot_pooled_rate(cell_att, cell_suc)
print()
print('=== (2) staged/false_positive/200/scoring0 legitimate-write completion ===')
print('trials=%d attempts=%d successes=%d point=%.4f' % (len(cell_att), cell_att.sum(), cell_suc.sum(), pt))
print('per-trial success counts (of %d attempts each): %s'
      % (int(cell_att[0]), sorted(cell_suc.astype(int).tolist())))
print('trial-level 95%% CI = [%.4f, %.4f]  (percent)' % (lo, hi))


# ---------- Source 2: recovery_fair (disturbed trace) ----------
rec = [json.loads(l) for l in open(
    'results/recovery_fair_20261026/trials.jsonl', encoding='utf-8')]

print()
print('=== (3) matched-recovery disturbed-trace legitimate-write completion ===')
for policy in ['observation_reactive', 'consecutive_safe']:
    att, suc = [], []
    for t in rec:
        if t['policy'] == policy and t.get('disturbed'):
            att.append(t['metrics']['business_attempts'])
            suc.append(t['metrics']['business_successes'])
    att = np.array(att, dtype=float)
    suc = np.array(suc, dtype=float)
    pt, (lo, hi), per_trial = boot_pooled_rate(att, suc)
    print('%-20s trials=%d attempts=%d successes=%d point=%.4f  trial-level 95%% CI=[%.4f, %.4f]'
          % (policy, len(att), att.sum(), suc.sum(), pt, lo, hi))
    print('  per-trial success counts (of %d attempts each): %s'
          % (int(att[0]), sorted(suc.astype(int).tolist())))