from pathlib import Path
import json, hashlib, re, collections
import numpy as np
from scipy.stats import chi2, beta
import sys

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
EXP=ROOT/'experiments'
def read(p): return json.loads((EXP/p).read_text(encoding='utf-8-sig'))
def paired(x,y):
    b=int(np.sum(x & ~y)); c=int(np.sum(~x & y)); n=b+c
    stat=max(0,abs(b-c)-1)**2/n if n else 0
    return dict(b=b,c=c,chi2=stat,p=float(chi2.sf(stat,1)) if n else 1.)
def metrics(g,v):
    n=len(g); err=int(np.sum(g!=v)); fp=int(np.sum((g==0)&(v==1))); fn=int(np.sum((g==1)&(v==0)))
    return dict(n=n,errors=err,fp=fp,fn=fn,error_rate=err/n,fp_over_n=fp/n,fn_over_n=fn/n,
      fpr=fp/int(np.sum(g==0)),fnr=fn/int(np.sum(g==1)),
      ci=[float(beta.ppf(.025,err,n-err+1)) if err else 0.,float(beta.ppf(.975,err+1,n-err)) if err<n else 1.])
data=read('data/arbitration_cases.json'); raw=read('results/rq2_jury_cases_raw.json')
report={'dataset':{'total':len(data),'labels':dict(collections.Counter(str(x['gold_label']) for x in data)), 'categories':dict(collections.Counter(x['category'] for x in data))},'jury':{}}
ids=None; errors={}
for name,rows in raw.items():
    rows=sorted(rows,key=lambda x:x['case_id']); current=[r['case_id'] for r in rows]
    if ids is None: ids=current
    assert ids==current and len(set(ids))==len(ids)
    gold=np.array([r['gold_label'] for r in rows]); votes=np.array([r['votes'] for r in rows]); majority=(votes.sum(axis=1)>=2).astype(int)
    assert np.array_equal(majority,[r['verdict'] for r in rows])
    dataset={d['case_id']:d['gold_label'] for d in data}
    assert all(dataset[r['case_id']]==r['gold_label'] for r in rows)
    e=majority!=gold; errors[name]=e
    jurors=[]
    for i in range(3):
        m=metrics(gold,votes[:,i]); m['mcnemar_vs_majority']=paired(votes[:,i]!=gold,e); jurors.append(m)
    report['jury'][name]={'majority':metrics(gold,majority),'jurors':jurors,'unanimous_errors':int(np.sum(np.all(votes!=gold[:,None],axis=1))),
      'spectral_rho':float(np.linalg.eigvalsh(np.corrcoef(votes.T))[-1]-1)}
report['heterogeneous_vs_homogeneous']=paired(errors['E-RTB-Lite_heterogeneous'],errors['B3_homogeneous'])
ah=read('results/agentharm_jury_api.json'); report['agentharm']={}
for name in ['qwen','glm','deepseek','majority']:
    rows=[x for x in ah['cases'] if x[name]['verdict'] is not None]
    report['agentharm'][name]=metrics(np.array([r['gold'] for r in rows]),np.array([r[name]['verdict'] for r in rows]))
    report['agentharm'][name]['missing']=len(ah['cases'])-len(rows)
cross=read('results/cross_node_N30.json'); a=np.array([r['latency_ms'] for r in cross['raw_results']])
report['cross_node_reported_values_only']={'n':len(a),'mean':float(a.mean()),'sample_sd':float(a.std(ddof=1)),'p50':float(np.quantile(a,.5)),'p95_linear':float(np.quantile(a,.95)),'p99_linear':float(np.quantile(a,.99)),'p99_nearest_rank':float(np.sort(a)[int(np.ceil(.99*len(a)))-1])}
sys.path.insert(0,str(EXP))
from rq2.collusion_detection import evaluate_collusion_detection
pairs=read('data/collusion_pairs.json')
report['collusion_recomputed']={str(flag):evaluate_collusion_detection(pairs,verdict_constraint=flag) for flag in [False,True]}
saved=read('results/rq2_collusion_20260611_155916.json')
assert report['collusion_recomputed']['False']==saved['baseline']
assert report['collusion_recomputed']['True']==saved['with_verdict_constraint']
(OUT/'recomputed.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (EXP/'results').glob('*.json')}
sources.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (EXP/'data').glob('*.json')})
(OUT/'input_sha256.json').write_text(json.dumps(sources,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2,ensure_ascii=False))
