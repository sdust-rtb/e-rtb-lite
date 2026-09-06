import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

components = ['HMAC\nverify', 'Ed25519\nsign', 'OPA risk\nassess', 'Soft\nrevocation', 'Risk\nscoring', 'LLM\ninference']
p50_us = [2.9, 34.0, 6.8, 385.0, 8000.0, 921200.0]  # µs
p95_us = [5.7, 71.3, 12.5, 1000.0, 12000.0, 937700.0]

p50_ms = [v/1000 for v in p50_us]
p95_ms = [v/1000 for v in p95_us]

fig, ax = plt.subplots(figsize=(9, 5))

x = np.arange(len(components))
width = 0.35

bars_p50 = ax.bar(x - width/2, p50_ms, width, label='P50', color='#4C72B0', edgecolor='black', linewidth=0.5)
bars_p95 = ax.bar(x + width/2, p95_ms, width, label='P95', color='#DD8452', edgecolor='black', linewidth=0.5)

ax.set_yscale('log')
ax.set_ylabel('Latency (ms, log scale)', fontsize=11)
ax.set_xticks(x)
ax.set_xticklabels(components, fontsize=9)
ax.legend(fontsize=10)

ax.yaxis.grid(True, alpha=0.3, which='both')
ax.set_axisbelow(True)

for bar, val in zip(bars_p50, p50_ms):
    if val >= 1:
        ax.text(bar.get_x() + bar.get_width()/2, val*1.3, f'{val:.1f}', ha='center', va='bottom', fontsize=7)
    else:
        ax.text(bar.get_x() + bar.get_width()/2, val*1.3, f'{val:.3f}', ha='center', va='bottom', fontsize=7)

ax.annotate('LLM inference: 921.2 ms (99.1% of total 929.6 ms)',
            xy=(5, 921.2), xytext=(3.5, 500),
            arrowprops=dict(arrowstyle='->', color='#C44E52', lw=1.5),
            fontsize=9, color='#C44E52', fontweight='bold')

ax.set_title('End-to-End Latency Decomposition (P50/P95)', fontsize=12)

plt.tight_layout()
plt.savefig(r'D:\data\RTB\JISA\CCPE\File\figure\fig12_e2e_latency_jisa.pdf', dpi=300, bbox_inches='tight')
print('Figure 8 regenerated with 99.1% label')
