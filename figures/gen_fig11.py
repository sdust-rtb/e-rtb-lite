import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

configs = ['Heterogeneous\n(Qwen+GLM+Rego)', 'Homogeneous\n(Qwen×3, temp perturb.)', 'Without Rego\n(Qwen+GLM+DeepSeek)']
error_rate = [0.0333, 0.1500, 0.0222]
fpr = [0.0000, 0.0333, 0.0000]
fnr = [0.0333, 0.1167, 0.0222]
rho_eff = [1.4438, 1.3692, 1.4480]

x = np.arange(len(configs))
width = 0.2

fig, ax1 = plt.subplots(figsize=(8, 4.5))

bars1 = ax1.bar(x - 1.5*width, error_rate, width, label='Error Rate', color='#4C72B0', edgecolor='black', linewidth=0.5)
bars2 = ax1.bar(x - 0.5*width, fpr, width, label='FPR', color='#DD8452', edgecolor='black', linewidth=0.5)
bars3 = ax1.bar(x + 0.5*width, fnr, width, label='FNR', color='#55A868', edgecolor='black', linewidth=0.5)

ax1.set_ylabel('Rate (lower is better)', fontsize=11)
ax1.set_ylim(0, 0.20)
ax1.set_xticks(x)
ax1.set_xticklabels(configs, fontsize=9)

ax2 = ax1.twinx()
bars4 = ax2.bar(x + 1.5*width, rho_eff, width, label=r'$\rho_{\mathrm{eff}}$', color='#C44E52', edgecolor='black', linewidth=0.5)
ax2.set_ylabel(r'$\rho_{\mathrm{eff}}$ (lower is better)', fontsize=11)
ax2.set_ylim(0, 2.5)
ax2.axhline(2.0, color='gray', linestyle='--', linewidth=1.2, zorder=1)
ax2.text(2.42, 2.03, 'theoretical degenerate bound (2.0)', fontsize=7.5, color='gray', ha='right', va='bottom')

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=9, framealpha=0.9)

ax1.yaxis.grid(True, alpha=0.3)
ax1.set_axisbelow(True)

plt.tight_layout()
plt.savefig(r'D:\data\RTB\JISA\CCPE\File\figure\fig11_jury_quality_jisa.pdf', dpi=300, bbox_inches='tight')
print('Figure 7 regenerated with corrected values')
