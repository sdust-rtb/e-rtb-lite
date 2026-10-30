# E-RTB Lite 证据来源清单

整理日期：2026-10-26。范围：当前工作区论文、experiments 代码和结果，以及此前审计归档。此清单区分“结果存在”“可复算”“实现支持的结论”；不对历史实验作造假推断。

当前文件 SHA-256、大小和路径见 `evidence_sources_20261026.json`。哈希只固定本次核查时的文件内容，不能证明历史运行时使用了当前代码。下表中的历史脚本是可定位的相关实现；除明确归档者外，历史精确版本仍需从原运行环境确认。

| 论文主张/实验 | 结果来源（相对 experiments） | 相关代码 | 可支持的内容与限制 |
|---|---|---|---|
| 30 万次攻击，零成功 | `results/rq1_attack_results.json` | `rq1/attack_simulator.py` | 三类实现级攻击结果；不能推导未知攻击覆盖或新密码原语安全性。当前核心已升级 v2，旧结果不能标为 v2 重跑结果。 |
| 113,559 包、10 分钟采集后批量签名 | 已从 Kilo Code 2026-05-15 会话找回用户粘贴的服务器终端记录；见 `../audits/2026-10-26-recovered-113559/FINDINGS.md` | 找回远程 bsigner.py 片段和运行命令 | 113559事件、113559签名、113559/113559验签；采集跨度599.4s，随后批量签名7.026s。原文件线索为服务器 `/root/ebpf_10min.jsonl`，尚未恢复完整文件。后续链脚本为再次顺序签名，非独立逐包链复核。 |
| eBPF 实际采集 | `results/ebpf_15s.jsonl`、`ebpf_600s.jsonl.gz`、`ebpf_events.json` | `ebpf_probe.py`、`rq2/ebpf_runner.py`（相关采集实现） | 前两组分别保存 3,116、88,805 条事件及汇总；300 秒另一组 total=27,768、样本5,000。不同采集运行不能拼接成同一次签名闭环。 |
| 双观测、突发和共同原因丢失 | `results/rq2_real_dual_obs*.json`、`rq2_dual_obs_bursty.json`、`rq2_dual_obs_common_cause.json` | `rq2/dual_observation.py`、`dual_obs_bursty.py`、`dual_obs_common_cause.py` | 已采集基线上的丢失模拟/后处理；不能统称部署中同时运行双探针的效果。 |
| 180 案件裁决质量 | `results/rq2_jury_results.json`、`rq2_jury_cases_raw.json`、`rq2_single_juror_stats.json`、`rq2_bootstrap_mcnemar.json` | `rq2/jury_quality_real.py`、`single_juror_stats.py`、`bootstrap_jury.py` | 存有逐模型响应与票型；用于裁决质量和配对统计。规则参与者的 Python 实现不能标成真实 OPA/Rego 调用耗时。 |
| AgentHarm 352 例 | `results/agentharm_jury_api.json` | `rq2/agentharm_jury_api.py` | 文本判别基准，不等于实际工具攻击阻断，也不证明 Rego 否决收益。 |
| 50 轮、929.574 ms、50 次撤销 | `results/e2e_real_20260512_152042.json`；其他 `*e2e*real*.json` 留有不同运行 | 原驱动归档：`../audits/2026-10-26-core-timing/before-repair/end_to_end_e2e.py` | 主文件为聚合统计，缺少其50轮明细。原计时止于内存撤销状态，非真实操作被拒绝；真实 LLM 调用记录与真实采集记录分别保留。 |
| 6.8 μs / 组件开销 | `results/rq3_benchmark_results.json` | `rq3/micro_benchmark.py` | 风险项调用 Python RiskEngine，不能写为 OPA runtime 性能。 |
| 约 14,000–15,500 events/s | `results/rq3_stress_results.json` | `rq3/stress_test.py` | 共享 signer、每线程尽快提交500事件的饱和负载；不是50 events/s/agent 的限速负载。需保留尾延迟。 |
| 原 B1–B4 凭证消融 | `results/rq3_dct_vs_jwt.json`（保留） | `../audits/2026-10-26-credential-ablation/dct_vs_jwt_before.py` | 原 B4 哈希固定点检查无效；旧链拒绝率不得继续作为有效链验证证据。 |
| 修复后 B3/B4 | `results/credential_v2_20261026/{trials.jsonl,summary.json,metadata.json,verification.json}` | `rq3/dct_vs_jwt.py`、`core/bsigner.py`、`core/governance.py` | 10条基础序列、每条5包，派生7场景×2配置，共140个序列运行、760次提交；本地密码/协议功能验证，无eBPF、LLM或实际执行阻断。B1/B2未重跑。 |
| 历史冷却/状态机效果 | `results/rq4_ablation_results.json`、`rq4_dynamics_results.json` | 原 `rq4/state_ablation.py` 已归档到上述 core-timing/before-repair；`rq4/dynamics_sim.py` | 模拟结果；旧 Pending 提前恢复问题已发现，不能移用旧结论解释新状态语义。 |
| 修复后真实操作三策略 | `results/revalidated_linux_dac_20261026/` | `core/experiment.py`、`linux_dac.py`、`file_worker.py`、`governance.py` | 720轮、42,480个签名操作；Pending 写尝试3,191次、成功0次。Linux DAC真实文件操作＋受控裁决延迟；非eBPF＋真实LLM全链路。见该目录 RESULTS.md。 |
| 跨节点、恢复、网络分区 | `results/cross_node_N30.json`、`rq4_crash_recovery.json`、`rq4_network_partition.json`、`rq4_observation_degradation.json` | `rq4/resilience_test.py`及跨节点脚本 | 保留为可行性/模拟证据；跨节点客户端未传递完整签名证据、快照为同进程模拟等限制见核心审计，不能声称生产级复制和故障恢复保证。 |

## 投稿前如何使用

1. 历史数字和新实验分开引用，禁止把不同运行的组件耗时相加当作全链路实测。
2. 新凭证实验采用 v2 事件编码和真实 Ed25519 签名；旧表 n=1,000 不能直接沿用，新场景每配置 n=10。
3. B3 新定义包含认证的静态锚点，匹配论文描述；旧实现没有该字段。这是明示的协议对齐，不是原表原样复测。
4. 归档旧数据不代表认可其全部结论；协议功能测试也不代表密码安全证明或真实执行阻断。
5. 原始密钥不写入结果；证据公钥、锚点、事件、签名、判定原因及接收状态均保留。独立复核器验证 B4 逐包密码链；凭证 HMAC 外壳由测试和重跑覆盖。
