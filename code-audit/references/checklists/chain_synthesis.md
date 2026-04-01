# 攻击链合成检查清单

> 配合 `references/core/chain_synthesis.md` 使用。目标是保留高价值链路，而不是把 speculative material 包装成正式漏洞。

## 前置条件

- [ ] 已拿到 `FINALIZED_FINDING_INDEX`
- [ ] 每个候选节点都包含前提条件、影响和 lifecycle
- [ ] 需要进入 formal path 的节点均为 `CONFIRMED`

## 图构建

- [ ] 先按能力分类节点（信息泄露 / 认证绕过 / 权限提升 / RCE / 持久化）
- [ ] 为每个节点记录产出能力和前提条件
- [ ] 对每条边执行 5 个 edge gates
- [ ] formal edge 全闭合后才进入 `ATTACK_PATH`
- [ ] 仍有开放条件的边降级到 `CANDIDATE_CHAIN` 或 `POTENTIAL_EDGE`

## 候选链保留

- [ ] `PROBABLE` / `HYPOTHESIS` 只进入 `CANDIDATE_CHAIN`
- [ ] 标明缺失证据、运行时阻塞点或租户/主体连续性缺口
- [ ] 不把候选链计入 confirmed readiness

## 报告与交接

- [ ] 每条 confirmed path 都有真实 `VULN-ID`
- [ ] 输出 `ATTACK_PATH`、`CANDIDATE_CHAIN`、`POTENTIAL_EDGE`
- [ ] 仅将 confirmed execution-ready 项目写入 `EXPLOIT_QUEUE_FINAL`
- [ ] probable review 项目单独进入 phase 3
- [ ] 不将 speculative 复合链直接写回 `EXPLOIT_QUEUE`
