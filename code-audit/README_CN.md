# Code Audit 代码安全审计技能

> 证据驱动的白盒代码安全审计技能。主技能更短，但正式漏洞裁决、更严格的状态机和 precision/recall 回归锚点都被保留下来。

## 概述

`code-audit` 用于审计代码仓库、补丁和安全敏感实现。它不会把简单的关键字命中直接当成漏洞，而是要求把代码证据、可达性、防护有效性和业务影响一起核对后再做正式裁决。

## 当前职责边界

本版本采用明确分层:

- `SKILL.md` 负责:
  - finding lifecycle
  - 升级/降级规则
  - 正式漏洞统计口径
  - 报告门禁
- `agent.md` 负责:
  - multi-agent 执行机制
  - subagent 编排
  - 详细 handoff 协议
  - 执行时路由与聚合

这样可以避免执行细节反过来污染“什么算正式漏洞”的语义。

## 统一状态机

所有发现都应归一到以下状态:

- `SIGNAL`
- `CANDIDATE`
- `PROBABLE`
- `HYPOTHESIS`
- `CONFIRMED`
- `CHAINED`
- `[FP]`

旧状态兼容:

- `CONFIRMED_CANDIDATE` -> `CANDIDATE`
- `HYPOTHESIS_CANDIDATE` -> `PROBABLE`

正式漏洞统计只包含:

- `CONFIRMED`
- `CHAINED`

`PROBABLE` 与 `HYPOTHESIS` 进入人工复核和验证队列，不计入正式漏洞。

## 证据模型

裁决基于 E1-E6 六个证据槽:

| 槽位 | 含义 |
|------|------|
| `E1` | 输入可控或控制缺口可触发 |
| `E2` | 危险 sink 或控制缺口真实存在 |
| `E3` | 路径真实可达 |
| `E4` | 防护评估完成 |
| `E5` | 真实业务影响成立 |
| `E6` | 可链化或横向扩展价值 |

升级逻辑:

- `PROBABLE`: E1-E3 基本闭合，但 E4 或 E5 还缺一个关键证据
- `HYPOTHESIS`: 证据缺口较大，但风险信号明确
- `CONFIRMED`: E1-E5 闭合，且报告契约满足
- `CHAINED`: 多个 `CONFIRMED` 组合后形成更高价值攻击链

## 平衡策略

本版本追求“平衡”而不是极端:

- 有效控制措施应抑制误报，避免过早进入 `CONFIRMED`
- 不确定但有价值的发现应保留在 `PROBABLE` 或 `HYPOTHESIS`
- 只有“不是最佳实践”的问题，不应被包装成正式漏洞

通常会阻断 `CONFIRMED` 的强控制包括:

- enum / 强类型边界
- 真 allowlist
- 真参数化查询
- 上下文正确的输出编码
- 真实对象归属检查
- 已确认生效的框架自动防护

通常会触发降级的情况包括:

- 没有实际读取 sink 代码
- 没有读取净化/防护实现
- 版本未确认
- 数据流断链
- 业务影响只是猜测

## 模式

| 模式 | 场景 |
|------|------|
| `quick` | CI 冒烟、小仓库快速分诊 |
| `quick-diff` | PR / diff 增量审计 |
| `standard` | 常规仓库审计 |
| `deep` | 关键目标、攻防链、深度专项分析 |

## 保留的兼容契约

本次重构保留以下外部接口与语义:

- `Phase -1` 到 `Phase 6`
- `EXPLOIT_QUEUE`
- `POC_READY`
- 9 字段漏洞报告
- `code-audit -> dotnet-audit` handoff 入口
- `code-audit -> burp-suite` handoff 入口

## Hardening Notes (2026-03-31)

- Frontmatter 已被视为运行时契约的一部分，主技能与 subagent 的元数据必须可解析。
- 版本化 specialist prompt 现在放在 `subagents/` 下，外部 `.claude/agents/` 仅作为部署副本，必须与 `subagents/` 保持字节级一致。
- `test/` 与 `tests/` 不再被前置硬排除，是否纳入由 recon 决定。
- `chain-synthesizer` 的正式链路仅允许 `CONFIRMED/CHAINED` 节点，`PROBABLE` 和 `HYPOTHESIS` 只能保留在人工复核或候选链中。
- `smoke-audit.ps1` 默认执行语义回归，不再只做静态锚点检查。

## 回归锚点

README 中承诺的最小回归夹具现在应真实存在于:

- `tests/fixtures/precision-java/src/SafeSearchController.java`
- `tests/fixtures/recall-java/src/VulnerableUserController.java`

期望:

- precision fixture 不得被报成正式 `CONFIRMED` SQLi
- recall fixture 应保持为可确认的 SQLi 路径

更完整的回归方法见:

- `references/core/benchmark_methodology.md`

可用的本地回归脚本:

- `tests/validate-hardening.ps1` 用于协议、路由与副本一致性校验
- `tests/smoke-interop.ps1` 用于 triad 协议回归
- `tests/smoke-audit.ps1` 用于 fixture 能力 sanity + 默认语义回归

## 目录结构

```text
code-audit/
├── SKILL.md
├── agent.md
├── subagents/
├── README.md
├── README_CN.md
├── tests/fixtures/
└── references/
```

## 维护约束

当你修改以下语义时，必须同步:

- lifecycle
- verdict gate
- report semantics
- 正式漏洞统计口径

同时要:

- 先更新 `SKILL.md`
- 保持 `agent.md` 只负责执行机制
- 同步 `README.md` 与 `README_CN.md`
- 确保 fixture 路径真实存在

## 免责声明

本技能仅用于经过授权的安全测试。使用者必须拥有合法授权，并遵守适用法律、伦理规范与负责任披露原则。
