---
name: code-audit
description: Evidence-driven white-box code security audit for repositories, diffs, patch reviews, supply-chain checks, and AI or agent security paths.
tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
  - LSP
  - WebSearch
  - HTTP
model: sonnet
priority: high
file_patterns:
  - "**/*.java"
  - "**/*.py"
  - "**/*.go"
  - "**/*.php"
  - "**/*.js"
  - "**/*.ts"
  - "**/*.jsx"
  - "**/*.tsx"
  - "**/*.c"
  - "**/*.cpp"
  - "**/*.h"
  - "**/*.cs"
  - "**/*.rb"
  - "**/*.rs"
  - "**/*.xml"
  - "**/*.yml"
  - "**/*.yaml"
  - "**/*.json"
  - "**/*.properties"
  - "**/*.lock"
  - "**/*.toml"
  - "**/Dockerfile"
  - "**/*.tf"
  - "**/pom.xml"
  - "**/build.gradle"
  - "**/go.mod"
  - "**/composer.json"
  - "**/package.json"
  - "**/.github/workflows/*.yml"
  - "**/.gitlab-ci.yml"
  - "**/Jenkinsfile"
exclude_patterns:
  - "**/node_references/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.git/**"
  - "**/__pycache__/**"
---

# Code Audit Skill v6.0

Optimized from code audit expert and senior penetration testing engineer perspectives: enhanced taint/bypass analysis, better reporting with CWE/OWASP/CVSS, stricter evidence requirements, and improved gadget/deserialization hunting.

## v6.0 Hardening Overrides

- Frontmatter keys in this file and in named subagents must stay parseable.
- Bundled prompts in `subagents/` are the versioned authority. External `.claude/agents/` copies are deployment mirrors and must stay byte-identical.
- `test/` and `tests/` are not hard-excluded at the frontmatter layer. Recon decides whether they belong in scope.
- The `[PLAN]` gate is mode-aware: `quick`, `quick-diff`, CI, smoke, benchmark, and automation runs continue automatically unless the user explicitly asks to pause.
- Formal findings remain `CONFIRMED` and `CHAINED` only.
- `PROBABLE` stays in manual review and Burp phase 3.
- `HYPOTHESIS` stays out of formal counts unless later upgraded.

## Non-Negotiables

- No formal finding without real code reads.
- No fabricated paths, line numbers, versions, or impacts.
- CVE intel can guide priority but cannot replace project-local evidence.
- Strong controls suppress premature confirmation.
- Uncertain findings stay alive as `PROBABLE` or `HYPOTHESIS`; they are not discarded.

## Lifecycle

States:

- `SIGNAL`
- `CANDIDATE`
- `PROBABLE`
- `HYPOTHESIS`
- `CONFIRMED`
- `CHAINED`
- `[FP]`

Compatibility mapping:

- `CONFIRMED_CANDIDATE` -> `CANDIDATE`
- `HYPOTHESIS_CANDIDATE` -> `PROBABLE`

Formal counts include only:

- `CONFIRMED`
- `CHAINED`

## Evidence Slots

- `E1`: attacker-controlled input or control gap
- `E2`: real dangerous sink or real missing control
- `E3`: reachable path
- `E4`: defense assessment completed **+ Adversarial Analysis Protocol executed with Bypass Feasibility Matrix**
- `E5`: real impact
- `E6`: chain or expansion value

- ### Adversarial Analysis Protocol (对抗性审查协议) - 必须强制执行

对于每一个 CANDIDATE 及以上 finding，审计师必须立即切换 **Red Team 视角**（你拥有完整源代码、生产部署环境、全部配置权限，是最高权限的攻击者）：

1. **主动枚举真实 Bypass 向量**（至少列出 3 种以上攻击者常用手法）：
   - Framework 默认防护绕过（配置覆盖、注解禁用、order 优先级、环境变量、热加载等）
   - Reflection / DI / Proxy / Decorator / AOP / Dynamic Proxy / Metaprogramming 注入
   - Second-order taint / Persistent storage / Cache / MQ / Event Bus / Async contamination
   - Race condition / TOCTOU / 状态机覆盖 / 并发逻辑
   - Version boundary / 未打全补丁 / Dev vs Prod / 环境差异绕过
   - Control-flow flattening、opaque predicates、split-sink、delayed execution 等对抗静态分析/LLM 的技巧
   - LLM / Agent / Tool-calling 信任边界污染

2. **Bypass Feasibility Assessment**（必须输出以下标准化矩阵）：
   | Bypass 向量                  | 可行性 (High/Med/Low) | 具体代码路径/证据/行号          | 当前防御是否可被绕过 |
   |-----------------------------|-----------------------|---------------------------------|---------------------|

3. **结论规则**：
   - 只有**所有 High/Med 可行性 Bypass 向量**均被**有效、不可绕过地**缓解，才允许 E4 判定为“充分防御”。
   - 否则**不得**提升至 CONFIRMED，必须保持 PROBABLE 或 HYPOTHESIS。
   - 所有分析必须附带**真实代码路径 + 行号 + 调用栈证据**，禁止任何“理论上”“可能”等模糊表述。

4. 本协议由 `adversarial-simulator` 子代理执行，或在 `taint-analyst` / `patch-bypass-auditor` 中强制集成。

Promotion guidance:

- `CANDIDATE`: real signal worth tracing
- `PROBABLE`: E1 to E3 mostly closed, with one important gap left in defense or impact
- `HYPOTHESIS`: larger evidence gaps remain
- `CONFIRMED`: E1 to E5 closed and report contract complete，且 Adversarial Analysis Protocol 已完成，所有 High/Med Bypass 向量均被充分不可绕过地缓解
- `CHAINED`: multiple confirmed findings form a stronger attack path

## Modes

- `quick`: fast risk triage
- `quick-diff`: diff-focused review
- `standard`: normal repository audit
- `deep`: critical targets and chain work

## Recon Requirements

Recon must always emit:

- `[RECON]`
- `[COVERAGE_MATRIX]`
- `[VULN_QUEUE]`

Recon must also make a `TEST_DIR_DECISION`:

- high-value targets: force tests into scope
- ordinary targets: include only if they materially shape reachability, ownership, fixtures, or exploit setup
- pure unit tests with no production impact: may stay out of scope with a reason

## Plan Gate

`[PLAN]` is required before execution.

- interactive `standard` and `deep` audits pause after `[PLAN]`
- `quick`, `quick-diff`, smoke, CI, benchmark, and automation continue automatically after `[PLAN]`

`[PLAN]` should include:

- mode
- stack summary
- coverage summary
- activated `VULN_QUEUE`
- specialist routes such as patch bypass, taint, gadget, or `.NET`

## Output Contract

Main reporting shape:

```text
[MODE] ...
[RECON] ...
[COVERAGE_MATRIX] ...
[VULN_QUEUE] ...
[PLAN] ...
[REPORT]
Formal findings:
- VULN-01 | CONFIRMED | ...

Manual review:
- VULN-02 | PROBABLE | ...
- VULN-03 | HYPOTHESIS | ...

Excluded:
- VULN-04 | [FP] | ...
```

## Queue And Handoff Rules

- `EXPLOIT_QUEUE` may contain `CONFIRMED`, clear `PROBABLE`, and high-value `HYPOTHESIS` for later validation.
- Burp phase 2 is for confirmed execution-ready items.
- Burp phase 3 is for probable review items.
- Downstream tools must not silently collapse lifecycle states.

## Triad Interop Rules

When `code-audit` coordinates with `dotnet-audit`, `burp-suite`, or both, load `../_shared/security-audit-interop.md` before emitting or consuming protocol blocks.

- `dotnet_shared_context` is the canonical shared context key.
- If an older alias such as `shared_context` or `DOTNET_SHARED_CONTEXT` is received, normalize it to `dotnet_shared_context` before continuing.
- `code-audit -> dotnet-audit` handoff must use `[DOTNET_HANDOFF]`.
- `dotnet-audit -> code-audit` return traffic must use `[HANDOFF_ACK]` and `[SHARED_CONTEXT_WRITEBACK]`.
- `burp-suite -> dotnet-audit` reverse discovery must use `[DOTNET_SURFACE_FEED]`, and the acknowledgment path must use `[SURFACE_FEED_ACK]`.
- `JOINT_SESSION` is the single authority for shared triad state when Burp is in the loop.
- No handoff may silently rename, drop, or flatten triad protocol fields.

## Load-On-Demand Map

The primary prompts stay thin on purpose. Depth comes from loading the right reference files for the current target instead of inlining every pattern at all times.

Use `references/core/load_on_demand_map.md` as the routing index, then load only the sections relevant to the current stack, finding type, and mode.

### Core References

Load these when the matching question appears:

- hallucination or evidence discipline -> `references/core/anti_hallucination.md`
- verdict, exploitability, or defense sufficiency -> `references/core/verification_methodology.md`
- sink, source, or taint reasoning depth -> `references/core/taint_analysis.md`, `references/core/sinks_sources.md`
- false-positive pressure or strong control review -> `references/core/false_positive_filter.md`
- coverage or depth planning -> `references/checklists/coverage_matrix.md`, `references/core/phase2_deep_methodology.md`
- attack-path prioritization -> `references/core/chain_synthesis.md`, `references/core/attack_path_priority.md`

### Language References

After stack detection, load only the language files that match the code under review:

- Java -> `references/languages/java.md`
- JavaScript or TypeScript -> `references/languages/javascript.md`
- Python -> `references/languages/python.md`
- PHP -> `references/languages/php.md`
- Go -> `references/languages/go.md`
- `.NET` -> `references/languages/dotnet.md`
- Ruby -> `references/languages/ruby.md`
- Rust -> `references/languages/rust.md`
- C or C++ -> `references/languages/c_cpp.md`

### Framework References

Load framework notes only when the framework is actually present:

- Spring / Spring Boot -> `references/frameworks/spring.md`
- MyBatis -> `references/frameworks/mybatis_security.md`
- Express / Koa / Nest / Fastify -> matching files in `references/frameworks/`
- Flask / Django / FastAPI -> matching files in `references/frameworks/`
- Laravel / Rails / Gin / Rust web / `.NET` -> matching files in `references/frameworks/`

### Security Topic References

Load these only when the target or current finding activates them:

- auth, authz, IDOR, multi-tenant access -> `references/security/authentication_authorization.md`
- file upload, traversal, archive extraction -> `references/security/file_operations.md`
- API, GraphQL, gateway, proxy -> matching files in `references/security/`
- LLM, MCP, tool abuse, agent trust -> `references/security/llm_security.md`, `references/security/cross_service_trust.md`
- race, state machine, payment logic -> `references/security/race_conditions.md`, `references/security/business_logic.md`
- infra and supply chain -> `references/security/infra_supply_chain.md`, `references/security/dependencies.md`

### Deserialization And Bypass References

Load these only when the entrypoint exists:

- generic deserialization bypass and filters -> `references/checklists/deserialization_filter_bypass.md`
- Java deserialization, Fastjson, JNDI, script engines -> matching files in `references/languages/`
- gadget enumeration and chain help -> `references/core/gadget_enum.md`, `references/checklists/gadget.md`
- patch bypass and version boundaries -> `references/core/bypass_strategies.md`, `references/core/version_boundaries.md`

### Historical Case References

When real-world exploit pattern mining is useful, start with `references/wooyun/INDEX.md` and then load only the matching scenario file:

- SQL injection -> `references/wooyun/sql-injection.md`
- XSS -> `references/wooyun/xss.md`
- command execution -> `references/wooyun/command-execution.md`
- business logic flaws -> `references/wooyun/logic-flaws.md`
- file upload -> `references/wooyun/file-upload.md`
- unauthorized access / IDOR -> `references/wooyun/unauthorized-access.md`
- information disclosure -> `references/wooyun/info-disclosure.md`
- file traversal -> `references/wooyun/file-traversal.md`
- patch bypass -> `references/wooyun/bypass_cases.md`

## Canonical Ownership

- `SKILL.md` owns lifecycle and formal-finding semantics.
- `agent.md` owns orchestration and dispatch.
- named subagents own bounded specialist evidence.
