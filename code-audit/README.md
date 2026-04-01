# Code Audit Skill for Claude Code

> Evidence-driven white-box code security audit skill with a compact verdict authority, explicit finding lifecycle, and regression-backed precision/recall anchors.

## Overview

`code-audit` is a static white-box security audit skill for code repositories, patches, and security-sensitive implementations. It does not treat keyword hits as vulnerabilities by default. A finding becomes formal only after code evidence, reachability, defense assessment, and impact are checked together.

## Current Architecture Boundary

The current architecture is intentionally split:

- `SKILL.md` is the single authority for:
  - finding lifecycle
  - verdict promotion and demotion
  - formal vulnerability counting
  - report gate semantics
- `agent.md` owns:
  - multi-agent execution mechanics
  - subagent orchestration
  - detailed handoff contracts
  - execution-time routing and aggregation

This keeps the main skill short and prevents execution details from silently redefining what counts as a formal finding.

## Formal Finding Lifecycle

Every finding should normalize into one of these states:

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

Formal vulnerability statistics include only:

- `CONFIRMED`
- `CHAINED`

`PROBABLE` and `HYPOTHESIS` stay in manual review and verification queues. `[FP]` is explicitly excluded.

## Evidence Model

The verdict gate uses six evidence slots:

| Slot | Meaning |
|------|---------|
| `E1` | attacker-controlled input or control gap |
| `E2` | real dangerous sink or real missing control |
| `E3` | reachable path from source/gap to sink |
| `E4` | defense assessment completed |
| `E5` | real business impact established |
| `E6` | chain value or lateral expansion potential |

Promotion guidance:

- `PROBABLE`: E1-E3 mostly closed, one key gap remains in E4 or E5
- `HYPOTHESIS`: significant evidence gaps remain
- `CONFIRMED`: E1-E5 closed and report contract complete
- `CHAINED`: multiple `CONFIRMED` findings produce a stronger attack path

## Precision And Recall Policy

The skill is optimized for balance:

- strong controls should suppress premature `CONFIRMED`
- uncertain findings should be preserved as `PROBABLE` or `HYPOTHESIS`, not discarded
- best-practice-only observations should not be promoted into formal vulnerabilities

Examples of controls that usually block `CONFIRMED`:

- enum or strong-type input boundaries
- real allowlists
- real parameterized queries
- context-correct encoding
- real authorization or object-ownership checks
- confirmed framework auto-protection

Examples that force downgrade:

- sink code not actually read
- defense implementation not read
- version guessed rather than confirmed
- broken or black-box call chain
- impact asserted but not shown

## Modes

| Mode | Use Case |
|------|----------|
| `quick` | CI smoke checks, small repositories |
| `quick-diff` | PR and diff-focused audit |
| `standard` | regular repository audit |
| `deep` | critical targets, exploit-chain work, high-risk systems |

## Hardening Notes (2026-03-31)

- Frontmatter is now treated as part of the runtime contract. Skill and subagent metadata must remain parseable.
- Versioned specialist prompts now live under `subagents/`. External `.claude/agents/` copies are deployment mirrors and should be kept byte-identical.
- `test/` and `tests/` are no longer frontmatter-hard-excluded. Recon decides whether they should be scanned.
- `[PLAN]` pauses only for interactive `standard` and `deep` audits. `quick`, `quick-diff`, smoke, benchmark, and CI flows continue automatically unless the user asks to stop.
- `chain-synthesizer` must preserve the authoritative lifecycle: formal findings are `CONFIRMED` and `CHAINED`, `PROBABLE` stays in manual review, and `HYPOTHESIS` remains non-formal until upgraded.
- `patch-bypass-auditor` is evidence-producing only. Static patch-bypass ideas do not become exploit-ready queue items without a later verdict.

Legacy body sections may still contain historical or encoding-damaged guidance. When that happens, the frontmatter, hardening notes, and canonical contract sections in the main files and subagents are authoritative.

## Thin-To-Thick Loading

The main prompts are intentionally compact. Depth is restored by loading the right files from `references/` on demand instead of inlining every language, framework, and scenario rule into `SKILL.md` or `agent.md`.

See `references/core/load_on_demand_map.md`.

## Compatibility Contracts Preserved

The refactor keeps these external contracts intact:

- `Phase -1` through `Phase 6`
- `EXPLOIT_QUEUE`
- `POC_READY`
- 9-field report structure
- `code-audit -> dotnet-audit` handoff entry
- `code-audit -> burp-suite` handoff entry

## Regression Anchors

The documented fixtures now live at real paths:

- `tests/fixtures/precision-java/src/SafeSearchController.java`
- `tests/fixtures/recall-java/src/VulnerableUserController.java`

Expected behavior:

- the precision fixture should not become a formal `CONFIRMED` SQL injection
- the recall fixture should remain a `CONFIRMED` SQL injection candidate

See `references/core/benchmark_methodology.md` for the broader regression workflow.

Available local regression scripts:

- `tests/validate-hardening.ps1` for contract and routing integrity
- `tests/smoke-interop.ps1` for triad protocol integrity
- `tests/smoke-audit.ps1` for fixture-based capability sanity and default semantic model checks

## Repository Layout

```text
code-audit/
+-- SKILL.md
+-- agent.md
+-- subagents/
+-- README.md
+-- README_CN.md
+-- tests/fixtures/
`-- references/
```

## Contributing

When changing lifecycle, verdict rules, report semantics, or formal finding counting:

- update `SKILL.md` first
- keep `agent.md` focused on execution mechanics
- sync `README.md` and `README_CN.md`
- keep the regression fixture paths real

## Disclaimer

This skill is intended for authorized security testing only. Users must have permission to audit the target and must follow applicable laws and responsible disclosure practices.
