# Security Audit Interop

This file is the canonical triad protocol for `code-audit`, `dotnet-audit`, and `burp-suite`.

When any two or all three coordinate, this file wins over local wording in the participating skills.

## Hardening Note (2026-04-01)

- Lifecycle truth comes from the participating skills, especially `code-audit`.
- `CONFIRMED` and `CHAINED` remain the only formal finding states in the broader triad.
- `PROBABLE` is a first-class manual-review state and must not be collapsed into `HYPOTHESIS` or silently dropped during handoff.
- Legacy urgency labels such as `P0/P1` may appear in historical notes, but they are not lifecycle fields.
- **v6.1 FN/FP Balance**: Synced "Avoiding False Negatives During FP Filtering" from code-audit. Requires sibling path search and cross-subagent validation before marking [FP] in shared context.

## Canonical Keys

- shared context key: `dotnet_shared_context`
- accepted legacy aliases on read: `shared_context`, `DOTNET_SHARED_CONTEXT`
- canonical write-back key after normalization: `dotnet_shared_context`

## Canonical Keys

- shared context key: `dotnet_shared_context`
- accepted legacy aliases on read: `shared_context`, `DOTNET_SHARED_CONTEXT`
- canonical write-back key after normalization: `dotnet_shared_context`

## [DOTNET_HANDOFF]

```yaml
[DOTNET_HANDOFF]
protocol_version: triad-2026-04
source_skill: code-audit v5.8+
target_skill: dotnet-audit v3.3+
session_mode: batch|realtime
audit_mode: quick|standard|deep
handoff_priority: critical|high|standard
project_root: {absolute path}
trigger_signals: ["*.csproj", "packages.config", "obfuscated dll"]
audit_scope:
  include_paths: ["..."]
  focus_areas: ["DESERIALIZATION", "VIEWSTATE", "LLM_SECURITY", "SUPPLY_CHAIN"]
  skip_phases: ["Phase -1", "Phase 0"]
known_cve:
  - id: CVE-XXXX-YYYY
    severity: critical|high|medium|low
vuln_queue_active: ["DESERIALIZATION_QUEUE"]
coverage_matrix_delta: ["module-auth", "AdminController::Login"]
dotnet_shared_context:
  framework_family: ASP.NET|ASP.NET Core|WCF|WebForms|unknown
  framework_version: {version|null}
  project_structure: {summary}
  global_auth_state: {summary}
  recon_completed: ["Phase -1", "Phase 0"]
  high_risk_findings: ["..."]
  deobfuscation_confidence: High|Medium|Low|Unchecked
  viewstate_rce_feasible: true|false|unchecked
  dotnet_gadget_chains: []
  nuget_cve_list: []
  llm_injection_queue: []
```

## [HANDOFF_ACK]

```yaml
[HANDOFF_ACK]
protocol_version: triad-2026-04
received_from: code-audit v5.8+
normalized_context_key: dotnet_shared_context
shared_context_loaded: true|false
skipped_phases: ["Phase -1", "Phase 0"]
audit_scope_applied: {summary}
js_id: JS-{hash8}|STANDALONE
next_phase: Phase 1|Phase 0S|AI-11
```

## [SHARED_CONTEXT_WRITEBACK]

```yaml
[SHARED_CONTEXT_WRITEBACK]
protocol_version: triad-2026-04
source_skill: dotnet-audit v3.3+
target_skill: code-audit v5.8+
js_id: JS-{hash8}|STANDALONE
coverage_matrix_delta: ["..."]
dotnet_findings:
  obfuscation: {type + restore rate}
  confirmed_vulns: [{EXPLOIT_QUEUE items}]
  probable_review: [{manual review items}]
  hypothesis_notes: [{exploration-only notes}]
  fp_list: [{reason}]
  supply_chain: {Phase 0S result}
  llm_ai_vulns: [{LLM_INJECTION_QUEUE items}]
  deobfuscation_confidence: High|Medium|Low|Unchecked
  viewstate_rce_confirmed: true|false|unchecked
```

## [DOTNET_SURFACE_FEED]

```yaml
[DOTNET_SURFACE_FEED]
protocol_version: triad-2026-04
source_skill: burp-suite v2.4+
target_skill: dotnet-audit v3.3+
js_id: JS-{hash8}|STANDALONE
surface_type: VIEWSTATE|WEBFORMS|WCFENDPOINT|ASMXSERVICE|APICONTROLLER
endpoint: {METHOD path}
evidence: {header|body|cookie signal}
suggested_phase: Phase 3B|AI-11|Phase 0E|Phase 0S
related_vuln_id: VULN-N|null
```

## [SURFACE_FEED_ACK]

```yaml
[SURFACE_FEED_ACK]
protocol_version: triad-2026-04
received_from: burp-suite v2.4+
target_skill: dotnet-audit v3.3+
js_id: JS-{hash8}|STANDALONE
surfaces_received: {N}
coverage_matrix_updated: true|false
action: {surface_type -> phase mapping}
status: PROCESSING|QUEUED|SKIPPED_DUPLICATE
```

## JOINT_SESSION Rules

- `JOINT_SESSION` is the single authority for triad shared state.
- Writers must append or merge, not silently overwrite incompatible data.
- `.NET` triad fields must use `dotnet_audit_version`, `deobfuscation_confidence`, `dotnet_gadget_chains`, `viewstate_rce_feasible`, `nuget_cve_list`, and `llm_injection_queue`.
- Shared write-back should preserve `confirmed_vulns`, `probable_review`, `hypothesis_notes`, and `fp_list` as distinct buckets.
- If `deobfuscation_confidence=Low`, `.NET`-specific Burp or static conclusions must be downgraded to `HYPOTHESIS` or `INCONCLUSIVE`.
