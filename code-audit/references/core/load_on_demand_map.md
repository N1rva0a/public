# Load-On-Demand Reference Map

Use this file as the thin-to-thick routing index for `code-audit`.

## Goal

Keep the primary prompts small and stable while recovering depth by loading the right reference files only when they are actually needed.

## Loading Rules

- Load the minimum set of references needed to answer the current question.
- Prefer core methodology files before language or framework specifics.
- Prefer language files before framework files when both apply.
- Prefer scenario files only when the code or intel actually activates them.
- Do not bulk-load whole directories by default.

## Core Routing

| Situation | Load |
|---|---|
| Need strict evidence discipline | `references/core/anti_hallucination.md` |
| Need exploitability or defense evaluation | `references/core/verification_methodology.md` |
| Need sink/source or taint depth | `references/core/taint_analysis.md`, `references/core/sinks_sources.md` |
| Need FP suppression | `references/core/false_positive_filter.md` |
| Need coverage planning | `references/checklists/coverage_matrix.md`, `references/core/phase2_deep_methodology.md` |
| Need path prioritization | `references/core/chain_synthesis.md`, `references/core/attack_path_priority.md` |

## Language Routing

| Stack | Load |
|---|---|
| Java | `references/languages/java.md` |
| JavaScript / TypeScript | `references/languages/javascript.md` |
| Python | `references/languages/python.md` |
| PHP | `references/languages/php.md` |
| Go | `references/languages/go.md` |
| `.NET` | `references/languages/dotnet.md` |
| Ruby | `references/languages/ruby.md` |
| Rust | `references/languages/rust.md` |
| C / C++ | `references/languages/c_cpp.md` |

## Framework Routing

| Framework | Load |
|---|---|
| Spring / Spring Boot | `references/frameworks/spring.md` |
| MyBatis | `references/frameworks/mybatis_security.md` |
| Express | `references/frameworks/express.md` |
| Koa | `references/frameworks/koa.md` |
| Nest / Fastify | `references/frameworks/nest_fastify.md` |
| Flask | `references/frameworks/flask.md` |
| Django | `references/frameworks/django.md` |
| FastAPI | `references/frameworks/fastapi.md` |
| Laravel | `references/frameworks/laravel.md` |
| Rails | `references/frameworks/rails.md` |
| Gin | `references/frameworks/gin.md` |
| `.NET` web stack | `references/frameworks/dotnet.md` |
| Rust web | `references/frameworks/rust_web.md` |

## Scenario Routing

| Scenario | Load |
|---|---|
| Authn / authz / IDOR | `references/security/authentication_authorization.md` |
| File upload or traversal | `references/security/file_operations.md` |
| API / GraphQL / proxy | matching files in `references/security/` |
| LLM / MCP / agent trust | `references/security/llm_security.md`, `references/security/cross_service_trust.md` |
| Business logic / race | `references/security/business_logic.md`, `references/security/race_conditions.md` |
| Infra / CI / supply chain | `references/security/infra_supply_chain.md`, `references/security/dependencies.md` |
| Patch bypass | `references/core/bypass_strategies.md`, `references/core/version_boundaries.md` |
| Deserialization | `references/checklists/deserialization_filter_bypass.md`, plus platform-specific language files |
| adversarial analysis, bypass feasibility, red team simulation → references/core/bypass_feasibility_matrix.md + subagents/adversarial-simulator.md |

## Historical Corpus Routing (WooYun)

Use `references/wooyun/INDEX.md` as the entry index whenever real-world exploit patterns or bypass playbooks are needed. Then load the single matching corpus file for the active scenario instead of bulk-loading the whole corpus.

| Scenario | Load |
|---|---|
| SQL injection | `references/wooyun/sql-injection.md` |
| XSS | `references/wooyun/xss.md` |
| Command execution | `references/wooyun/command-execution.md` |
| Business logic flaws | `references/wooyun/logic-flaws.md` |
| File upload | `references/wooyun/file-upload.md` |
| Unauthorized access / IDOR | `references/wooyun/unauthorized-access.md` |
| Information disclosure | `references/wooyun/info-disclosure.md` |
| File traversal | `references/wooyun/file-traversal.md` |
| Patch bypass | `references/wooyun/bypass_cases.md` |

## Checklist Routing

Use checklist files when you need broad, scenario-shaped audit prompts rather than one narrow sink or framework note.

| Situation | Load |
|---|---|
| Universal sanity pass across any stack | `references/checklists/universal.md` |
| Chain construction checklist | `references/checklists/chain_synthesis.md` |
| CI/CD review checklist | `references/checklists/cicd.md` |
| Supply-chain review checklist | `references/checklists/supply_chain.md` |
| Second-order review checklist | `references/checklists/second_order.md` |
| C / C++ checklist | `references/checklists/c_cpp.md` |
| `.NET` checklist | `references/checklists/dotnet.md` |
| Go checklist | `references/checklists/go.md` |
| Java checklist | `references/checklists/java.md` |
| JavaScript checklist | `references/checklists/javascript.md` |
| PHP checklist | `references/checklists/php.md` |
| Python checklist | `references/checklists/python.md` |
| Ruby checklist | `references/checklists/ruby.md` |
| Rust checklist | `references/checklists/rust.md` |

## Adapter Routing

Use adapter YAML files when a worker needs structured control-detection patterns or machine-readable language mappings.

| Stack | Load |
|---|---|
| Go adapter rules | `references/adapters/go.yaml` |
| Java adapter rules | `references/adapters/java.yaml` |
| JavaScript adapter rules | `references/adapters/javascript.yaml` |
| PHP adapter rules | `references/adapters/php.yaml` |
| Python adapter rules | `references/adapters/python.yaml` |

## Casebook Routing

Use the casebook when real-world anchor examples matter more than one exploit family.

| Situation | Load |
|---|---|
| Real-world grounding or benchmark comparison | `references/cases/real_world_vulns.md` |

## Extended Core Routing

Use these when the narrower core references are not enough:

| Situation | Load |
|---|---|
| Full end-to-end audit playbook | `references/core/comprehensive_audit_methodology.md` |
| Deep source-to-sink reasoning | `references/core/data_flow_methodology.md` |
| Dynamic validation planning | `references/core/dynamic_code_audit.md` |
| External tool selection | `references/core/external_tools_guide.md` |
| PoC design and payload shaping | `references/core/poc_generation.md` |
| Security-control modeling | `references/core/security_controls_methodology.md` |
| Machine-readable control matrix | `references/core/security_controls_matrix.yaml` |
| Control-engine implementation details | `references/core/security_controls_engine.py` |
| Security signal inventory | `references/core/security_indicators.md` |
| Semantic search or large-repo exploration | `references/core/semantic_search_guide.md` |
| Sensitive-operation classification | `references/core/sensitive_operations_matrix.md` |
| Alternate supply-chain methodology | `references/core/supply_chain.md` |
| Reflection or anti-drift review | `references/core/systematic_reflection.md` |
| Local script-driven audits | `references/core/audit.sh` |
| Benchmark or regression planning | `references/core/benchmark_methodology.md` |
| Capability baseline comparisons | `references/core/capability_baseline.md` |
| Container or image verification | `references/core/docker_verification.md` |

## Extended Framework And Language Routing

| Situation | Load |
|---|---|
| Generic Java web stack when framework is mixed or unclear | `references/frameworks/java_web_framework.md` |
| Go-specific security nuances beyond generic Go | `references/languages/go_security.md` |
| Practical Java audit heuristics | `references/languages/java_practical.md` |
| Java XXE review | `references/languages/java_xxe.md` |

## Extended Security Routing

| Scenario | Load |
|---|---|
| API gateway or reverse proxy trust boundaries | `references/security/api_gateway_proxy.md` |
| General API design and abuse review | `references/security/api_security.md` |
| Cache poisoning or host-header trust | `references/security/cache_host_header.md` |
| CI/CD security specifics | `references/security/cicd_security.md` |
| Cryptography review | `references/security/cryptography.md` |
| Frontend framework trust boundaries | `references/security/frontend_frameworks.md` |
| GraphQL review | `references/security/graphql.md` |
| HTTP smuggling or parsing ambiguity | `references/security/http_smuggling.md` |
| Input validation strategy | `references/security/input_validation.md` |
| Logging and audit trail security | `references/security/logging_security.md` |
| Native memory and unsafe boundary review | `references/security/memory_native.md` |
| Async message queue trust boundaries | `references/security/message_queue_async.md` |
| Mobile-specific audit surface | `references/security/mobile_security.md` |
| OAuth / OIDC / SAML review | `references/security/oauth_oidc_saml.md` |
| WebSocket / SSE / gRPC / realtime review | `references/security/realtime_protocols.md` |
| Scheduled task or cron review | `references/security/scheduled_tasks.md` |
| Serverless review | `references/security/serverless.md` |

## Subagent Hints

- `audit-intel` should emphasize supply-chain, framework, LLM-surface, and `.NET` routing references.
- `module-scanner` should emphasize coverage matrix, language, framework, and security-topic references.
- `taint-analyst` should emphasize taint, sanitizer, second-order, and LLM security references.
- `gadget-hunter` should emphasize deserialization, gadget, and platform-specific language references.
- `patch-bypass-auditor` should emphasize bypass, version-boundary, and historical-case references.
- `vuln-reporter` should emphasize verification and reporting references.
- `chain-synthesizer` should emphasize chain synthesis and attack-path priority references.
