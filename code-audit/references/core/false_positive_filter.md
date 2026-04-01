# Strong Control Review

> Use this file to suppress premature confirmation, not to auto-dismiss findings from heuristics.

## Hardening Rules

- Heuristics are escalation hints, not verdicts.
- Never downgrade based only on a type name, annotation, framework reputation, or helper name.
- Read the actual control implementation before concluding that it blocks exploitation.
- Multi-path systems stay live until every reachable sibling path is reviewed.

## What This Reference Is For

Use it when a path looks dangerous but strong controls may exist:

- strong types or allowlists
- DTO validation and coercion
- global filters or middleware
- ORM parameterization
- authorization or ownership checks
- framework auto-protection claims

The goal is to answer one question honestly:

`Does this specific control, on this specific path, close E4 strongly enough to block promotion?`

## Review Workflow

1. Identify the claimed control on the live path.
2. Read the real implementation or generated code that enforces it.
3. Confirm activation scope:
   - which routes it covers
   - which sinks it protects
   - whether sibling entrypoints bypass it
4. Check context fit:
   - HTML encoding is not SQL protection
   - DTO validation is not ownership enforcement
   - parameterization does not save string-built identifiers
5. Decide the outcome:
   - `CONFIRMED` blocked only when the control is real, active, and context-correct
   - `PROBABLE` when the control exists but coverage or semantics are still unclear
   - `[FP]` only when the dangerous path is eliminated with code-backed evidence

## Control Families

### Strong Type Or Allowlist

Treat enum or allowlist usage as a clue to inspect, not an automatic safe outcome.

Read:

- parsing or coercion code
- fallback branches
- alternate entrypoints
- any conversion back to unsafe strings

### DTO Validation

`@Valid`, `@Pattern`, `@Email`, or similar annotations only help when:

- they execute on the live entrypoint
- they constrain the dangerous field in the relevant context
- later transformations do not re-open risk

### Global Filters Or Middleware

Filters help only when:

- they run before the sink
- exclusions or path bypasses are absent
- the wrapped request is what downstream code actually reads

### ORM And Query Safety

Parameterization blocks value injection, not:

- dynamic table or column names
- native queries rebuilt with string fragments
- second-order data reused in unsafe contexts

### Authorization And Ownership

Annotations or helper names are insufficient by themselves.

Read:

- effective security configuration
- resource ownership checks
- tenant scoping
- bypass routes such as exports, batch endpoints, jobs, or internal APIs

## Common False Assurance Patterns

- enum on one controller, raw string on another
- DTO validation on create path, no validation on import or update path
- filter exists, but excluded admin or upload routes bypass it
- parameterized value clause, but identifier or sort field is concatenated
- method annotation exists, but method security is not enabled

## Recommended Outcomes

| Situation | Outcome |
|---|---|
| control unread or activation uncertain | keep `PROBABLE` |
| control real but one sibling path remains open | keep path alive, usually `PROBABLE` |
| control real and blocks the exact sink on every reachable path | cap at `[FP]` or non-reportable |
| control only changes exploit difficulty | keep lifecycle truth, adjust impact wording later |

## Final Rule

Strong controls should prevent false positives.
They must never become a shortcut that hides real, bypassable, or cross-path vulnerabilities.

## New: Avoiding False Negatives During FP Filtering (v6.1 Enhancement)

To balance FP reduction with FN prevention:

- When a control is found, **always** search for sibling/bypass paths in the same module and dependent modules (use Grep for similar sinks).
- Never mark [FP] if any alternate entry point (API, batch, internal, admin, export) bypasses the control.
- For framework "auto-protection" claims, verify the actual middleware/filter execution order using code reads or LSP.
- Add explicit check for second-order flows and async taint propagation before closing a path.
- Cross-validate with taint-analyst and patch-bypass-auditor subagents before final [FP] verdict.

This ensures FP filtering does not create FN on complex attack paths.
