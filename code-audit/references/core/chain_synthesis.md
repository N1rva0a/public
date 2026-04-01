# Attack Path Synthesis Methodology

> Use this reference to connect already-vetted findings into attacker-realistic paths without inflating speculative material into formal results.

## Authority

- `SKILL.md` and `chain-synthesizer` own lifecycle semantics.
- This file helps with path construction, edge gating, and handoff packaging only.
- Formal attack paths use finalized findings only.

## Inputs

Start from a `FINALIZED_FINDING_INDEX` where each node already has:

- `VULN-ID`
- finalized lifecycle state
- prerequisite summary
- impact summary
- report path

Feed-only context such as version intel, `.NET` surface enrichment, or speculative operator notes may inform ranking, but it does not become a formal node until the coordinator maps it to a finalized finding.

## Graph Classes

### ATTACK_PATH

Use only when every node is `CONFIRMED`.

### CANDIDATE_CHAIN

Use when any edge or node still depends on:

- `PROBABLE`
- `HYPOTHESIS`
- feed-only context
- unresolved runtime blockers

These chains are useful for prioritization and validation planning, not for formal counting.

### POTENTIAL_EDGE

Use when two findings look related but at least one edge gate is still open.

## Edge Gates

Promote an edge into a formal `ATTACK_PATH` only when all of the following are closed with code-backed evidence:

1. asset or service continuity
2. route or reachability continuity
3. principal, tenant, or trust-boundary continuity
4. reusable artifact or prerequisite continuity
5. no unresolved blocker that would keep the relation speculative

If any gate remains open, downgrade to `CANDIDATE_CHAIN` or `POTENTIAL_EDGE`.

## Workflow

1. Collect finalized findings and classify each by attacker capability:
   - information disclosure
   - authentication or authorization foothold
   - privilege expansion
   - code execution or data plane control
   - persistence or lateral movement
2. Record prerequisites and outputs for each finding.
3. Evaluate pairwise edges with the edge gates above.
4. Build the shortest high-value confirmed paths first, then retain unresolved but valuable relations as candidate chains.
5. Rank paths by exploitability, blast radius, and blocker count.
6. Prepare handoff artifacts without mutating the raw finding lifecycle.

## Ranking Rules

- Shorter confirmed paths outrank longer confirmed paths with the same impact.
- Confirmed paths outrank candidate chains.
- Candidate chains with one open gate outrank chains with multiple unresolved gates.
- Large blast radius matters only after lifecycle truth is preserved.

## Handoff Discipline

- confirmed, execution-ready items feed `EXPLOIT_QUEUE_FINAL` / Burp phase 2
- probable review items feed Burp phase 3
- hypothesis-only ideas remain appendix or manual-review material

Do not write speculative compound paths back into `EXPLOIT_QUEUE` as if they were new findings.

## Do Not

- do not consume `HYPOTHESIS` as a formal path node
- do not turn ranking labels into severity or lifecycle upgrades
- do not cap chain length arbitrarily; stop when evidence quality falls off
- do not count candidate chains toward confirmed readiness metrics

## Output Sketch

```text
[VULN_GRAPH]
...

[ATTACK_PATH_01]
nodes:
- VULN-01 | CONFIRMED | ...
- VULN-04 | CONFIRMED | ...
why_it_connects: ...

[CANDIDATE_CHAIN_01]
nodes:
- VULN-02 | PROBABLE | ...
- VULN-07 | CONFIRMED | ...
open_gates:
- tenant continuity

[POTENTIAL_EDGE]
from: VULN-03
to: VULN-08
blocked_by:
- missing route proof

[EXPLOIT_QUEUE_FINAL]
phase2_rows: ...
phase3_rows: ...
```
