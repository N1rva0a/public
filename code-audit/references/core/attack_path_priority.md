# Attack Path Prioritization

> Use this reference to rank already-modeled paths by attacker utility. It does not redefine lifecycle, severity, or formal finding eligibility.

## Hardening Rules

- Path priority is downstream of lifecycle truth.
- `CONFIRMED`, `PROBABLE`, and `HYPOTHESIS` keep their original states; ranking never upgrades them.
- Historical "P0/P1" style labels are retired here to avoid confusion with severity or formal counts.
- Strong controls lower priority only after the real control was read and its scope was verified.

## Ranking Dimensions

Score or describe each path across these dimensions:

1. **authentication burden**
   - public
   - low-privilege user
   - privileged user
   - operator or admin
2. **request complexity**
   - single request
   - short sequence
   - race or timing dependent
   - long workflow or multi-actor
3. **operator dependency**
   - no human interaction
   - low-friction victim action
   - admin review or delayed trigger
4. **tooling barrier**
   - browser or curl
   - common tooling
   - custom exploit or environment shaping
5. **blast radius**
   - single object
   - tenant or account scope
   - cross-tenant or infrastructure scope
6. **chain fragility**
   - all prerequisites reusable
   - some prerequisites one-shot or timing-sensitive
   - path breaks if any open gate fails

## Suggested Priority Bands

Use descriptive bands rather than formal states:

- `Immediate`: short confirmed path, low operator burden, high blast radius
- `High`: confirmed or near-confirmed path with one meaningful friction point
- `Standard`: useful but narrower or more fragile path
- `Appendix`: speculative or low-payoff path kept for completeness

## Practical Guidance

- A public data leak that unlocks authenticated takeover may outrank an admin-only RCE if the first path is confirmed and repeatable.
- A confirmed path always outranks a more dramatic but speculative chain.
- Candidate chains are still worth ranking, but they should be labeled clearly as speculative and kept out of confirmed readiness math.

## Output Example

```text
[HANDOFF_SUMMARY]
path_rankings:
- ATTACK_PATH_01 | Immediate | public entrypoint, single request, tenant-wide impact
- ATTACK_PATH_02 | High | authenticated path, two steps, reusable artifact
- CANDIDATE_CHAIN_01 | Appendix | speculative tenant continuity
```

## Final Rule

Priority is for sequencing analyst attention and remediation focus.
It must never be used as a shortcut to inflate certainty.
