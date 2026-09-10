# RELEASE R2 Independent Evidence Closure — Checker-Side Preregistration

Status: `FROZEN_BEFORE_NEW_EVIDENCE_MECHANISM`
Authority effect: `NONE_EVIDENCE_ONLY`
Candidate: `ffec566022fcd221fb4ab7569ed3bc245f75b546`
Checker baseline: `45604c8425bcad623be87d8f88106e509345e266`
Reviewer disposition being addressed: `INSUFFICIENT_EVIDENCE`

This checker-side preregistration mirrors the candidate-side frozen R2 evidence-closure contract before any new checker-owned evidence mechanism is introduced.

Required closure dimensions are: exact-SHA check evidence; live App-bound release ruleset; reproducible immutable ancestry proof plus negative vectors; checker revision provenance; adversarial harness/import isolation matrix; complete qualification-contributing dependency/test/helper/fixture/workflow/runtime closure; mutable workflow/dependency review; ruleset/bypass fail-closed evidence; authority separation without exposing the private signing key; RELEASE-vs-PRODUCTION contract mapping; and independently verifiable RED/preregistration chronology.

Any negative control that unexpectedly passes is a new RELEASE-blocking RED. It must be preserved and preregistered before repair. Missing or contradictory material evidence fails closed. CI, App checks, signatures, and reviewer/model outputs remain evidence only and grant no terminal authority.
