# RELEASE R3 Successor Requalification Harness RED 001

Status: PRESERVED_RED / PREREGISTERED_NARROW_REPAIR
Authority effect: NONE_EVIDENCE_ONLY

## Run
`34509781708`

Checker SHA:
`75cca405a8d581dfb18871439e525bb730c78bd5`

Exact candidate:
`6d4fbb9ce266979ca3147a159ae724f33e0362ba`

## Observed failure
The external falsifier failed closed before candidate pin comparison with:

`GitHub App token required for authoritative ruleset evidence`

## Classification
`TEST_HARNESS_CONFIGURATION_DEFECT`

The new branch-only successor requalification workflow omitted the governance App installation token required by the existing external checker. This is not evidence that the successor candidate passed or failed its frozen blob corpus.

## Frozen repair
Only wire the existing protected-environment governance App credentials into the successor requalification workflow, using the already pinned `actions/create-github-app-token` action, and pass the resulting token as the existing checker environment expects. Do not weaken any checker requirement or pin. Rerun after repair. This RED remains preserved.
