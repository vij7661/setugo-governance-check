# R10 successor automation preregistration

Status: FROZEN_BEFORE_SUCCESSOR_VECTOR_UPDATE
Authority effect: NONE_EVIDENCE_ONLY

The frozen R10 attack vectors remain unchanged:
- R10-A `4d8d40acf622243f64c54c04481c4807040557d1` must fail closed.
- R10-B `2b69938815e1cd57300bc196d5f8dc18870bc378` must fail closed.

The candidate repair PR #31 has now merged to protected `phase/testing` at exact successor SHA:
`bb6c8adc3ba98b2e9b06ba65d10ef36a061b2ceb`.

Before changing the automated regression vector, freeze the following acceptance rule:
1. The R10 external checker mechanism and frozen attack expectations are unchanged.
2. The success/control vector is advanced from the pre-merge PR head to the exact merged successor SHA above.
3. The exact merged successor must pass the external checker under the checker SHA produced by the protected-main merge containing this vector update.
4. A success is evidence only and grants no TESTING terminal authority.
5. Prior RED evidence remains append-only and is not superseded by a later PASS.
