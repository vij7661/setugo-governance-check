# R10 automation preregistration

Status: FROZEN_BEFORE_AUTOMATION_CHANGE

This change automates execution of the already-frozen R10 cases; it does not alter qualification semantics or authority.

Frozen cases and expected outcomes:
- `4d8d40acf622243f64c54c04481c4807040557d1` (R10-A stdlib shadow attack): external falsifier must fail closed.
- `2b69938815e1cd57300bc196d5f8dc18870bc378` (R10-B bridge dependency substitution): external falsifier must fail closed.
- `af162af911639aba8f801c1545270684a961b71a` (non-attack repaired candidate): external falsifier must succeed.

Automation must retain exact checker SHA binding, exact candidate SHA binding, protected `governance-app-publisher` environment use, dedicated GitHub App check publication, and `NONE_EVIDENCE_ONLY` authority effect. A mismatch between actual and expected outcome must fail the regression workflow.
