# R10 regression automation note

The three frozen R10 runs are automated on pushes to the protected external-checker `main` branch by `.github/workflows/r10-regression.yml`.

Expected outcomes are fixed in the workflow: R10-A and R10-B must fail closed; the non-attack control `af162af911639aba8f801c1545270684a961b71a` must pass. The workflow uses the protected `governance-app-publisher` environment and the dedicated governance GitHub App to publish exact-SHA `external-governance-qualification` checks.

Automation changes execution mechanics only. Results remain `NONE_EVIDENCE_ONLY` and confer no TESTING terminal authority.
