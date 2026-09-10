# R10-C Isolated Collector Compatibility — Repair Preregistration

Status: FROZEN_BEFORE_REPAIR
Authority effect: NONE_EVIDENCE_ONLY

## Exposed evidence

External checker SHA: `a9a1a93b1112f413465646d170b721f989febbbf`.
Candidate SHA: `af162af911639aba8f801c1545270684a961b71a`.
External workflow run: `34480592210`.
Observed result: `FAIL_CLOSED`.
Observed error: `qualification test module executed zero tests: test_manual_authority_verifier`.

The candidate's ordinary qualification workflow for the same SHA had already passed. Inspection of the pinned `test_manual_authority_verifier.py` shows top-level `test_*` functions rather than `unittest.TestCase` methods. The new checker-owned isolated collector used only `unittest.TestLoader`, so it rejected a legitimate pinned test module before executing its intended top-level tests.

## Frozen defect

R10-C: the isolated runner must support the already-qualified mixed test shape used by the exact externally pinned candidate modules without reintroducing candidate-controlled collection, `conftest.py`, plugin, cwd, environment, user-site, or stdlib-shadow influence.

## Repair boundary

1. Keep `python -I` and user-site/environment isolation.
2. Keep candidate runtime appended only after trusted interpreter imports.
3. Do not invoke candidate-controlled pytest collection hooks, plugins, or `conftest.py`.
4. Continue running ordinary `unittest.TestCase` tests.
5. Additionally execute top-level zero-required-argument callables whose names begin with `test_` and whose defining module is the exact imported candidate test module.
6. A selected pinned module must contribute at least one executed unittest case or one executed top-level test function; otherwise fail closed.
7. A top-level `test_*` function requiring arguments/fixtures must fail closed rather than being silently skipped.
8. The selected qualification modules remain protected by exact Git-blob pins in the external checker.
9. Preserve the R10-A and R10-B RED results append-only; no later green result erases them.
10. Do not weaken exact-SHA, external-root, signed-ruleset, GitHub-App source binding, policy/verifier/facade pinning, or authority semantics.

## Acceptance

The repaired checker must still fail closed for exact R10-A SHA `4d8d40acf622243f64c54c04481c4807040557d1` and exact R10-B SHA `2b69938815e1cd57300bc196d5f8dc18870bc378`, while the exact non-attack candidate `af162af911639aba8f801c1545270684a961b71a` must execute all selected pinned modules under isolation and pass only if their assertions succeed.

Any newly exposed material defect must be preregistered before changing its mechanism.
