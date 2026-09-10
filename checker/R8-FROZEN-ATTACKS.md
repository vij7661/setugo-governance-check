# R8 External Checker Frozen Attacks

Status: `FROZEN_BEFORE_R8_CHECKER_REPAIR`
Authority effect: `NONE_EVIDENCE_ONLY`
Exposed candidate: `61e98ba0ca8fc461b407e91e4f60ffc687fc784e`
Source review disposition: `CHANGES_REQUIRED`.

Before changing the external checker, freeze these attacks:

1. `R8-01`: candidate substitution of `governance-runtime/manual_authority_verifier.py` must fail external qualification even if the policy/root module blobs remain unchanged.
2. `R8-02`: live ruleset `22736961` must require `external-governance-qualification` from GitHub App integration `4895420`; a same-name or candidate GitHub Actions result is insufficient.
3. `R8-04`: candidate substitution of `governance-runtime/qualification_boundary_policy.py` or any authority-critical dependency in the active runtime import closure must fail external qualification.
4. `R8-07`: missing/hidden/nonempty bypass actors, inactive/wrong-target ruleset, non-strict status policy, or missing dedicated-App source binding must fail closed in the external checker.
5. External qualification must exercise the compatibility facade used by candidate runtime consumers after validating the exact authority-critical dependency blobs.
6. This checker still does not claim that its own revision/credential boundary is closed; `R8-03` remains separately open until external-checker governance and GitHub App private-key use are independently constrained.
7. Green results are evidence only and grant no terminal authority.
