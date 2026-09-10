# RELEASE R1 External Coverage Preregistration 001

Status: FROZEN_BEFORE_MECHANISM_CHANGE
Authority effect: NONE

Protected checker base: `22e61dbecaf94c11c9940f2bcda9813f6825663c`.
Current RELEASE hardening candidate: `35d0b2e85e0779eb582d7968f67b06e05a5b493d`.
TESTING source ancestor: `15d50cc25ae524fc64e2c65269c91135e0361846`.

Frozen RELEASE obligation `REL-R1-03`: the external qualification boundary must independently execute or equivalently verify both the candidate live external-trust-root boundary and the Slice 6 terminal-authority regression, rather than relying only on the candidate-local workflow.

Frozen acceptance contract:
1. The external RELEASE checker must bind to the exact RELEASE candidate SHA and reject stale or different candidate SHAs.
2. It must pin and verify the exact candidate blobs for `governance-runtime/verify_external_trust_root_control.py` and `experiments/governed-platform/governance/test_integrated_governed_mvp_slice6_terminal_authority.py` before execution.
3. It must independently execute both paths from the exact candidate revision and fail closed on any non-zero result.
4. The externally enforced qualification-test closure must be updated for the repaired bridge and the new RELEASE R1 shape-guard regression; candidate modification of those files must fail closed.
5. Existing R10/R11 negative controls and authority-boundary protections must remain intact.
6. The dedicated RELEASE qualification check must bind `head_sha` to the exact RELEASE candidate and `external_id` to the exact protected checker revision that produced it, using governance App ID `4895420`.
7. Results are evidence only and grant no `MERGE_RELEASE_CANDIDATE`, `BEGIN_PRODUCTION_QUALIFICATION`, or PRODUCTION authority.
8. Any new material false-green found during this repair must be preserved and preregistered before repair.
