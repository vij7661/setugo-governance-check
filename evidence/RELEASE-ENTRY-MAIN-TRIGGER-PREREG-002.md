# RELEASE Entry Main-Trigger Preregistration 002

Status: FROZEN_BEFORE_MECHANISM_CHANGE
Authority effect: NONE

Exact protected checker base SHA: `77868de67a047c4f1ae67bd74b80767772f99124`.
Exact TESTING source SHA under RELEASE-entry evaluation: `15d50cc25ae524fc64e2c65269c91135e0361846`.

Observed problem: the RELEASE-entry workflow added by PR #15 is scoped to the temporary construction branch `release/entry-qualification-001`. After the checker mechanism was merged to protected `main`, no protected-main execution of that exact mechanism can occur automatically, so a success from the temporary branch would be insufficient use-time evidence for the protected checker revision.

Frozen repair contract:
1. RELEASE-entry qualification must execute from protected checker `main` after merge.
2. The workflow must bind emitted `external-release-entry-qualification` check `head_sha` to exact source `15d50cc25ae524fc64e2c65269c91135e0361846`.
3. The emitted check `external_id` must equal the exact protected checker `main` SHA that executed the workflow.
4. App ID must remain `4895420`.
5. The earlier construction RED remains preserved and must not be overwritten or reinterpreted.
6. A green run on an unprotected feature branch is evidence only and cannot satisfy protected-checker use-time binding.
7. Workflow/check results remain evidence only and grant no RELEASE or PRODUCTION authority.
