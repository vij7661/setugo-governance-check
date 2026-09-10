# RELEASE R1 Entry-Lineage Rebind Preregistration — ffec5660

Status: FROZEN_BEFORE_REPAIR
Authority effect: NONE_EVIDENCE_ONLY

## Exposed condition

The protected `phase/release` ruleset requires both:

- `external-release-entry-qualification`
- `external-release-qualification`

from GitHub App ID `4895420`.

The existing RELEASE-entry workflow correctly qualifies the TESTING source SHA `15d50cc25ae524fc64e2c65269c91135e0361846`, but publishes that check only onto the TESTING source SHA. The current RELEASE candidate is `ffec566022fcd221fb4ab7569ed3bc245f75b546`, so the ruleset cannot observe the already-proven RELEASE-entry condition on the exact candidate.

## Frozen repair boundary

Do not weaken or remove either required status check. Instead, preserve the original TESTING-source qualification and add candidate-lineage binding before publishing `external-release-entry-qualification` on the RELEASE candidate.

Required mechanism:

1. Re-run the existing frozen RELEASE-entry checker for exact TESTING source `15d50cc25ae524fc64e2c65269c91135e0361846`.
2. Independently fetch exact RELEASE candidate `ffec566022fcd221fb4ab7569ed3bc245f75b546` and prove the exact TESTING source is an ancestor of that candidate.
3. Fail closed if source qualification fails, exact candidate checkout fails, or ancestry cannot be proven.
4. Only after both conditions pass, publish `external-release-entry-qualification` on head SHA `ffec566022fcd221fb4ab7569ed3bc245f75b546` from App ID `4895420`.
5. Bind published `external_id` to the protected checker revision that performed the proof.
6. Keep the original source-SHA evidence intact; this candidate check is a lineage-bound carry-forward proof, not a rewrite of history.
7. Result remains evidence only and grants no RELEASE terminal or merge authority.
