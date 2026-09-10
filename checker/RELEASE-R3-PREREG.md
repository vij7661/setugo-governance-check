# RELEASE R3 Preregistration

Status: FROZEN_BEFORE_MECHANISM
Authority effect: NONE_EVIDENCE_ONLY
Exact candidate: ffec566022fcd221fb4ab7569ed3bc245f75b546

Triggered by independent RELEASE R2 BOUNDED_PASS findings R2-01/R2-02/R2-08.

Frozen objectives:
1. Add a distinct App-produced `external-release-merge-authority` check that can succeed only for a valid Ed25519-signed HUMAN_RELEASE_AUTHORITY attestation bound to exact candidate ffec5660..., exact scope `TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE`, policy id/version/hash, and pinned external trust root.
2. Keep the signed authority evidence outside the reviewed candidate commit so terminal evidence does not mutate the qualified candidate SHA.
3. Demonstrate RED while authority evidence is absent/invalid.
4. Add negative controls for wrong SHA, wrong authority class, wrong scope, stale policy binding, wrong trust root, altered payload, missing/invalid signature.
5. Harden RELEASE workflow_dispatch paths so a supplied SHA must equal the head SHA of the open PR targeting `phase/release` before an App check is published.
6. Preserve `external_id` as evidence-only metadata; platform enforcement remains check context + App integration_id.
7. No checker result itself grants merge authority.
