# RELEASE R3 Successor Preregistration

Status: FROZEN_BEFORE_MECHANISM_FOR_SUCCESSOR
Authority effect: NONE_EVIDENCE_ONLY

Original R3 preregistration remains preserved. The RELEASE candidate advanced after the separately preregistered phase-scoped trust-root repair and stale-test repair.

Exact successor candidate:
`6d4fbb9ce266979ca3147a159ae724f33e0362ba`

Frozen objectives for this successor:
1. `external-release-merge-authority` may succeed only for a valid Ed25519 HUMAN_RELEASE_AUTHORITY attestation bound to this exact candidate SHA.
2. Required scope is exactly `TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE`.
3. Required policy binding is the candidate's active qualification policy v7 identity/version/hash.
4. Required trust root is only `SETUGO_RELEASE_GOVERNANCE_ED25519_V1`, resolved from public archived repository `vij7661/setugo-release-governance-root`, repository id `1364609306`, exact root commit `7300b9b0d27611bcb5ccc1638fb1d16e53dc5994`, DER SHA-256 `91355cf1049a27aac52ea56f5ba1664054aded93500203cd23d557a710b0444c`.
5. TESTING root material must fail to satisfy RELEASE authority. RELEASE root material must fail to satisfy TESTING or PRODUCTION authority.
6. The merge-authority check must be published by governance App id `4895420` on the exact PR #37 head SHA only after verifying PR #37 is open, targets `phase/release`, and its head equals the requested candidate.
7. Missing, malformed, wrong-SHA, wrong-class, wrong-scope, stale-policy, wrong-root, altered-payload, or invalid-signature evidence must fail closed.
8. The check result is an enforcement signal only. It does not itself mint authority; the human signature is the authority evidence.
9. Existing RELEASE qualification and entry checks remain separate required evidence.
10. First negative execution without valid authority evidence must be preserved as RED before any positive authority check is accepted.
