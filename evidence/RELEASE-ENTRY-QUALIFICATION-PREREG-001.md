# RELEASE Entry Qualification — Preregistration 001

Status: FROZEN_BEFORE_MECHANISM_CHANGE
Authority effect: NONE_EVIDENCE_ONLY

## Exact source subject

- Candidate repository: `vij7661/setugo-ai-development-framework`
- Exact TESTING-qualified source SHA: `15d50cc25ae524fc64e2c65269c91135e0361846`
- Current RELEASE branch before entry: `phase/release` at `a5726dcb9236e31028ec70603bee35b30b9dbe66`
- Required promotion direction: `phase/testing` -> `phase/release`
- RELEASE ruleset ID: `22789078`
- Required RELEASE target ref: `refs/heads/phase/release`
- Required governance App ID: `4895420`

## Frozen entry contract

The external RELEASE-entry checker MUST fail closed unless all of the following are independently reproduced at use time:

1. The requested source SHA is exactly `15d50cc25ae524fc64e2c65269c91135e0361846`.
2. The source SHA is on the governed TESTING lineage and the current pre-entry RELEASE tip is an ancestor of that source, so entry does not discard RELEASE history.
3. A verifier-valid Ed25519 attestation authorizes only `TERMINAL_ACTION:TESTING:READY_TO_BEGIN_RELEASE_QUALIFICATION` for the exact source SHA under qualification policy `QUALIFICATION_BOUNDARY_OWNERSHIP` version 6 and its exact policy hash.
4. The attestation authority class is exactly `HUMAN_GOVERNANCE_OWNER`; reviewer/model/CI/check success cannot substitute for this authority.
5. The public verification key is bound to external governance root repository `vij7661/setugo-governance-root`, exact commit `5f470774ec8c17f5519da8db2aaae59af114cef9`, and DER SHA-256 `2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2`.
6. RELEASE ruleset `22789078` is active, targets exactly `refs/heads/phase/release`, has no bypass actors, reports current user cannot bypass, blocks deletion and non-fast-forward updates, requires pull requests, requires review-thread resolution, and has zero required approvals for the single-owner profile.
7. Before the source can enter `phase/release`, that ruleset must additionally require a dedicated external check named `external-release-entry-qualification` bound to governance App ID `4895420`. Missing or source-unbound status configuration fails closed.
8. The dedicated App check emitted for RELEASE entry must bind `head_sha` exactly to the source SHA and `external_id` exactly to the checker revision that executed the entry contract.
9. The checker revision, action dependencies, and authority-evidence bytes used for the entry decision must be exact-revision bound and candidate-unmodifiable.
10. Green TESTING CI, the independent `TESTING_RULES_BOUNDED_PASS`, prior App checks, or this preregistration are evidence only and cannot authorize RELEASE entry by themselves.

## Frozen negative cases

- RE-01 wrong candidate SHA -> FAIL.
- RE-02 stale or replayed terminal attestation on another SHA -> FAIL.
- RE-03 changed authority class/scope/policy binding -> FAIL.
- RE-04 invalid signature or rebound public trust root -> FAIL.
- RE-05 RELEASE ruleset missing/inactive/wrong target -> FAIL.
- RE-06 any RELEASE bypass actor or observable bypass capability -> FAIL.
- RE-07 deletion, force-push, PR, or review-thread protection weakened -> FAIL.
- RE-08 required external RELEASE-entry status missing or not bound to App `4895420` -> FAIL.
- RE-09 App check head SHA or checker `external_id` mismatch -> FAIL.
- RE-10 RELEASE branch is not an ancestor of the exact TESTING source -> FAIL.

## Transition rule

No movement of `phase/release` is permitted under this contract until the external checker has been implemented and independently exercised, and the RELEASE ruleset has been tightened to require its App-bound status check. The first introduction of the exact TESTING source into RELEASE must occur through the governed pull-request path.

Any mechanism repair after exposure requires a new preregistration lineage. All failures remain append-only evidence.
