# RELEASE R3 Full Independent Review Packet — Preregistration

Status: `FROZEN_BEFORE_REVIEW_PACKET_GENERATION`
Authority effect: `NONE_EVIDENCE_ONLY`

Exact RELEASE candidate: `6d4fbb9ce266979ca3147a159ae724f33e0362ba`
Exact TESTING source: `15d50cc25ae524fc64e2c65269c91135e0361846`
Exact current `phase/release` base: `a5726dcb9236e31028ec70603bee35b30b9dbe66`
Exact authoritative checker main: `88d8b972b6bed43ceb572471b56b165db6893f06`
Candidate PR: `vij7661/setugo-ai-development-framework#37`
Live RELEASE ruleset: `22789078`
Required App integration: `4895420` (`setugo-governance-vij7661`)

Purpose: construct a self-contained plain-text packet for a fresh independent RELEASE falsification review of the exact candidate and checker state after the RELEASE merge-authority check was installed as a required protected-branch check.

The packet must preserve prior RED and `INSUFFICIENT_EVIDENCE` history, include exact source/provenance material sufficient to review the candidate and external checker, and state the currently expected polarity: `external-release-entry-qualification=SUCCESS`, `external-release-qualification=SUCCESS`, and `external-release-merge-authority=FAILURE` until separately signed `HUMAN_RELEASE_AUTHORITY` exists.

The reviewer must treat all CI, App checks, signatures and prior model/reviewer outputs as evidence only. Review cannot mint `MERGE_RELEASE_CANDIDATE`, deployment authority, production qualification or production authority. Missing or contradictory material evidence must fail closed.

Required review dimensions include exact-SHA/ancestry binding, external checker independence and provenance, ruleset/bypass controls, dependency/test/helper/workflow/runtime closure, adversarial harness isolation, async/generator false-green closure, mutable action/dependency review, release-scoped trust-root and signature verifier correctness, policy/version/hash binding, replay/substitution opportunities, RELEASE-vs-PRODUCTION separation, configuration/migration/recovery/security/reproducibility concerns that are material in RELEASE, and preservation of prior failures.
