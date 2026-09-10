# Signed administrative ruleset evidence

This evidence records the human-governance view of candidate ruleset `22736961` because GitHub App ruleset responses may omit `bypass_actors` and `current_user_can_bypass` even with Administration:read.

The JSON is signed with the existing Setugo manual governance Ed25519 key whose public half is anchored at external governance-root commit `5f470774ec8c17f5519da8db2aaae59af114cef9`.

The attestation is bound to the exact live ruleset `updated_at` value `2026-09-10T15:22:40.267+05:30`. Any later ruleset mutation makes this evidence stale and the external checker fails closed until a fresh human-signed administrative attestation is supplied.

This evidence is verification material only. It grants no TESTING, RELEASE, PRODUCTION, merge, deployment, or terminal authority.
