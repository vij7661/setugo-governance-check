# RELEASE R3 Successor External Requalification Preregistration

Status: FROZEN_BEFORE_PIN_REFRESH
Authority effect: NONE_EVIDENCE_ONLY
Exact candidate: `6d4fbb9ce266979ca3147a159ae724f33e0362ba`

## Trigger

The RELEASE candidate advanced from `ffec566022fcd221fb4ab7569ed3bc245f75b546` after the separately preregistered phase-scoped RELEASE trust-root repair and the preserved stale policy-version test repair. Existing external RELEASE R1 qualification is therefore stale by exact-SHA design and must not be replayed.

## Frozen requirements

1. First point `checker/falsify_candidate_release_r1.py` at exact successor `6d4fbb9c...` without silently accepting stale blob pins; any mismatched qualification-contributing pin is expected to fail closed and is preserved as requalification evidence.
2. Refresh only blob pins demonstrably changed in the exact successor tree and add the new RELEASE R3 phase-scoped authority regression to externally executed qualification coverage.
3. The external checker must exercise or independently verify the new RELEASE resolver, RELEASE manual verifier, active policy v7 routing, TESTING-root rejection of RELEASE authority, and production fail-closed behavior.
4. Existing RELEASE R1 bridge-shape, TESTING ownership, trust-root, terminal-authority, and isolation coverage must remain active.
5. Update RELEASE-entry and RELEASE qualification workflows to publish on the exact successor only after their checkers pass.
6. Both existing required App checks must be republished fresh on exact successor `6d4fbb9c...`; old `ffec5660...` checks are stale evidence only.
7. Checker changes must pass protected-branch PR qualification before entering checker `main`.
8. No result from this refresh grants merge authority. `external-release-merge-authority` remains a separate fail-closed gate requiring a valid human RELEASE signature.
