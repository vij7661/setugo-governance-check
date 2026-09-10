# External Checker Governance Contract

Status: `REQUIRED_FOR_R8_03`
Authority effect: `NONE_EVIDENCE_ONLY`

The external checker exists to constrain the evaluated candidate repository. It is not independent human identity and it does not grant terminal authority.

## Required repository controls

`main` must be protected by an active no-bypass ruleset that at minimum:
- targets `refs/heads/main`;
- blocks deletion and non-fast-forward updates;
- requires changes through pull requests;
- requires review-thread resolution;
- has no bypass actors;
- requires signed commits if the account/repository UI supports that rule without creating a deadlock.

No approval count greater than zero is required for this single-owner TESTING profile; the purpose is to make checker changes explicit and prevent evaluated candidate code from directly redefining the checker, not to fabricate an independent second human.

## Required GitHub App credential boundary

The GitHub App private key must not remain as a repository-level Actions secret. It must be stored only in environment `governance-app-publisher`, together with `SETUGO_GOVERNANCE_APP_ID`.

Environment `governance-app-publisher` must permit deployment only from protected branches. The external qualification workflow itself additionally rejects execution unless `GITHUB_REF == refs/heads/main` and checkout HEAD equals `GITHUB_SHA`.

After environment secrets are confirmed, delete the same-named repository-level Actions secrets. Never commit or paste the App private key.

## Runtime evidence

Every published `external-governance-qualification` check must record the exact external checker `GITHUB_SHA` as `external_id` and in its summary. The candidate SHA remains separately exact-bound as the check run `head_sha`.

## Scope

These controls are designed to prevent the evaluated candidate from self-qualifying and to make governance-side checker changes explicit. They do not claim immunity from compromise or deliberate action by the human governance owner/account administrator.
