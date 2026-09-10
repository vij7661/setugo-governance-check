#!/usr/bin/env bash
set -euo pipefail

CANDIDATE_SHA=15d50cc25ae524fc64e2c65269c91135e0361846
CHECKER_SHA=c5dc3a69e1a62a55555021d553934c6dcbb476aa
ROOT_SHA=5f470774ec8c17f5519da8db2aaae59af114cef9
EXTERNAL_RUN=34488506619
LOCAL_RUN=34488207164
APP_CHECK=102908925653
SELFTEST_RUN=34488506669
OUT="$GITHUB_WORKSPACE/TESTING-QUALIFICATION-R11-FULL-REVIEW-15d50cc2-DEEPSEEK.txt"
WORK="$RUNNER_TEMP/r11-full-packet-v2"
rm -rf "$WORK" && mkdir -p "$WORK"

git clone -q https://github.com/vij7661/setugo-ai-development-framework.git "$WORK/candidate"
git -C "$WORK/candidate" checkout -q --detach "$CANDIDATE_SHA"
test "$(git -C "$WORK/candidate" rev-parse HEAD)" = "$CANDIDATE_SHA"
git clone -q https://github.com/vij7661/setugo-governance-check.git "$WORK/checker"
git -C "$WORK/checker" checkout -q --detach "$CHECKER_SHA"
test "$(git -C "$WORK/checker" rev-parse HEAD)" = "$CHECKER_SHA"
git clone -q https://github.com/vij7661/setugo-governance-root.git "$WORK/root"
git -C "$WORK/root" checkout -q --detach "$ROOT_SHA"
test "$(git -C "$WORK/root" rev-parse HEAD)" = "$ROOT_SHA"

cat > "$OUT" <<EOF
INDEPENDENT FALSIFICATION REVIEW REQUEST — R11 FULL SELF-CONTAINED PACKET

Authority effect: NONE_EVIDENCE_ONLY
Review posture: assume false-green until proven otherwise.

EXACT SUBJECTS
candidate_repository=vij7661/setugo-ai-development-framework
candidate_sha=$CANDIDATE_SHA
checker_repository=vij7661/setugo-governance-check
checker_sha=$CHECKER_SHA
external_root_repository=vij7661/setugo-governance-root
external_root_sha=$ROOT_SHA
local_testing_run=$LOCAL_RUN
external_regression_run=$EXTERNAL_RUN
dedicated_app_check=$APP_CHECK
checker_selftest_run=$SELFTEST_RUN

This packet supersedes the earlier thin R10 delta packet that correctly received INSUFFICIENT_EVIDENCE. It is assembled from detached exact Git commits and includes file-level Git blob SHA-1, SHA-256, byte counts, full checker chain, full 15-file test closure, bridge source, control-plane evidence, and raw external attack/success/selftest logs.

REQUIRED REVIEW
1. Re-falsify R11-01 through R11-10 and exact-SHA local-evidence repair 012.
2. Verify full executed checker chain against checker commit $CHECKER_SHA.
3. Verify all 15 candidate qualification test files are externally blob-pinned and that bridge imports are included.
4. Verify async/generator/returned-awaitable paths fail closed; supported synchronous top-level tests actually execute.
5. Verify command spelling, unittest discovery, pytest/conftest/plugins, unknown tests, and stdlib namespace collision cannot bypass the isolated checker-owned path.
6. Verify exact lineage and no stale PASS/review replay.
7. Verify local run $LOCAL_RUN and external App check $APP_CHECK both bind to exact candidate $CANDIDATE_SHA.
8. Verify App check head_sha=$CANDIDATE_SHA and external_id=$CHECKER_SHA.
9. Search for new false-green paths in imports, collection, dependency closure, check publication, ruleset/App binding, stale evidence, or authority self-grant.
10. Treat all CI/check/signature/reviewer/model outputs as evidence only. Do not grant TESTING, RELEASE, or PRODUCTION authority.

Return one final disposition only: TESTING_RULES_PASS, TESTING_RULES_BOUNDED_PASS, CHANGES_REQUIRED, or INSUFFICIENT_EVIDENCE.
For each finding: ID, severity, exact failure path, TESTING-blocking yes/no, evidence relied upon.
EOF

append_file() {
  repo="$1"; rel="$2"; label="$3"; full="$WORK/$repo/$rel"
  test -f "$full" || { echo "MISSING REQUIRED FILE $repo/$rel" >&2; exit 1; }
  blob="$(git -C "$WORK/$repo" hash-object "$rel")"
  sha256="$(sha256sum "$full" | awk '{print $1}')"
  bytes="$(wc -c < "$full" | tr -d ' ')"
  printf '\n================================================================\nBEGIN FILE: %s\nREPO: %s\nPATH: %s\nGIT_BLOB_SHA1: %s\nSHA256: %s\nBYTES: %s\n----------------------------------------------------------------\n' "$label" "$repo" "$rel" "$blob" "$sha256" "$bytes" >> "$OUT"
  cat "$full" >> "$OUT"
  printf '\nEND FILE: %s\n================================================================\n' "$label" >> "$OUT"
}
append_api() {
  url="$1"; label="$2"; mode="${3:-public}"
  printf '\n================================================================\nBEGIN API EVIDENCE: %s\nURL: %s\n----------------------------------------------------------------\n' "$label" "$url" >> "$OUT"
  if [ "$mode" = checker ]; then curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' "$url" >> "$OUT"; else curl -fsSL -H 'Accept: application/vnd.github+json' "$url" >> "$OUT"; fi
  printf '\nEND API EVIDENCE: %s\n================================================================\n' "$label" >> "$OUT"
}
append_log() {
  url="$1"; label="$2"
  printf '\n================================================================\nBEGIN RAW JOB LOG: %s\nURL: %s\n----------------------------------------------------------------\n' "$label" "$url" >> "$OUT"
  curl -fsSL -L -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' "$url" >> "$OUT"
  printf '\nEND RAW JOB LOG: %s\n================================================================\n' "$label" >> "$OUT"
}

# Checker chain and harness.
for p in checker/falsify_candidate.py checker/falsify_candidate_entry.py checker/falsify_candidate_r9_entry.py checker/falsify_candidate_r10_entry.py checker/run_candidate_unittests_isolated.py checker/test_r11_harness.py .github/workflows/r10-regression.yml .github/workflows/r11-checker-selftest.yml evidence/R11-INDEPENDENT-REVIEW-HARNESS-PREREG.md evidence/phase-testing-ruleset-22736961.attestation.json evidence/phase-testing-ruleset-22736961.attestation.sig.b64; do append_file checker "$p" "CHECKER/$p"; done
# Independently retrieved administrative ruleset snapshot lives only on packaging branch and is explicitly evidence, not checker mechanism.
SNAP="$GITHUB_WORKSPACE/evidence/R11-LIVE-CANDIDATE-RULESET-22736961.json"
printf '\n================================================================\nBEGIN EVIDENCE FILE: ADMINISTRATIVE-LIVE-RULESET-SNAPSHOT\nSHA256: %s\nBYTES: %s\n----------------------------------------------------------------\n' "$(sha256sum "$SNAP"|awk '{print $1}')" "$(wc -c < "$SNAP"|tr -d ' ')" >> "$OUT"
cat "$SNAP" >> "$OUT"
printf '\nEND EVIDENCE FILE: ADMINISTRATIVE-LIVE-RULESET-SNAPSHOT\n================================================================\n' >> "$OUT"

# Candidate contracts/runtime/workflow.
for p in governance-runtime/repair-preregistrations/TESTING-QUALIFICATION-INDEPENDENT-REVIEW-CLOSURE-011.md governance-runtime/repair-preregistrations/TESTING-QUALIFICATION-EXACT-SHA-LOCAL-EVIDENCE-012.md .github/workflows/testing-qualification-boundary-ownership.yml governance-runtime/qualification_boundary_policy_v4.py governance-runtime/qualification_boundary_policy.py governance-runtime/manual_authority_verifier.py governance-runtime/external_governance_root.py governance-runtime/phase_policy.py; do append_file candidate "$p" "CANDIDATE/$p"; done
# Complete externally pinned candidate qualification corpus: 12 base + 3 bridge-imported modules.
for p in test_phase_policy.py test_manual_authority_verifier.py test_manual_authority_signed_attestation.py test_external_governance_root.py test_external_root_policy_binding.py test_external_trust_root_control.py test_qualification_boundary_unittest_bridge.py test_review_protocol.py test_review_semantics.py test_review_classification.py test_single_file_review_container.py test_platform_candidate_review_request_integrity.py test_qualification_boundary_policy.py test_manual_review_authority_spoofing_regression.py test_manual_review_authority_ingress_regression.py; do append_file candidate "governance-runtime/$p" "TEST/$p"; done
# Non-secret historical signature fixture referenced by tests.
append_file candidate governance-runtime/manual-attestations/ed265f37487bccffcc5f4463f5f3b62ee9f2b713.acceptance-boundary.json CANDIDATE/historical-signed-attestation.json
append_file candidate governance-runtime/manual-attestations/ed265f37487bccffcc5f4463f5f3b62ee9f2b713.acceptance-boundary.sig.b64 CANDIDATE/historical-signed-attestation.sig.b64
# External root public material only.
append_file root trust-roots/SETUGO_MANUAL_GOVERNANCE_ED25519_V1.pem ROOT/public-key.pem
append_file root trust-roots/SETUGO_MANUAL_GOVERNANCE_ED25519_V1.json ROOT/root-metadata.json

# Exact lineage and run/check metadata.
append_api "https://api.github.com/repos/vij7661/setugo-ai-development-framework/commits/$CANDIDATE_SHA" CANDIDATE/exact-commit
append_api https://api.github.com/repos/vij7661/setugo-ai-development-framework/pulls/31 CANDIDATE/PR31-R10
append_api https://api.github.com/repos/vij7661/setugo-ai-development-framework/pulls/33 CANDIDATE/PR33-R11
append_api https://api.github.com/repos/vij7661/setugo-ai-development-framework/pulls/34 CANDIDATE/PR34-local-evidence-repair
append_api "https://api.github.com/repos/vij7661/setugo-ai-development-framework/actions/runs/$LOCAL_RUN" CANDIDATE/exact-local-run
append_api "https://api.github.com/repos/vij7661/setugo-ai-development-framework/check-runs/$APP_CHECK" CANDIDATE/dedicated-App-check
append_api "https://api.github.com/repos/vij7661/setugo-governance-check/commits/$CHECKER_SHA" CHECKER/exact-commit checker
append_api "https://api.github.com/repos/vij7661/setugo-governance-check/actions/runs/$EXTERNAL_RUN" CHECKER/external-regression-run checker
append_api "https://api.github.com/repos/vij7661/setugo-governance-check/actions/runs/$SELFTEST_RUN" CHECKER/harness-selftest-run checker
append_api https://api.github.com/repos/vij7661/setugo-governance-root ROOT/live-repository
append_api "https://api.github.com/repos/vij7661/setugo-governance-root/commits/$ROOT_SHA" ROOT/exact-commit

# Raw external regression logs. These are from the authoritative checker repository and are fetched with Actions:read.
append_log https://api.github.com/repos/vij7661/setugo-governance-check/actions/jobs/102908847249/logs R10-A-unittest-shadow-attack
append_log https://api.github.com/repos/vij7661/setugo-governance-check/actions/jobs/102908847234/logs R10-B-bridge-pin-attack
append_log https://api.github.com/repos/vij7661/setugo-governance-check/actions/jobs/102908847063/logs R11-pre-local-fix-successor
# Current exact 15d successor job from external run 34488506619.
# The first job in that run is the 15d successor by frozen matrix; embed its resolved raw log too.
CURRENT_JOB="$(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/vij7661/setugo-governance-check/actions/runs/$EXTERNAL_RUN/jobs" | jq -r '.jobs[] | select(.name|contains("15d50cc25ae524fc64e2c65269c91135e0361846")) | .id' | head -1)"
test -n "$CURRENT_JOB" && test "$CURRENT_JOB" != null
append_log "https://api.github.com/repos/vij7661/setugo-governance-check/actions/jobs/$CURRENT_JOB/logs" R11-exact-15d-successor-external
SELFTEST_JOB="$(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/vij7661/setugo-governance-check/actions/runs/$SELFTEST_RUN/jobs" | jq -r '.jobs[0].id')"
test -n "$SELFTEST_JOB" && test "$SELFTEST_JOB" != null
append_log "https://api.github.com/repos/vij7661/setugo-governance-check/actions/jobs/$SELFTEST_JOB/logs" R11-checker-harness-selftest

cat >> "$OUT" <<EOF

================================================================
PACKET FINAL RECORD
----------------------------------------------------------------
candidate_sha=$CANDIDATE_SHA
checker_sha=$CHECKER_SHA
root_sha=$ROOT_SHA
local_testing_run=$LOCAL_RUN
external_regression_run=$EXTERNAL_RUN
app_check=$APP_CHECK
selftest_run=$SELFTEST_RUN
authority_effect=NONE_EVIDENCE_ONLY
NOTE: candidate local run metadata and its GitHub Actions check payload are included; raw candidate-run logs are not claimed because the checker-repository packaging token has no candidate-repository Actions permission. This omission must be treated explicitly by the reviewer rather than silently inferred.
END PACKET
EOF
sha256sum "$OUT" | tee "$OUT.sha256"
wc -c "$OUT"
