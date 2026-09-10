#!/usr/bin/env bash
set -euo pipefail

CANDIDATE_SHA=6d4fbb9ce266979ca3147a159ae724f33e0362ba
TESTING_SHA=15d50cc25ae524fc64e2c65269c91135e0361846
RELEASE_BASE_SHA=a5726dcb9236e31028ec70603bee35b30b9dbe66
CHECKER_SHA=88d8b972b6bed43ceb572471b56b165db6893f06
OUT=RELEASE-R3-FULL-INDEPENDENT-REVIEW-6d4fbb9c-DEEPSEEK.txt

rm -rf candidate checker-main "$OUT" pr37.diff

git clone --quiet https://github.com/vij7661/setugo-ai-development-framework.git candidate
git -C candidate checkout --quiet --detach "$CANDIDATE_SHA"
test "$(git -C candidate rev-parse HEAD)" = "$CANDIDATE_SHA"
git -C candidate cat-file -e "${TESTING_SHA}^{commit}"
git -C candidate cat-file -e "${RELEASE_BASE_SHA}^{commit}"

git clone --quiet https://github.com/vij7661/setugo-governance-check.git checker-main
git -C checker-main checkout --quiet --detach "$CHECKER_SHA"
test "$(git -C checker-main rev-parse HEAD)" = "$CHECKER_SHA"

git -C candidate diff --no-ext-diff "$RELEASE_BASE_SHA...$CANDIDATE_SHA" > pr37.diff
POLICY_HASH="$(sha256sum candidate/governance-runtime/qualification_boundary_policy_v7.py | awk '{print $1}')"

cat evidence/RELEASE-R3-INDEPENDENT-REVIEW-INSTRUCTIONS.txt > "$OUT"
cat >> "$OUT" <<EOF

===== EXACT VERIFIED LIVE STATE SNAPSHOT =====
RELEASE ruleset 22789078: active; target refs/heads/phase/release; no bypass actors; current_user_can_bypass=never; deletion and non-fast-forward blocked; pull request required; strict required status checks enabled.
Required App-bound checks (integration_id 4895420):
- external-release-entry-qualification
- external-release-qualification
- external-release-merge-authority
Ruleset snapshot last independently observed: 2026-09-10T23:39:42.583+05:30.

Exact candidate App checks published by App 4895420 with external_id ${CHECKER_SHA}:
- external-release-entry-qualification: check 102988937552, SUCCESS, head ${CANDIDATE_SHA}; verifies TESTING source ${TESTING_SHA} ancestry into exact candidate.
- external-release-qualification: check 102988967477, SUCCESS, head ${CANDIDATE_SHA}; frozen RELEASE external coverage passed.
- external-release-merge-authority: check 102988915673, FAILURE, head ${CANDIDATE_SHA}; signed HUMAN_RELEASE_AUTHORITY absent/invalid, merge remains blocked.
===== END EXACT VERIFIED LIVE STATE SNAPSHOT =====

===== ACTIVE POLICY CONTENT SHA256 =====
qualification_boundary_policy_v7.py sha256=${POLICY_HASH}
===== END ACTIVE POLICY CONTENT SHA256 =====
EOF

append_file() {
  local label="$1" file="$2"
  [ -f "$file" ] || return 0
  printf '\n\n===== %s =====\n' "$label" >> "$OUT"
  cat "$file" >> "$OUT"
  printf '\n===== END %s =====\n' "$label" >> "$OUT"
}

append_file 'PR #37 EXACT RELEASE-BASE...CANDIDATE DIFF' pr37.diff

{
  printf '\n\n===== EXACT CANDIDATE / ANCESTRY =====\n'
  git -C candidate show --no-patch --pretty=raw "$CANDIDATE_SHA"
  printf '\n--- TESTING -> candidate ancestry ---\n'
  git -C candidate log --oneline --ancestry-path "${TESTING_SHA}..${CANDIDATE_SHA}"
  printf '\nmerge-base(TESTING,candidate)='; git -C candidate merge-base "$TESTING_SHA" "$CANDIDATE_SHA"
  printf 'merge-base(RELEASE-base,candidate)='; git -C candidate merge-base "$RELEASE_BASE_SHA" "$CANDIDATE_SHA"
  printf '===== END EXACT CANDIDATE / ANCESTRY =====\n'
} >> "$OUT"

while IFS= read -r file; do
  append_file "CANDIDATE:${file#candidate/}" "$file"
done < <(find candidate/governance-runtime -type f \
  \( -name '*.py' -o -name '*.md' -o -name '*.json' -o -name '*.txt' -o -name '*.yml' -o -name '*.yaml' \) \
  ! -path '*/__pycache__/*' | sort)

while IFS= read -r file; do
  append_file "CANDIDATE:${file#candidate/}" "$file"
done < <(find candidate/.github/workflows -maxdepth 1 -type f \
  \( -iname '*release*' -o -iname '*testing*' -o -iname '*qualification*' -o -iname '*governance*' \) | sort)

while IFS= read -r file; do
  append_file "CHECKER:${file#checker-main/}" "$file"
done < <(find checker-main/checker checker-main/evidence checker-main/history -type f \
  \( -name '*.py' -o -name '*.md' -o -name '*.json' -o -name '*.txt' -o -name '*.yml' -o -name '*.yaml' -o -name '*.b64' \) \
  ! -path '*/__pycache__/*' | sort)

while IFS= read -r file; do
  append_file "CHECKER:${file#checker-main/}" "$file"
done < <(find checker-main/.github/workflows -maxdepth 1 -type f \
  \( -iname '*release*' -o -iname '*r10*' -o -iname '*r11*' -o -iname '*external*' \) | sort)

cat >> "$OUT" <<EOF

===== PACKET PROVENANCE =====
candidate_sha=${CANDIDATE_SHA}
testing_sha=${TESTING_SHA}
release_base_sha=${RELEASE_BASE_SHA}
checker_sha=${CHECKER_SHA}
active_policy_sha256=${POLICY_HASH}
===== END PACKET PROVENANCE =====
EOF

test -s "$OUT"
printf 'packet_sha256=%s\n' "$(sha256sum "$OUT" | awk '{print $1}')"
printf 'packet_bytes=%s\n' "$(wc -c < "$OUT")"
