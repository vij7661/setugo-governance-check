#!/usr/bin/env python3
from pathlib import Path
import hashlib
import subprocess
import json

CANDIDATE_SHA = '61e98ba0ca8fc461b407e91e4f60ffc687fc784e'
CHECKER_SHA = '37df9c463d8db7bde4616e2f71f621b7188a40b6'
ROOT_SHA = '5f470774ec8c17f5519da8db2aaae59af114cef9'
OUT = Path('TESTING-QUALIFICATION-R8-REVIEW-61e98ba0-DEEPSEEK.txt')


def run(*args, cwd=None):
    subprocess.run(list(args), cwd=cwd, check=True)


def capture(*args, cwd=None):
    return subprocess.check_output(list(args), cwd=cwd)


def append_bytes(label: str, data: bytes):
    h = hashlib.sha256(data).hexdigest()
    with OUT.open('ab') as f:
        f.write((f'\n===== ARTIFACT: {label} =====\nBYTE_LENGTH: {len(data)}\nSHA256: {h}\n===== BEGIN =====\n').encode())
        f.write(data)
        if not data.endswith(b'\n'):
            f.write(b'\n')
        f.write(b'===== END =====\n')


header = f'''INDEPENDENT FALSIFICATION REVIEW PACKET — R8 STRENGTHENED STATE

Authority effect: NONE_EVIDENCE_ONLY
Review posture: assume false-green until proven otherwise.

Exact candidate SHA: {CANDIDATE_SHA}
Exact external checker SHA: {CHECKER_SHA}
Exact external governance root SHA: {ROOT_SHA}

Latest strengthened external checker evidence:
run_id=34471548437
conclusion=success
result=PASS_BOUNDED_EVIDENCE_ONLY
candidate_check_run_id=102852431333
candidate_check_name=external-governance-qualification
candidate_check_app_id=4895420
candidate_check_external_id={CHECKER_SHA}
candidate_check_head_sha={CANDIDATE_SHA}
candidate_governance_tests=106/106 OK

The PASS above is evidence only. It grants no TESTING, RELEASE, PRODUCTION, merge, deployment, or terminal authority.

REVIEW REQUEST
Re-falsify R8-01 through R8-07 and search for new material false-green paths. Test verifier/import substitution, required-check source binding, checker revision/credential control, signed fixture reproducibility, exact-SHA lineage, ruleset administrative visibility and attestation staleness, and whether timestamp normalization weakens any comparison beyond equality of one ISO-8601 instant. Treat all CI, App checks, signatures, archived state and model/reviewer outputs as evidence only.

Return one disposition: TESTING_RULES_PASS, TESTING_RULES_BOUNDED_PASS, CHANGES_REQUIRED, or INSUFFICIENT_EVIDENCE. Give exact failure paths and severity. Do not assume facts outside this packet.
'''
OUT.write_text(header, encoding='utf-8')

run('git','clone','-q','https://github.com/vij7661/setugo-ai-development-framework.git','candidate')
run('git','checkout','-q',CANDIDATE_SHA,cwd='candidate')
run('git','fetch','-q','origin','evidence/testing-f81eb5f3','repair/testing-independent-refalsification-008',cwd='candidate')
run('git','clone','-q','https://github.com/vij7661/setugo-governance-check.git','checker-exact')
run('git','checkout','-q',CHECKER_SHA,cwd='checker-exact')
run('git','clone','-q','https://github.com/vij7661/setugo-governance-root.git','root')
run('git','checkout','-q',ROOT_SHA,cwd='root')

candidate_files = [
'governance-runtime/qualification_boundary_policy_v4.py','governance-runtime/qualification_boundary_policy.py','governance-runtime/manual_authority_verifier.py','governance-runtime/external_governance_root.py','governance-runtime/test_qualification_boundary_policy.py','governance-runtime/test_manual_authority_verifier.py','governance-runtime/test_manual_authority_signed_attestation.py','governance-runtime/test_external_governance_root.py','governance-runtime/test_external_root_policy_binding.py','governance-runtime/verify_external_trust_root_control.py','governance-runtime/test_external_trust_root_control.py','governance-runtime/test_qualification_boundary_unittest_bridge.py','governance-runtime/repair-preregistrations/TESTING-QUALIFICATION-INDEPENDENT-REFALSIFICATION-007.md','governance-runtime/failures/TESTING-QUALIFICATION-INDEPENDENT-REFALSIFICATION-RED-007.md','.github/workflows/testing-qualification-boundary-ownership.yml','standards/qualification-boundary-ownership.md','governance-runtime/manual-attestations/ed265f37487bccffcc5f4463f5f3b62ee9f2b713.acceptance-boundary.json','governance-runtime/manual-attestations/ed265f37487bccffcc5f4463f5f3b62ee9f2b713.acceptance-boundary.sig.b64']
for p in candidate_files:
    path = Path('candidate') / p
    if not path.is_file():
        raise SystemExit(f'missing required candidate artifact: {p}')
    append_bytes(f'candidate@{CANDIDATE_SHA}:{p}', path.read_bytes())

for p in ['governance-runtime/manual-attestations/f81eb5f3cbde819d60c134ba73287dedc6b67e0b.acceptance-boundary.json','governance-runtime/manual-attestations/f81eb5f3cbde819d60c134ba73287dedc6b67e0b.acceptance-boundary.sig.b64']:
    append_bytes(f'candidate-evidence-branch:{p}', capture('git','show',f'origin/evidence/testing-f81eb5f3:{p}',cwd='candidate'))

for p in ['governance-runtime/repair-preregistrations/TESTING-QUALIFICATION-INDEPENDENT-REFALSIFICATION-008.md','governance-runtime/failures/TESTING-QUALIFICATION-INDEPENDENT-REFALSIFICATION-R8-001.md']:
    append_bytes(f'R8-repair-lineage@e058be4b:{p}', capture('git','show',f'origin/repair/testing-independent-refalsification-008:{p}',cwd='candidate'))

for p in ['README.md','checker/falsify_candidate.py','checker/falsify_candidate_entry.py','.github/workflows/external-qualification.yml','evidence/phase-testing-ruleset-22736961.attestation.json','evidence/phase-testing-ruleset-22736961.attestation.sig.b64']:
    path = Path('checker-exact') / p
    if not path.is_file():
        raise SystemExit(f'missing required checker artifact: {p}')
    append_bytes(f'checker@{CHECKER_SHA}:{p}', path.read_bytes())

for p in ['README.md','trust-roots/SETUGO_MANUAL_GOVERNANCE_ED25519_V1.pem','trust-roots/SETUGO_MANUAL_GOVERNANCE_ED25519_V1.json']:
    path = Path('root') / p
    if not path.is_file():
        raise SystemExit(f'missing required root artifact: {p}')
    append_bytes(f'root@{ROOT_SHA}:{p}', path.read_bytes())

candidate_ruleset = {"id":22736961,"name":"phase/testing","target":"branch","enforcement":"active","conditions":{"ref_name":{"exclude":[],"include":["refs/heads/phase/testing"]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"pull_request","parameters":{"required_approving_review_count":0,"required_review_thread_resolution":True,"require_extra_approval_for_unattributed_changes":True}},{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":True,"required_status_checks":[{"context":"falsify-qualification-boundary"},{"context":"falsify-qualification-boundary","integration_id":15368},{"context":"external-governance-qualification","integration_id":4895420}]}}],"updated_at":"2026-09-10T15:22:40.267+05:30","bypass_actors":[],"current_user_can_bypass":"never"}
append_bytes('live-admin-snapshot:candidate-ruleset-22736961',(json.dumps(candidate_ruleset,sort_keys=True,separators=(',',':'))+'\n').encode())

checker_ruleset = {"id":22757786,"name":"governanace-check-main","target":"branch","enforcement":"active","conditions":{"ref_name":{"exclude":[],"include":["~DEFAULT_BRANCH"]}},"rules":[{"type":"non_fast_forward"},{"type":"pull_request","parameters":{"required_approving_review_count":0,"required_review_thread_resolution":True,"require_extra_approval_for_unattributed_changes":True}},{"type":"deletion"}],"updated_at":"2026-09-10T15:58:24.413+05:30","bypass_actors":[],"current_user_can_bypass":"never"}
append_bytes('live-admin-snapshot:checker-ruleset-22757786',(json.dumps(checker_ruleset,sort_keys=True,separators=(',',':'))+'\n').encode())

check_runs = {"candidate_sha":CANDIDATE_SHA,"check_runs":[{"id":102852431333,"name":"external-governance-qualification","head_sha":CANDIDATE_SHA,"external_id":CHECKER_SHA,"status":"completed","conclusion":"success","app":{"id":4895420,"slug":"setugo-governance-vij7661","permissions":{"administration":"read","checks":"write","contents":"read","metadata":"read"}}},{"id":102825416969,"name":"falsify-qualification-boundary","head_sha":CANDIDATE_SHA,"status":"completed","conclusion":"success","app":{"id":15368,"slug":"github-actions"}}]}
append_bytes('live-check-run-snapshot:61e98ba0',(json.dumps(check_runs,sort_keys=True,separators=(',',':'))+'\n').encode())

digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
Path(str(OUT)+'.sha256').write_text(f'{digest}  {OUT.name}\n')
print(f'packet_sha256={digest}')
print(f'packet_bytes={OUT.stat().st_size}')
