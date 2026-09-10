#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import verify_release_merge_authority as gate

ADJ_REF = "sha256:" + ("a" * 64)


class ReleaseMergeAuthorityGateTests(unittest.TestCase):
    def _valid_attestation(self):
        return {
            "schema_version": 1,
            "candidate_sha": gate.CANDIDATE_SHA,
            "authority_class": gate.AUTHORITY_CLASS,
            "decision_scope": gate.DECISION_SCOPE,
            "evidence_ref": ADJ_REF,
            "source_kind": gate.SOURCE_KIND,
            "qualification_policy_id": gate.POLICY_ID,
            "qualification_policy_version": gate.POLICY_VERSION,
            "qualification_policy_hash": gate.POLICY_HASH,
            "trust_root_id": gate.TRUST_ROOT_ID,
        }

    def test_wrong_candidate_is_rejected_before_network_or_signature(self):
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "frozen RELEASE R3 candidate"):
            gate.verify("0" * 40, "", "", ADJ_REF)

    def test_missing_adjudication_digest_is_rejected_before_network(self):
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "adjudication digest"):
            gate.verify(gate.CANDIDATE_SHA, "", "", "")

    def test_missing_and_malformed_attestation_are_rejected(self):
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "attestation is missing"):
            gate.decode_attestation("")
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "attestation is malformed"):
            gate.decode_attestation("not-base64")

    def test_exact_field_set_is_required(self):
        att = self._valid_attestation(); del att["decision_scope"]
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "fields are missing or unexpected"):
            gate.validate_attestation(att, gate.CANDIDATE_SHA, ADJ_REF)
        att = self._valid_attestation(); att["candidate_claim"] = "extra"
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "fields are missing or unexpected"):
            gate.validate_attestation(att, gate.CANDIDATE_SHA, ADJ_REF)

    def test_wrong_sha_class_scope_policy_and_root_are_rejected(self):
        mutations = {
            "candidate_sha": "1" * 40,
            "authority_class": "HUMAN_GOVERNANCE_OWNER",
            "decision_scope": "TERMINAL_ACTION:RELEASE:BEGIN_PRODUCTION_QUALIFICATION",
            "qualification_policy_id": "OTHER_POLICY",
            "qualification_policy_version": gate.POLICY_VERSION - 1,
            "qualification_policy_hash": "0" * 64,
            "trust_root_id": "SETUGO_MANUAL_GOVERNANCE_ED25519_V1",
            "source_kind": "MODEL_ASSERTION",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                att = self._valid_attestation(); att[field] = value
                with self.assertRaisesRegex(gate.ReleaseAuthorityError, f"mismatch: {field}"):
                    gate.validate_attestation(att, gate.CANDIDATE_SHA, ADJ_REF)

    def test_free_form_or_wrong_adjudication_reference_is_rejected(self):
        att = self._valid_attestation()
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "digest is missing or invalid"):
            gate.validate_attestation(att, gate.CANDIDATE_SHA, "R3-test-evidence")
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "not bound"):
            gate.validate_attestation(att, gate.CANDIDATE_SHA, "sha256:" + ("b" * 64))

    def test_ed25519_signature_accepts_exact_payload_and_rejects_alteration(self):
        att = self._valid_attestation()
        with tempfile.TemporaryDirectory(prefix="setugo-r3-gate-test-") as td:
            root = Path(td); priv=root/"private.pem"; pub=root/"public.pem"; payload=root/"payload.json"; sig=root/"signature.bin"
            subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",str(priv)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            payload.write_bytes(gate._canonical(att))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),"-rawin","-in",str(payload),"-out",str(sig)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            signature_b64 = base64.b64encode(sig.read_bytes()).decode("ascii")
            gate.verify_signature(att, signature_b64, pub.read_bytes())
            altered = copy.deepcopy(att); altered["evidence_ref"] = "sha256:" + ("c" * 64)
            with self.assertRaisesRegex(gate.ReleaseAuthorityError, "signature is invalid"):
                gate.verify_signature(altered, signature_b64, pub.read_bytes())

    def test_signature_encoding_and_length_fail_closed(self):
        att = self._valid_attestation()
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "not valid base64"):
            gate.verify_signature(att, "%%%", b"unused")
        short = base64.b64encode(b"short").decode("ascii")
        with self.assertRaisesRegex(gate.ReleaseAuthorityError, "length is invalid"):
            gate.verify_signature(att, short, b"unused")


if __name__ == "__main__":
    unittest.main()
