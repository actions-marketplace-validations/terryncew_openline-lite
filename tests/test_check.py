from __future__ import annotations
import json,tempfile,unittest
from pathlib import Path
from openline_lite.canonical import pretty,sha256_hex
from openline_lite.check import run_check
from openline_lite.crypto import public_key_hex
from openline_lite.wire import SOURCE_SCHEMA,issue_source_receipt
PRODUCER_KEY="01"*32;GATE_KEY="02"*32
class OpenLineCheckTests(unittest.TestCase):
    def make_case(self,root,*,review_commit="abc123",include_review=True,trust_producer=True,tamper_tests_after_issue=False):
        e=root/"evidence";e.mkdir()
        tb=b'{"commit":"abc123","passed":true}';rb=('{"approved":true,"commit":"'+review_commit+'"}').encode()
        (e/"tests.json").write_bytes(tb)
        if include_review:(e/"review.json").write_bytes(rb)
        payload={"schema":SOURCE_SCHEMA,"issuer":"coding-agent","issued_at":"2026-08-21T17:55:00Z","run_id":"run-481","sequence":0,
        "action":{"type":"merge_code","name":"merge PR #481","target":"abc123"},"claim":"Current patch has passing tests and current review approval.",
        "evidence":[{"id":"tests","sha256":sha256_hex(tb),"media_type":"application/json"},{"id":"review","sha256":sha256_hex(rb),"media_type":"application/json"}]}
        (root/"source.receipt.json").write_text(pretty(issue_source_receipt(payload,PRODUCER_KEY,"agent-key")))
        (root/"producer-trust.json").write_text(pretty({"agent-key":public_key_hex(PRODUCER_KEY)} if trust_producer else {}))
        policy={"policy_id":"merge-current-evidence","version":"1","allowed_actions":["merge_code"],"required_evidence":["tests","review"],
        "claim_rules":[{"id":"tests-pass","evidence_id":"tests","pointer":"/passed","expected":True},{"id":"tests-current","evidence_id":"tests","pointer":"/commit","expected":"abc123"},{"id":"review-approved","evidence_id":"review","pointer":"/approved","expected":True},{"id":"review-current","evidence_id":"review","pointer":"/commit","expected":"abc123"}],
        "max_age_seconds":3600,"on_undecidable":"QUARANTINE","rollback_supported":False}
        (root/"receiver-policy.json").write_text(pretty(policy))
        pack={"schema":"openline.check.v1","label":"Merge PR #481","source":"source.receipt.json","producer_trust":"producer-trust.json","policy":"receiver-policy.json","evidence":{"tests":"evidence/tests.json","review":"evidence/review.json"},"now":"2026-08-21T18:00:00Z"}
        (root/"check.json").write_text(pretty(pack))
        if tamper_tests_after_issue:(e/"tests.json").write_bytes(b'{"commit":"abc123","passed":false}')
        return root/"check.json"
    def r(self,**kw):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name);pack=self.make_case(root,**kw);kp=root/"gate.key";kp.write_text(GATE_KEY+"\n")
        return root,run_check(pack,gate_key_path=str(kp),gate_id="test-gate",output_dir=root/"out")
    def test_current_evidence_commits(self):
        root,r=self.r();self.assertEqual((r.verdict,r.decision),("VERIFIED","COMMIT"));self.assertTrue((root/"out"/"decision.receipt.json").exists())
    def test_stale_review_denies(self):
        _,r=self.r(review_commit="old");self.assertEqual((r.verdict,r.decision),("REJECTED","DENY"));self.assertTrue(any("review-current" in x for x in r.reason_codes))
    def test_missing_evidence_quarantines(self):
        _,r=self.r(include_review=False);self.assertEqual((r.verdict,r.decision),("UNDECIDABLE","QUARANTINE"));self.assertTrue(any("artifact_missing:review" in x for x in r.reason_codes))
    def test_untrusted_producer_quarantines(self):
        _,r=self.r(trust_producer=False);self.assertEqual((r.verdict,r.decision),("UNDECIDABLE","QUARANTINE"))
    def test_tampered_evidence_denies(self):
        _,r=self.r(tamper_tests_after_issue=True);self.assertEqual((r.verdict,r.decision),("REJECTED","DENY"))
    def test_ephemeral_disclosed(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name);pack=self.make_case(root);r=run_check(pack,output_dir=root/"out",env={});self.assertEqual(r.gate_key_mode,"ephemeral");self.assertEqual(r.result["portable_authority"],"NONE")
    def test_path_escape_rejected(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name);pack=self.make_case(root);v=json.loads(pack.read_text());v["policy"]="../outside.json";pack.write_text(json.dumps(v))
        with self.assertRaisesRegex(ValueError,"policy_path_escape"):run_check(pack)
    def test_github_summary(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name);pack=self.make_case(root);s=root/"summary.md";run_check(pack,output_dir=root/"out",env={"GITHUB_STEP_SUMMARY":str(s)});self.assertIn("OPENLINE CHECK",s.read_text())
if __name__=="__main__":unittest.main()
