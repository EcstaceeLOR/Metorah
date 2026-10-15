"""Verify the local harness can never pretend to produce chain evidence."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
S = importlib.util.spec_from_file_location("source_fixture_runner", ROOT / "tools/fixtures/run_local.py")
FIX = importlib.util.module_from_spec(S)
sys.modules[S.name] = FIX
S.loader.exec_module(FIX)


class FixtureHarnessTests(unittest.TestCase):
    def test_empty_results_are_failure(self):
        r = FIX.build_report([], present=True, source_digest="abc", lock_digest="def")
        self.assertEqual(r["status"], "OFFLINE_FIXTURE_FAILED")
        self.assertFalse(r["can_activate"])

    def test_missing_lock_or_source_is_failure(self):
        steps = [dict(exit_code=0, executed=True) for _ in FIX.COMMANDS]
        self.assertEqual(
            FIX.build_report(steps, present=False, source_digest=None, lock_digest=None)["status"],
            "OFFLINE_FIXTURE_FAILED",
        )

    def test_any_nonzero_command_blocks(self):
        steps = [dict(exit_code=0, executed=True), dict(exit_code=1, executed=True)]
        self.assertEqual(
            FIX.build_report(steps, present=True, source_digest="a", lock_digest="b")["status"],
            "OFFLINE_FIXTURE_FAILED",
        )

    def test_execution_error_blocks(self):
        steps = [dict(exit_code=0, executed=False) for _ in FIX.COMMANDS]
        self.assertEqual(
            FIX.build_report(steps, present=True, source_digest="a", lock_digest="b")["status"],
            "OFFLINE_FIXTURE_FAILED",
        )

    def test_success_is_explicitly_offline_not_onchain(self):
        steps = [dict(exit_code=0, executed=True) for _ in FIX.COMMANDS]
        report = FIX.build_report(steps, present=True, source_digest="a", lock_digest="b")
        self.assertEqual(report["status"], "OFFLINE_FIXTURE_PASSED")
        self.assertFalse(report["actual_source_contract_deployed"])
        self.assertFalse(report["actual_signed_chain_transactions"])
        self.assertFalse(report["real_tx_or_block_hashes_collected"])
        self.assertFalse(report["finality_or_storage_proofs_verified"])
        self.assertFalse(report["can_activate"])
        self.assertFalse(report["can_claim"])

    def test_command_list_does_not_broadcast_or_deploy(self):
        commands = " ".join(" ".join(args) for _, args in FIX.COMMANDS)
        self.assertNotIn("deploy", commands)
        self.assertNotIn("submit", commands)
        self.assertNotIn("send", commands)

    def test_source_and_lock_have_digests(self):
        self.assertTrue(FIX.SOURCE.is_file())
        self.assertTrue(FIX.LOCKFILE.is_file())
        self.assertEqual(len(FIX.sha256_file(FIX.SOURCE)), 64)
        self.assertEqual(len(FIX.sha256_file(FIX.LOCKFILE)), 64)


if __name__ == "__main__":
    unittest.main()
