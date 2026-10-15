"""CLI integration checks using mock Substrate RPCs, NO external network."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.finality import multirpc_acquire as M
from tools.finality.quorum import QuorumError
from test_multi_rpc_consistency import Replica, GENESIS, CHECKPOINT, h


class MultiRPCCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.providers = self.root / "operators.json"
        self.keys = self.root / "keys.json"
        self.journal = self.root / "progress.json"
        self.output = self.root / "report.json"
        self.rs = {f"https://rpc{i}.example.org": Replica() for i in range(3)}
        self.providers.write_text(json.dumps({
            "operators": [
                {"provider_id": f"node-{i}", "operator_id": f"operator-{i}",
                 "url": f"https://rpc{i}.example.org"} for i in range(3)
            ]
        }), encoding="utf-8")
        self.keys.write_text('["0x01","0x02","0x03"]', encoding="utf-8")

    def args(self, with_network=True):
        params = [
            "--providers", str(self.providers),
            "--storage-keys", str(self.keys),
            "--expected-genesis", GENESIS,
            "--checkpoint", CHECKPOINT,
            "--journal", str(self.journal),
            "--output", str(self.output),
            "--batch-size", "2",
        ]
        return (["--enable-network"] if with_network else []) + params

    def patched(self, args=None):
        with patch.object(M, "HttpJsonRpc", side_effect=lambda url: self.rs[url]):
            return M.main(self.args() if args is None else args)

    def test_no_network_opt_in_does_not_create_or_modify_outputs(self):
        with patch.object(M, "HttpJsonRpc", side_effect=AssertionError("NETWORK MUST NOT BE CALLED")):
            self.assertEqual(M.main(self.args(with_network=False)), 2)
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.output.exists())

    def test_three_mock_https_nodes_produce_untrusted_report_and_two_batches(self):
        self.assertEqual(self.patched(), 0)
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(report["queried_storage_keys"], 3)
        self.assertEqual(report["completed_batches"], 2)
        self.assertEqual(report["pinned_block_hash"], CHECKPOINT)
        self.assertEqual([r["value"] for r in report["records"]],
                         ["0x1234", None, "0x5678"])
        for k in ("genesis_authenticated", "finality_cryptographically_verified",
                  "trie_membership_verified", "operator_independence_verified",
                  "can_activate", "can_claim"):
            self.assertIs(report[k], False)
        self.assertIn(("state_getMetadata", [CHECKPOINT]), next(iter(self.rs.values())).calls)

    def test_refuses_to_overwrite_previous_success_report(self):
        self.assertEqual(self.patched(), 0)
        original = self.output.read_bytes()
        self.assertEqual(self.patched(), 2)
        self.assertEqual(self.output.read_bytes(), original)

    def test_does_not_emit_report_or_journal_on_root_split_brain(self):
        self.rs["https://rpc2.example.org"].headers[CHECKPOINT]["stateRoot"] = h(999)
        self.assertEqual(self.patched(), 2)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.journal.exists())

    def test_two_timeouts_fail_closed_without_success_report(self):
        for i in (1, 2):
            self.rs[f"https://rpc{i}.example.org"].unavailable_methods.add("chain_getHeader")
        self.assertEqual(self.patched(), 2)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.journal.exists())

    def test_one_timeout_is_tolerated_when_two_independent_peers_agree(self):
        self.rs["https://rpc2.example.org"].unavailable_methods.add("chain_getHeader")
        self.assertEqual(self.patched(), 0)

    def test_duplicate_json_provider_field_is_invalid(self):
        self.providers.write_text('{"operators":[],"operators":[]}', encoding="utf-8")
        self.assertEqual(self.patched(), 2)
        self.assertFalse(self.output.exists())

    def test_duplicate_operator_identity_fails_before_any_storage_read(self):
        data = json.loads(self.providers.read_text())
        data["operators"][2]["operator_id"] = "operator-0"
        self.providers.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(self.patched(), 2)
        self.assertTrue(all(not r.storage_calls for r in self.rs.values()))

    def test_unsorted_or_duplicate_key_plan_not_accepted(self):
        self.keys.write_text('["0x03","0x01","0x02"]', encoding="utf-8")
        self.assertEqual(self.patched(), 2)
        self.assertFalse(self.journal.exists())

    def test_journal_and_report_path_collision_rejected(self):
        args = self.args()
        args[args.index("--output") + 1] = str(self.journal)
        self.assertEqual(self.patched(args), 2)

    def test_different_runtime_metadata_on_resume_rejected(self):
        self.assertEqual(self.patched(), 0)
        self.output.unlink()
        for p in self.rs.values():
            p.metadata = "0x" + "ee" * 256
        self.assertEqual(self.patched(), 2)
        self.assertFalse(self.output.exists())

    def test_no_embedded_api_keys_in_source_reports(self):
        self.assertEqual(self.patched(), 0)
        output = self.output.read_text()
        self.assertNotIn("https://rpc", output)
        self.assertNotIn("APPROVED_OPERATOR", output)


if __name__ == "__main__":
    unittest.main()
