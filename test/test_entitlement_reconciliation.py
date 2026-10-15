"""Adversarial offline replay cases: invented public data, never live source proof."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.manifest import canonical
from tools.reconciliation.audit import ReconciliationError, audit

def h32(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 32

def h20(byte: int) -> str:
    return "0x" + f"{byte:02x}" * 20

OWNER = h32(99)
SOURCE = h32(44)
ACCOUNTS = [h32(i) for i in range(1, 7)]
A, B, C, D, E, F = ACCOUNTS
ZERO_H160 = "0x" + "00" * 20

def fixture():
    header = {
        "source_genesis": h32(11), "finalized_block_hash": h32(22),
        "finalized_block_number": "12345", "finalized_state_root": h32(33),
        "source_contract": SOURCE, "source_code_hash": h32(55),
        "migration_id": h32(66), "asset_id": h32(77),
        "destination_chain_id": "31337", "destination_contract": h20(88),
        "entitlement_kind": 1, "decimals": 12,
        "historical_holder_count": 6, "active_holder_count": 3,
        "total_units": "180",
    }
    ev = []
    def add(kind, **details):
        ev.append({"event_index": len(ev), "kind": kind, **details})
    add("Issued", to=A, amount="40")
    add("Issued", to=B, amount="20")
    add("Transferred", **{"from": A, "to": C, "amount": "10"})
    add("Issued", to=D, amount="30")
    add("Issued", to=E, amount="50")
    add("Issued", to=F, amount="60")
    add("Burned", **{"from": B, "amount": "20"})
    add("Transferred", **{"from": E, "to": D, "amount": "50"})
    add("Transferred", **{"from": C, "to": A, "amount": "10"})
    def bind(who, beneficiary, previous, nonce):
        add("BeneficiaryRegistered",
            source_owner=who, source_contract=SOURCE,
            destination_chain_id="31337",
            destination_contract=h20(88), migration_id=h32(66),
            previous_beneficiary=previous,
            beneficiary=beneficiary, nonce=str(nonce))
    bind(A, h20(10), ZERO_H160, 1)
    bind(D, h20(40), ZERO_H160, 1)
    bind(D, h20(41), h20(40), 2)
    bind(F, h20(60), ZERO_H160, 1)
    add("SourceFrozen", by=OWNER, source_contract=SOURCE,
        source_block="12345", asset_id=h32(77), migration_id=h32(66),
        destination_chain_id="31337", destination_contract=h20(88),
        total_supply="180", holder_count=6, active_holder_count=3,
        unbound_active_holders=0)
    slots = [
        {"index": i, "source_account": acct, "units": str(units),
         "beneficiary": beneficiary, "binding_nonce": str(nonce)}
        for i, (acct, units, beneficiary, nonce) in enumerate([
            (A, 40, h20(10), 1),
            (B, 0, None, 0),
            (C, 0, None, 0),
            (D, 80, h20(41), 2),
            (E, 0, None, 0),
            (F, 60, h20(60), 1),
        ])
    ]
    snapshot = {
        "schema_version": "metorah-source-replay-v1",
        "header": header, "owner": OWNER,
        "max_supply": "250", "frozen": True,
        "freeze_block_number": "12345",
        "unbound_active_holders": 0,
        "slots": slots, "events": ev,
    }
    entries = []
    for row in slots:
        if int(row["units"]) > 0:
            entries.append({
                "leaf_index": len(entries),  # dense positive-only Merkle leaf
                "historical_index": row["index"],  # never reassign source slot
                "source_account": row["source_account"],
                "beneficiary": row["beneficiary"],
                "units": row["units"],
                "binding_nonce": row["binding_nonce"],
            })
    return snapshot, canonical.build(copy.deepcopy(header), entries)

class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.source, self.manifest = fixture()

    def fails(self, code, source=None, manifest=None):
        with self.assertRaises(ReconciliationError) as ctx:
            audit(self.source if source is None else source,
                  self.manifest if manifest is None else manifest)
        self.assertEqual(ctx.exception.code, code)

    def test_six_historical_three_funded_and_three_tombstones(self):
        report = audit(self.source, self.manifest)
        self.assertEqual(report["status"], "COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED")
        self.assertEqual(report["historical_holder_count"], 6)
        self.assertEqual(report["active_holder_count"], 3)
        self.assertEqual(report["zero_balance_tombstones"], 3)
        self.assertEqual(report["issued_units"], "200")
        self.assertEqual(report["burned_units"], "20")
        self.assertEqual(report["total_supply_units"], "180")
        self.assertEqual(report["event_count"], 14)
        self.assertEqual(report["binding_event_count"], 4)
        self.assertEqual(report["manifest_digest"], self.manifest["manifest_digest"])

    def test_same_inputs_produce_deterministic_report(self):
        self.assertEqual(audit(*fixture()), audit(*fixture()))

    def test_no_authentication_or_activation_claim_from_local_report(self):
        r = audit(self.source, self.manifest)
        for name in ("independent_source_finality_verified", "registry_storage_proofs_verified",
                     "complete_event_history_cryptographically_verified",
                     "beneficiary_signatures_verified", "can_activate", "can_claim"):
            self.assertIs(r[name], False)

    def test_omitted_funded_owner_in_proposed_manifest_fails_even_if_merkle_valid(self):
        changed = copy.deepcopy(self.manifest)
        header = copy.deepcopy(changed["header"])
        header["active_holder_count"] = 2
        header["total_units"] = "120"
        rows = [copy.deepcopy(changed["entries"][0]), copy.deepcopy(changed["entries"][1])]
        rows[0]["leaf_index"] = 0
        rows[1]["leaf_index"] = 1
        forged = canonical.build(header, rows)
        self.assertTrue(canonical.verify_manifest(forged))
        self.fails("OPERATOR_MANIFEST_DISAGREEMENT", manifest=forged)

    def test_redirection_to_wrong_beneficiary_in_operator_manifest_fails(self):
        changed = copy.deepcopy(self.manifest)
        entries = copy.deepcopy(changed["entries"])
        entries[0]["beneficiary"] = h20(250)
        forged = canonical.build(changed["header"], entries)
        self.fails("OPERATOR_MANIFEST_DISAGREEMENT", manifest=forged)

    def test_inflated_units_of_one_holder_and_decreased_another_fails(self):
        entries = copy.deepcopy(self.manifest["entries"])
        entries[0]["units"] = "41"
        entries[1]["units"] = "79"
        forged = canonical.build(self.manifest["header"], entries)
        self.fails("OPERATOR_MANIFEST_DISAGREEMENT", manifest=forged)

    def test_wrong_migration_domain_in_operator_manifest_fails(self):
        header = copy.deepcopy(self.manifest["header"])
        header["migration_id"] = h32(254)
        forged = canonical.build(header, self.manifest["entries"])
        self.fails("OPERATOR_MANIFEST_DISAGREEMENT", manifest=forged)

    def test_missing_historical_slot_fails(self):
        s = copy.deepcopy(self.source)
        s["slots"].pop(1)
        self.fails("INCOMPLETE_HISTORICAL_REGISTRY", source=s)

    def test_duplicate_or_reordered_slot_fails(self):
        s = copy.deepcopy(self.source)
        s["slots"][1], s["slots"][2] = s["slots"][2], s["slots"][1]
        self.fails("MISSING_OR_REORDERED_SLOT", source=s)

    def test_wrong_registry_account_fails(self):
        s = copy.deepcopy(self.source)
        s["slots"][4]["source_account"] = h32(101)
        self.fails("REGISTRY_EVENT_ORDER_MISMATCH", source=s)

    def test_missing_registry_balance_fails(self):
        s = copy.deepcopy(self.source)
        s["slots"][3]["units"] = "79"
        self.fails("REGISTRY_BALANCE_DISAGREEMENT", source=s)

    def test_hidden_zero_holder_breaks_replay_completeness(self):
        s = copy.deepcopy(self.source)
        s["header"]["historical_holder_count"] = 5
        s["slots"] = s["slots"][:5]
        self.fails("HISTORICAL_REGISTRY_COUNT_MISMATCH", source=s)

    def test_missing_issued_event_fails(self):
        s = copy.deepcopy(self.source)
        s["events"].pop(4)
        self.fails("EVENT_SEQUENCE_GAP", source=s)

    def test_missing_transfer_event_fails_even_if_header_unchanged(self):
        s = copy.deepcopy(self.source)
        s["events"].pop(8)
        self.fails("EVENT_SEQUENCE_GAP", source=s)

    def test_reordered_events_fail(self):
        s = copy.deepcopy(self.source)
        s["events"][0], s["events"][1] = s["events"][1], s["events"][0]
        self.fails("EVENT_SEQUENCE_GAP", source=s)

    def test_duplicate_event_index_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][1]["event_index"] = 0
        self.fails("EVENT_SEQUENCE_GAP", source=s)

    def test_fake_deleted_holder_event_is_unsupported(self):
        s = copy.deepcopy(self.source)
        s["events"][6]["kind"] = "Deleted"
        self.fails("INVALID_EVENT_SCHEMA", source=s)

    def test_missing_freeze_fails(self):
        s = copy.deepcopy(self.source)
        s["events"].pop()
        self.fails("MISSING_FREEZE_EVENT", source=s)

    def test_freeze_event_must_be_last(self):
        s = copy.deepcopy(self.source)
        freeze = s["events"].pop()
        s["events"].insert(5, freeze)
        self.fails("EVENT_SEQUENCE_GAP", source=s)

    def test_wrong_freeze_signer_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][-1]["by"] = A
        self.fails("UNAUTHORIZED_FREEZE_ACTOR", source=s)

    def test_freeze_wrong_supply_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][-1]["total_supply"] = "181"
        self.fails("FREEZE_SUPPLY_MISMATCH", source=s)

    def test_freeze_wrong_asset_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][-1]["asset_id"] = h32(254)
        self.fails("FREEZE_ASSET_MISMATCH", source=s)

    def test_source_not_frozen_fails(self):
        s = copy.deepcopy(self.source)
        s["frozen"] = False
        self.fails("SOURCE_NOT_FROZEN", source=s)

    def test_wrong_freeze_block_fails(self):
        s = copy.deepcopy(self.source)
        s["freeze_block_number"] = "12346"
        self.fails("FREEZE_CUTOFF_MISMATCH", source=s)

    def test_supply_cap_rejects_overmint(self):
        s = copy.deepcopy(self.source)
        s["max_supply"] = "190"
        self.fails("ISSUANCE_EXCEEDS_CAP", source=s)

    def test_snapshot_total_above_cap_fails(self):
        s = copy.deepcopy(self.source)
        s["max_supply"] = "170"
        self.fails("SUPPLY_CAP_EXCEEDED", source=s)

    def test_transfer_cannot_spend_nonexistent_source_rights(self):
        s = copy.deepcopy(self.source)
        s["events"][2]["amount"] = "100"
        self.fails("INSUFFICIENT_TRANSFER_BALANCE", source=s)

    def test_burn_cannot_spend_nonexistent_source_rights(self):
        s = copy.deepcopy(self.source)
        s["events"][6]["amount"] = "21"
        self.fails("INSUFFICIENT_BURN_BALANCE", source=s)

    def test_self_transfer_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][2]["to"] = A
        self.fails("SELF_TRANSFER", source=s)

    def test_beneficiary_changes_require_contiguous_nonce(self):
        s = copy.deepcopy(self.source)
        s["events"][11]["nonce"] = "3"
        self.fails("INVALID_BINDING_HISTORY", source=s)

    def test_beneficiary_changes_require_correct_previous_wallet(self):
        s = copy.deepcopy(self.source)
        s["events"][11]["previous_beneficiary"] = h20(212)
        self.fails("INVALID_BINDING_HISTORY", source=s)

    def test_beneficiary_wrong_destination_domain_fails(self):
        s = copy.deepcopy(self.source)
        s["events"][10]["migration_id"] = h32(1)
        self.fails("EVENT_DOMAIN_MISMATCH", source=s)

    def test_stale_binding_at_frozen_registry_fails(self):
        s = copy.deepcopy(self.source)
        s["slots"][3]["beneficiary"] = h20(40)
        self.fails("REGISTRY_BINDING_DISAGREEMENT", source=s)

    def test_unbound_funded_holder_fails_before_replay(self):
        s = copy.deepcopy(self.source)
        s["unbound_active_holders"] = 1
        self.fails("UNBOUND_FUNDED_HOLDERS", source=s)

    def test_binding_only_when_account_currently_positive(self):
        s = copy.deepcopy(self.source)
        s["events"][9]["source_owner"] = C
        self.fails("BINDING_WITHOUT_ACTIVE_ENTITLEMENT", source=s)

    def test_duplicate_or_unknown_event_fields_rejected(self):
        s = copy.deepcopy(self.source)
        s["events"][0]["verified"] = True
        self.fails("INVALID_EVENT_SCHEMA", source=s)

    def test_malformed_bool_event_index_rejected(self):
        s = copy.deepcopy(self.source)
        s["events"][1]["event_index"] = True
        self.fails("INVALID_EVENT_INDEX", source=s)

    def test_overflow_amount_prevented(self):
        s = copy.deepcopy(self.source)
        s["events"][0]["amount"] = str(1 << 128)
        self.fails("INVALID_AMOUNT", source=s)

    def test_hostile_very_long_decimal_amount_fails_cleanly(self):
        s = copy.deepcopy(self.source)
        s["events"][0]["amount"] = "9" * 5000
        self.fails("INVALID_AMOUNT", source=s)

    def test_hostile_very_long_supply_cap_fails_cleanly(self):
        s = copy.deepcopy(self.source)
        s["max_supply"] = "9" * 5000
        self.fails("INVALID_MAX_SUPPLY", source=s)

    def test_reindexed_deleted_issuance_still_fails_accounting(self):
        s = copy.deepcopy(self.source)
        s["events"].pop(5)  # removes original F mint; reindexes to hide gap
        for i, event in enumerate(s["events"]):
            event["event_index"] = i
        self.fails("FREEZE_SUPPLY_MISMATCH", source=s)

    def test_deleted_final_binding_event_with_reindexed_events_fails_freeze(self):
        s = copy.deepcopy(self.source)
        s["events"].pop(12)  # source F no longer has authorized beneficiary
        for i, event in enumerate(s["events"]):
            event["event_index"] = i
        self.fails("FREEZE_UNBOUND_COUNT_MISMATCH", source=s)

    def test_fraudulent_positive_tombstone_balance_rejected(self):
        s = copy.deepcopy(self.source)
        s["slots"][1]["units"] = "1"
        self.fails("REGISTRY_BALANCE_DISAGREEMENT", source=s)

    def test_additional_unrecognized_snapshot_claim_rejected(self):
        s = copy.deepcopy(self.source)
        s["storage_proofs_verified"] = True
        self.fails("INVALID_SNAPSHOT_SCHEMA", source=s)

    def test_truthy_string_does_not_mean_frozen(self):
        s = copy.deepcopy(self.source)
        s["frozen"] = "true"
        self.fails("SOURCE_NOT_FROZEN", source=s)

    def test_invalid_operator_manifest_cannot_be_promoted(self):
        m = copy.deepcopy(self.manifest)
        m["can_claim"] = True
        self.fails("INVALID_OPERATOR_MANIFEST", manifest=m)

    def test_invalid_canonical_asset_hash_rejected(self):
        s = copy.deepcopy(self.source)
        s["header"]["asset_id"] = "0x" + "00" * 32
        self.fails("INVALID_CANONICAL_HEADER", source=s)

class ReconciliationCommandTests(unittest.TestCase):
    def test_valid_fixture_creates_explicitly_untrusted_diagnostic(self):
        from tools.reconciliation.check import main
        source, operator = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            snapshot = path / "source.json"
            manifest = path / "candidate.json"
            result = path / "result.json"
            snapshot.write_text(json.dumps(source), encoding="utf-8")
            manifest.write_text(json.dumps(operator), encoding="utf-8")
            self.assertEqual(main(["--snapshot", str(snapshot), "--manifest", str(manifest),
                                   "--output", str(result)]), 0)
            report = json.loads(result.read_text(encoding="utf-8"))
            self.assertFalse(report["can_activate"])
            self.assertFalse(report["can_claim"])
            self.assertFalse(report["registry_storage_proofs_verified"])

    def test_failed_cli_never_creates_a_success_artifact(self):
        from tools.reconciliation.check import main
        source, operator = fixture()
        operator["can_claim"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            snapshot = path / "source.json"
            manifest = path / "candidate.json"
            result = path / "must-not-exist.json"
            snapshot.write_text(json.dumps(source), encoding="utf-8")
            manifest.write_text(json.dumps(operator), encoding="utf-8")
            self.assertEqual(main(["--snapshot", str(snapshot), "--manifest", str(manifest),
                                   "--output", str(result)]), 2)
            self.assertFalse(result.exists())

    def test_duplicate_json_keys_are_rejected_before_audit(self):
        from tools.reconciliation.check import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            snapshot = path / "duplicate.json"
            manifest = path / "anything.json"
            result = path / "must-not-exist.json"
            snapshot.write_text('{"verified":false,"verified":true}', encoding="utf-8")
            manifest.write_text("{}", encoding="utf-8")
            self.assertEqual(main(["--snapshot", str(snapshot), "--manifest", str(manifest),
                                   "--output", str(result)]), 2)
            self.assertFalse(result.exists())

    def test_existing_result_never_silently_overwritten(self):
        from tools.reconciliation.check import main
        source, operator = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            snapshot = path / "source.json"
            manifest = path / "candidate.json"
            result = path / "existing.json"
            snapshot.write_text(json.dumps(source), encoding="utf-8")
            manifest.write_text(json.dumps(operator), encoding="utf-8")
            result.write_text("PREVIOUS_RESULT", encoding="utf-8")
            self.assertEqual(main(["--snapshot", str(snapshot), "--manifest", str(manifest),
                                   "--output", str(result)]), 2)
            self.assertEqual(result.read_text(encoding="utf-8"), "PREVIOUS_RESULT")


if __name__ == "__main__":
    unittest.main()
