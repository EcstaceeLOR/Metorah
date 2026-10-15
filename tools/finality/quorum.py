"""Quorum-based, resumable, read-only Substrate checkpoint acquisition (#30).

STRICT ASSURANCE BOUNDARY:
  * RPC operator independence is explicitly configured, not authenticated.
  * A matching RPC quorum does not authenticate finality, header hashes,
    holder completeness, source identities, or trie membership.
  * No success report ever authorizes a migration, mint, or claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from tools.finality.substrate import (
    FinalityObservationError, HEX_BYTES, JsonRpcReader, PinnedStateReader,
    _hash, _read, observe,
)

MAX_PROVIDERS = 9
MAX_KEYS = 4096
MAX_BATCH = 64
MAX_VALUE_BYTES = 1_048_576
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 1_048_576
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{1,47}\Z")
TRANSIENT = frozenset({"RPC_READ_FAILED", "RPC_UNAVAILABLE", "RPC_HTTP_FAILURE", "RPC_ERROR_RESPONSE"})
STATUS = "MULTI_RPC_STORAGE_CONSISTENT_UNAUTHENTICATED"


class QuorumError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Provider:
    provider_id: str
    operator_id: str
    reader: JsonRpcReader


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(tag: bytes, value: Any) -> str:
    return sha256(tag + _json(value)).hexdigest()


def _storage_key(key: Any) -> str:
    if (type(key) is not str or key == "0x" or HEX_BYTES.fullmatch(key) is None
            or key != key.lower() or len(key) > 2050):
        raise QuorumError("INVALID_CANONICAL_STORAGE_KEY")
    return key


def _storage_value(value: Any) -> str | None:
    if value is None:
        return None
    if (type(value) is not str or HEX_BYTES.fullmatch(value) is None
            or value != value.lower() or len(value) > 2 + 2 * MAX_VALUE_BYTES):
        raise QuorumError("INVALID_STORAGE_VALUE")
    return value


def _metadata(observation: dict[str, Any], metadata_hex: str) -> dict[str, Any]:
    if (observation.get("can_claim") is not False
            or observation.get("can_activate") is not False
            or observation.get("consensus_finality_cryptographically_verified") is not False):
        raise QuorumError("UNEXPECTED_CHAIN_AUTHENTICATION_CLAIM")
    if (type(metadata_hex) is not str or len(metadata_hex) <= 2
            or len(metadata_hex) > 2 + MAX_METADATA_BYTES * 2
            or HEX_BYTES.fullmatch(metadata_hex) is None):
        raise QuorumError("INVALID_RUNTIME_METADATA_BYTES")
    facts = observation["observed"]
    return {
        "runtime_metadata_sha256": sha256(bytes.fromhex(metadata_hex[2:])).hexdigest(),
        "runtime_metadata_size": (len(metadata_hex) - 2) // 2,
        "reported_genesis_hash": facts["reported_genesis_hash"],
        "snapshot_block_hash": facts["snapshot_block_hash"],
        "snapshot_block_number": facts["snapshot_block_number"],
        "snapshot_state_root": facts["snapshot_state_root"],
        "snapshot_extrinsics_root": facts["snapshot_extrinsics_root"],
        "snapshot_parent_hash": facts["snapshot_parent_hash"],
        "snapshot_digest_logs": facts["snapshot_digest_logs"],
        "runtime_at_snapshot": facts["runtime_at_snapshot"],
    }


class MultiRPC:
    """Strict comparison of three or more allegedly independent node operators.

    Every RESPONDING node must agree. Timeouts/network errors may be ignored
    only while two independent nodes finish the same complete batch. Semantic
    discrepancies, fork responses, malformed data and wrong metadata are fatal.
    """

    def __init__(
        self, providers: list[Provider], *,
        expected_genesis_hash: str, pinned_block_hash: str,
        min_quorum: int = 2, max_finalized_lag: int = 256,
        max_head_delta: int = 2,
    ):
        if (type(providers) is not list or not 3 <= len(providers) <= MAX_PROVIDERS):
            raise QuorumError("INVALID_PROVIDER_COUNT")
        ids: set[str] = set()
        operators: set[str] = set()
        for p in providers:
            if (not isinstance(p, Provider)
                    or type(p.provider_id) is not str
                    or IDENTIFIER.fullmatch(p.provider_id) is None
                    or type(p.operator_id) is not str
                    or IDENTIFIER.fullmatch(p.operator_id) is None
                    or p.provider_id in ids or p.operator_id in operators
                    or p.reader is None or not callable(getattr(p.reader, "call", None))):
                raise QuorumError("INVALID_OR_DUPLICATE_PROVIDER_IDENTITY")
            ids.add(p.provider_id)
            operators.add(p.operator_id)
        if type(min_quorum) is not int or not 2 <= min_quorum <= len(providers):
            raise QuorumError("INVALID_QUORUM_POLICY")
        if type(max_head_delta) is not int or not 0 <= max_head_delta <= 64:
            raise QuorumError("INVALID_FINALIZED_HEAD_DELTA")
        if type(max_finalized_lag) is not int or not 0 <= max_finalized_lag <= 4096:
            raise QuorumError("INVALID_FINALITY_LAG_POLICY")
        try:
            self.genesis = _hash(expected_genesis_hash, "INVALID_GENESIS")
            self.block = _hash(pinned_block_hash, "INVALID_CHECKPOINT")
        except FinalityObservationError as e:
            raise QuorumError(e.code) from e
        self.providers = tuple(sorted(providers, key=lambda p: p.provider_id))
        self.min_quorum = min_quorum
        self.max_finalized_lag = max_finalized_lag
        self.max_head_delta = max_head_delta
        self._baseline: dict[str, Any] | None = None
        self._head_high_water: dict[str, int] = {}

    @property
    def source_metadata(self) -> dict[str, Any]:
        if self._baseline is None:
            self.observe_quorum()
        return json.loads(_json(self._baseline))

    @property
    def metadata_checksum(self) -> str:
        return _digest(b"METORAH_MULTI_RPC_METADATA_V1\x00", self.source_metadata)

    def operator_manifest(self) -> list[dict[str, str]]:
        return [
            {"provider_id": p.provider_id, "operator_id": p.operator_id}
            for p in self.providers
        ]

    def observe_quorum(self) -> tuple[dict[str, tuple[Provider, dict]], list[str]]:
        healthy: dict[str, tuple[Provider, dict]] = {}
        failures: list[str] = []
        head_heights: list[int] = []
        hashes_by_height: dict[int, str] = {}
        first_meta: dict[str, Any] | None = None
        # NEVER pick a majority fork and ignore the third responding endpoint.
        for provider in self.providers:
            try:
                observation = observe(
                    provider.reader, expected_genesis_hash=self.genesis,
                    pinned_block_hash=self.block, max_finalized_lag=self.max_finalized_lag,
                )
                # Check actual runtime metadata at the SAME pinned checkpoint,
                # not only a self-reported specVersion or moving-head lookup.
                metadata_hex = _read(provider.reader, "state_getMetadata", [self.block])
            except FinalityObservationError as exc:
                if exc.code in TRANSIENT:
                    failures.append(provider.provider_id)
                    continue
                raise QuorumError("RPC_SEMANTIC_FAILURE_" + exc.code) from exc
            metadata = _metadata(observation, metadata_hex)
            if first_meta is None:
                first_meta = metadata
            elif metadata != first_meta:
                raise QuorumError("RPC_CHECKPOINT_SPLIT_BRAIN")
            if self._baseline is not None and metadata != self._baseline:
                raise QuorumError("PINNED_METADATA_CHANGED")
            facts = observation["observed"]
            height = facts["reported_finalized_number"]
            finality = facts["reported_finalized_hash"]
            last = self._head_high_water.get(provider.provider_id)
            if last is not None and height < last:
                raise QuorumError("FINALIZED_HEAD_REGRESSION")
            if height in hashes_by_height and hashes_by_height[height] != finality:
                raise QuorumError("SPLIT_BRAIN_FINALIZED_HEAD")
            hashes_by_height[height] = finality
            head_heights.append(height)
            healthy[provider.provider_id] = (provider, observation)
        if (not healthy or len(healthy) < self.min_quorum):
            raise QuorumError("INSUFFICIENT_INDEPENDENT_RPC_QUORUM")
        if max(head_heights) - min(head_heights) > self.max_head_delta:
            raise QuorumError("STALLED_OR_STALE_FINALIZED_HEAD")
        # Different heights can be normal lag. To distinguish genuine lag
        # from a fork hidden at the same overlapping finalized height, query
        # every respondent for the hash at the common minimum height.
        # A majority must NEVER overrule a conflicting responder.
        common_height = min(head_heights)
        common_hash: str | None = None
        for provider_id, (provider, _) in list(healthy.items()):
            try:
                value = _hash(
                    _read(provider.reader, "chain_getBlockHash", [common_height]),
                    "INVALID_COMMON_FINALIZED_HASH",
                )
            except FinalityObservationError as exc:
                if exc.code in TRANSIENT:
                    failures.append(provider_id)
                    del healthy[provider_id]
                    continue
                raise QuorumError("RPC_SEMANTIC_FAILURE_" + exc.code) from exc
            if common_hash is not None and value != common_hash:
                raise QuorumError("SPLIT_BRAIN_FINALIZED_ANCESTRY")
            common_hash = value
        if len(healthy) < self.min_quorum:
            raise QuorumError("INSUFFICIENT_INDEPENDENT_RPC_QUORUM")
        for provider_id, (_, obs) in healthy.items():
            self._head_high_water[provider_id] = obs["observed"]["reported_finalized_number"]
        if self._baseline is None:
            self._baseline = first_meta
        return healthy, failures

    def read_batch(self, keys: list[str]) -> dict[str, Any]:
        if (type(keys) is not list or not 1 <= len(keys) <= MAX_BATCH
                or any(_storage_key(k) != k for k in keys)
                or keys != sorted(set(keys))):
            raise QuorumError("INVALID_BATCH_STORAGE_KEYS")
        before, failures_before = self.observe_quorum()
        votes: list[tuple[str, list[dict[str, Any]]]] = []
        unavailable = set(failures_before)
        for provider_id, (provider, observation) in before.items():
            reader = PinnedStateReader(provider.reader, observation)
            try:
                values = [
                    {"key": key, "value": _storage_value(reader.storage(key))}
                    for key in keys
                ]
            except FinalityObservationError as exc:
                if exc.code in TRANSIENT:
                    unavailable.add(provider_id)
                    continue
                raise QuorumError("RPC_STORAGE_FAILURE_" + exc.code) from exc
            if votes and values != votes[0][1]:
                raise QuorumError("RPC_STORAGE_VALUE_SPLIT_BRAIN")
            votes.append((provider_id, values))
        # Follow-up observation catches a fork, changed header or stale metadata
        # mid-batch. A vote counts only if the provider passes AFTER the reads.
        after, failures_after = self.observe_quorum()
        unavailable.update(failures_after)
        valid = [(pid, rows) for pid, rows in votes if pid in after]
        if len(valid) < self.min_quorum:
            raise QuorumError("INSUFFICIENT_STABLE_RPC_VOTES")
        if any(rows != valid[0][1] for _, rows in valid[1:]):
            raise QuorumError("RPC_STORAGE_VALUE_SPLIT_BRAIN")
        return {
            "records": valid[0][1],
            "agreeing_providers": sorted(pid for pid, _ in valid),
            "unavailable_providers": sorted(unavailable),
        }


class ResumableAcquisition:
    """One immutable root/key/provider plan, atomically journalled by batch.

    Resume re-queries ALL committed keys, not merely their hashes, to detect
    stale/corrupt or differently answered RPC values across retry sessions.
    Journal SHA-256 is an accidental corruption checksum, NOT a signature.
    """
    def __init__(self, quorum: MultiRPC, keys: list[str], journal: Path, *,
                 batch_size: int = 32):
        if (type(keys) is not list or not 1 <= len(keys) <= MAX_KEYS
                or any(_storage_key(x) != x for x in keys)
                or keys != sorted(set(keys))):
            raise QuorumError("INVALID_ACQUISITION_STORAGE_KEYS")
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_BATCH:
            raise QuorumError("INVALID_BATCH_SIZE")
        if not isinstance(journal, Path):
            raise QuorumError("INVALID_JOURNAL_PATH")
        if journal.is_symlink() or (journal.exists() and not journal.is_file()):
            raise QuorumError("INVALID_JOURNAL_FILE")
        self.quorum = quorum
        self.keys = keys[:]
        self.journal = journal
        self.batch_size = batch_size
        # Header checks must succeed before creating or reading a journal.
        quorum.observe_quorum()
        self.plan = {
            "genesis_hash": quorum.genesis,
            "block_hash": quorum.block,
            "metadata_checksum": quorum.metadata_checksum,
            "operators": quorum.operator_manifest(),
            "quorum_size": quorum.min_quorum,
            "max_head_delta": quorum.max_head_delta,
            "max_finalized_lag": quorum.max_finalized_lag,
            "keys": self.keys,
            "batch_size": batch_size,
        }
        self.plan_digest = _digest(b"METORAH_MULTI_RPC_PLAN_V1\x00", self.plan)

    @staticmethod
    def _seal(doc: dict) -> dict:
        without = {k: v for k, v in doc.items() if k != "journal_sha256"}
        return {**without,
                "journal_sha256": _digest(b"METORAH_MULTI_RPC_JOURNAL_V1\x00", without)}

    def _new(self) -> dict:
        return self._seal({
            "schema_version": "metorah-multirpc-journal-v1",
            "status": "CHECKPOINT_ACQUISITION_PARTIAL_UNAUTHENTICATED",
            "plan_digest": self.plan_digest,
            "plan": self.plan,
            "batches": [],
            "head_watermarks": {},
            "can_activate": False,
            "can_claim": False,
        })

    def _load(self) -> dict:
        if not self.journal.exists():
            return self._new()
        if self.journal.stat().st_size > MAX_JOURNAL_BYTES:
            raise QuorumError("JOURNAL_TOO_LARGE")
        try:
            def reject_duplicate(pairs):
                result = {}
                for k, v in pairs:
                    if k in result:
                        raise QuorumError("DUPLICATE_JOURNAL_KEY")
                    result[k] = v
                return result
            doc = json.loads(self.journal.read_text(encoding="utf-8"),
                             object_pairs_hook=reject_duplicate)
        except QuorumError:
            raise
        except (UnicodeError, ValueError, OSError) as e:
            raise QuorumError("INVALID_JOURNAL_ENCODING") from e
        if (type(doc) is not dict or set(doc) != set(self._new())
                or doc["schema_version"] != "metorah-multirpc-journal-v1"
                or doc["plan"] != self.plan
                or doc["plan_digest"] != self.plan_digest
                or doc["can_activate"] is not False or doc["can_claim"] is not False
                or doc != self._seal(doc)):
            raise QuorumError("JOURNAL_SESSION_OR_DIGEST_MISMATCH")
        batches = doc["batches"]
        if type(batches) is not list:
            raise QuorumError("INVALID_JOURNAL_BATCHES")
        offset = 0
        allowed = {p.provider_id for p in self.quorum.providers}
        watermarks = doc["head_watermarks"]
        if (type(watermarks) is not dict
                or not set(watermarks).issubset(allowed)
                or any(type(v) is not int or not 0 <= v <= (2**64 - 1)
                       for v in watermarks.values())):
            raise QuorumError("INVALID_JOURNAL_HEAD_WATERMARKS")
        # In-memory checks are reset on process restart. Persist the highest
        # finalized height ever observed for EACH configured provider so a
        # restarted process cannot silently accept regressed finality.
        for provider_id, previous in watermarks.items():
            current = self.quorum._head_high_water.get(provider_id)
            if current is not None and current < previous:
                raise QuorumError("FINALIZED_HEAD_REGRESSION_ACROSS_RESUME")
            self.quorum._head_high_water[provider_id] = max(previous, current or 0)
        for batch in batches:
            if (type(batch) is not dict
                    or set(batch) != {"offset", "records", "agreeing_providers"}
                    or type(batch["offset"]) is not int or batch["offset"] != offset
                    or type(batch["records"]) is not list
                    or len(batch["records"]) != min(self.batch_size, len(self.keys) - offset)
                    or type(batch["agreeing_providers"]) is not list
                    or batch["agreeing_providers"] != sorted(set(batch["agreeing_providers"]))
                    or len(batch["agreeing_providers"]) < self.quorum.min_quorum
                    or any(p not in allowed for p in batch["agreeing_providers"])):
                raise QuorumError("INVALID_JOURNAL_BATCH_SEQUENCE")
            expected_keys = self.keys[offset:offset + len(batch["records"])]
            for expected, row in zip(expected_keys, batch["records"]):
                if (type(row) is not dict or set(row) != {"key", "value"}
                        or row["key"] != expected):
                    raise QuorumError("JOURNAL_KEY_MISMATCH")
                _storage_value(row["value"])
            offset += len(batch["records"])
        if doc["status"] not in {
            "CHECKPOINT_ACQUISITION_PARTIAL_UNAUTHENTICATED",
            STATUS,
        } or (doc["status"] == STATUS) != (offset == len(self.keys)):
            raise QuorumError("INVALID_JOURNAL_STATUS")
        return doc

    def _write(self, document: dict) -> None:
        payload = _json(self._seal(document)) + b"\n"
        if len(payload) > MAX_JOURNAL_BYTES:
            raise QuorumError("ACQUISITION_JOURNAL_LIMIT_EXCEEDED")
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        target = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.journal.parent,
                prefix=".metorah-multirpc-", suffix=".tmp", delete=False,
            ) as stream:
                target = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(target, self.journal)
        except OSError as e:
            raise QuorumError("JOURNAL_WRITE_FAILED") from e
        finally:
            if target is not None:
                target.unlink(missing_ok=True)

    def run(self) -> dict:
        doc = self._load()
        # A resume validates *actual bytes* from all previous batches under
        # the current independent quorum, not merely a diagnostic checksum.
        for batch in doc["batches"]:
            old = batch["records"]
            new = self.quorum.read_batch([item["key"] for item in old])
            if new["records"] != old:
                raise QuorumError("RESUME_PREVIOUS_STORAGE_MISMATCH")
        offset = sum(len(b["records"]) for b in doc["batches"])
        while offset < len(self.keys):
            chunk = self.keys[offset:offset + self.batch_size]
            answer = self.quorum.read_batch(chunk)
            doc["batches"].append({
                "offset": offset,
                "records": answer["records"],
                "agreeing_providers": answer["agreeing_providers"],
            })
            offset += len(chunk)
            if offset == len(self.keys):
                doc["status"] = STATUS
            doc["head_watermarks"] = dict(self.quorum._head_high_water)
            self._write(doc)
        self.quorum.observe_quorum()
        # Persist finalized-head advances seen in this final observation too.
        doc["head_watermarks"] = dict(self.quorum._head_high_water)
        self._write(doc)
        report = {
            "schema_version": "metorah-multirpc-report-v1",
            "status": STATUS,
            "genesis_hash": self.quorum.genesis,
            "pinned_block_hash": self.quorum.block,
            "source_metadata": self.quorum.source_metadata,
            "metadata_sha256_not_proof": self.quorum.metadata_checksum,
            "plan_sha256_not_proof": self.plan_digest,
            "provider_operators_declared_not_verified": self.quorum.operator_manifest(),
            "queried_storage_keys": len(self.keys),
            "completed_batches": len(doc["batches"]),
            "records": [row for batch in doc["batches"] for row in batch["records"]],
            "genesis_authenticated": False,
            "finality_cryptographically_verified": False,
            "trie_membership_verified": False,
            "operator_independence_verified": False,
            "can_activate": False,
            "can_claim": False,
            "warning": (
                "RPC majority does not prove finality. All records are unverified "
                "against consensus and the actual source trie; journal SHA256 is "
                "not a signature. Production migration and claims remain blocked."
            ),
        }
        return report
