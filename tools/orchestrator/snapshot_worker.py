"""Durable, block-pinned snapshot worker.

Network access and cryptographic finality/trie verification are injected interfaces.
This module refuses to create a run unless those trusted verifiers accept the exact
checkpoint and registry header. It never treats an ordinary RPC response as proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Iterable


class SnapshotError(RuntimeError):
    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


class SnapshotRetryableError(SnapshotError):
    """Temporary verifier/transport outage; retry without accepting partial data."""


@dataclass(frozen=True)
class VerifiedCheckpoint:
    source_chain_id: str
    block_number: int
    block_hash: bytes
    state_root: bytes
    genesis_hash: bytes
    trie_state_version: int
    finality_evidence_digest: bytes


@dataclass(frozen=True)
class RegistryCommitment:
    expected_holder_count: int
    expected_total_supply: int
    header_digest: bytes
    verifier_version: str


@dataclass(frozen=True)
class HolderRecord:
    source_index: int
    source_account_id: bytes
    storage_key: bytes
    amount: int
    proof_bundle: bytes


@dataclass(frozen=True)
class VerifiedHolder:
    source_index: int
    source_account_id: bytes
    storage_key: bytes
    amount: int
    proof_digest: bytes


def canonical_inventory_digest(records: Iterable[VerifiedHolder]) -> bytes:
    """Stable commitment over ordered, individually verified holder records."""
    encoded = []
    for record in sorted(records, key=lambda item: item.source_index):
        encoded.append({
            "source_index": record.source_index,
            "source_account_id": record.source_account_id.hex(),
            "storage_key": record.storage_key.hex(),
            "amount": str(record.amount),
            "proof_digest": record.proof_digest.hex(),
        })
    payload = json.dumps(encoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256(b"METORAH_VERIFIED_INVENTORY_V1\n" + payload.encode("utf-8")).digest()


def _digest(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise SnapshotError("INVALID_" + name.upper(), f"{name} must be exactly 32 bytes.")
    return value


def partition_ranges(holder_count: int, partition_size: int = 64) -> list[tuple[int, int, int]]:
    """Return exact half-open source-index ranges with no overlap or gaps."""
    if type(holder_count) is not int or not 1 <= holder_count <= 1_000_000:
        raise SnapshotError("HOLDER_COUNT_OUT_OF_RANGE")
    if type(partition_size) is not int or not 1 <= partition_size <= 256:
        raise SnapshotError("INVALID_PARTITION_SIZE")
    return [
        (index, start, min(start + partition_size, holder_count))
        for index, start in enumerate(range(0, holder_count, partition_size))
    ]


def _validate_checkpoint(checkpoint: VerifiedCheckpoint) -> None:
    if not isinstance(checkpoint, VerifiedCheckpoint):
        raise SnapshotError("UNVERIFIED_CHECKPOINT", "A trusted finality verifier must return VerifiedCheckpoint.")
    if not checkpoint.source_chain_id or type(checkpoint.block_number) is not int or checkpoint.block_number < 0:
        raise SnapshotError("INVALID_CHECKPOINT")
    _digest(checkpoint.block_hash, "block_hash")
    _digest(checkpoint.state_root, "state_root")
    _digest(checkpoint.genesis_hash, "genesis_hash")
    _digest(checkpoint.finality_evidence_digest, "finality_evidence_digest")
    if type(checkpoint.trie_state_version) is not int or checkpoint.trie_state_version not in (0, 1):
        raise SnapshotError("UNSUPPORTED_TRIE_STATE_VERSION")


def _validate_commitment(commitment: RegistryCommitment) -> None:
    if not isinstance(commitment, RegistryCommitment):
        raise SnapshotError("INVALID_REGISTRY_COMMITMENT")
    if type(commitment.expected_holder_count) is not int or not 1 <= commitment.expected_holder_count <= 1_000_000:
        raise SnapshotError("HOLDER_COUNT_OUT_OF_RANGE")
    if type(commitment.expected_total_supply) is not int or commitment.expected_total_supply < 0:
        raise SnapshotError("INVALID_EXPECTED_TOTAL_SUPPLY")
    _digest(commitment.header_digest, "registry_header_digest")
    if not commitment.verifier_version or len(commitment.verifier_version) > 128:
        raise SnapshotError("INVALID_VERIFIER_VERSION")


def _load_json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class SnapshotWorker:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connect = connection_factory

    def _open(self):
        connection = self._connect()
        return connection, connection.cursor()

    @staticmethod
    def _close(connection: Any, cursor: Any, error: BaseException | None = None) -> None:
        try:
            if error is None:
                connection.commit()
            else:
                connection.rollback()
        finally:
            try:
                cursor.close()
            finally:
                connection.close()

    def create_or_resume_run(
        self,
        *,
        tenant_id: str,
        migration_id: str,
        checkpoint: VerifiedCheckpoint,
        commitment: RegistryCommitment,
        verify_checkpoint: Callable[[VerifiedCheckpoint], bool],
        verify_registry_header: Callable[[VerifiedCheckpoint, RegistryCommitment], bool],
        partition_size: int = 64,
    ) -> dict:
        """Create a run once, or return the existing run at the same pinned hash.

        The callbacks must be trusted implementations backed by finalized-header
        verification and trie/storage proof verification. A caller-provided boolean
        or unauthenticated RPC response is not acceptable in production.
        """
        _validate_checkpoint(checkpoint)
        _validate_commitment(commitment)
        if type(partition_size) is not int or not 1 <= partition_size <= 256:
            raise SnapshotError("INVALID_PARTITION_SIZE")
        try:
            checkpoint_ok = verify_checkpoint(checkpoint)
            header_ok = verify_registry_header(checkpoint, commitment)
        except Exception as exc:
            raise SnapshotError("CHECKPOINT_VERIFICATION_UNAVAILABLE") from exc
        if checkpoint_ok is not True:
            raise SnapshotError("FINALITY_VERIFICATION_FAILED")
        if header_ok is not True:
            raise SnapshotError("REGISTRY_HEADER_PROOF_FAILED")

        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT source_chain_id, source_freeze_block_hash, status "
                "FROM migrations WHERE id=%s AND tenant_id=%s FOR UPDATE",
                (migration_id, tenant_id),
            )
            migration = cursor.fetchone()
            if migration is None:
                raise SnapshotError("MIGRATION_NOT_FOUND")
            source_chain_id, freeze_hash, migration_status = str(migration[0]), migration[1], str(migration[2])
            if source_chain_id != checkpoint.source_chain_id:
                raise SnapshotError("SOURCE_CHAIN_MISMATCH")
            if migration_status not in {"frozen", "verifying"}:
                raise SnapshotError("MIGRATION_NOT_FROZEN")
            if freeze_hash is None or bytes(freeze_hash) != checkpoint.block_hash:
                raise SnapshotError("CHECKPOINT_DIFFERS_FROM_FROZEN_SOURCE")

            cursor.execute(
                "SELECT id, status, expected_holder_count, expected_total_supply, state_root, "
                "genesis_hash, trie_state_version, finality_evidence_digest, registry_header_digest "
                "FROM snapshot_runs WHERE migration_id=%s AND source_chain_id=%s AND pinned_block_hash=%s FOR UPDATE",
                (migration_id, source_chain_id, checkpoint.block_hash),
            )
            existing = cursor.fetchone()
            if existing is not None:
                expected = (
                    int(existing[2]), int(existing[3]), bytes(existing[4]), bytes(existing[5]),
                    int(existing[6]), bytes(existing[7]), bytes(existing[8]),
                )
                supplied = (
                    commitment.expected_holder_count, commitment.expected_total_supply, checkpoint.state_root,
                    checkpoint.genesis_hash, checkpoint.trie_state_version,
                    checkpoint.finality_evidence_digest, commitment.header_digest,
                )
                if expected != supplied:
                    raise SnapshotError("PINNED_RUN_COMMITMENT_CONFLICT")
                self._close(connection, cursor)
                return {
                    "run_id": str(existing[0]), "status": str(existing[1]),
                    "pinned_block_number": checkpoint.block_number,
                    "pinned_block_hash": checkpoint.block_hash.hex(),
                    "expected_holder_count": commitment.expected_holder_count,
                    "expected_total_supply": str(commitment.expected_total_supply),
                    "resumed": True,
                }

            cursor.execute(
                "INSERT INTO snapshot_runs (tenant_id, migration_id, source_chain_id, pinned_block_number, "
                "pinned_block_hash, state_root, genesis_hash, trie_state_version, finality_evidence_digest, "
                "registry_header_digest, expected_holder_count, expected_total_supply) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (tenant_id, migration_id, source_chain_id, checkpoint.block_number, checkpoint.block_hash,
                 checkpoint.state_root, checkpoint.genesis_hash, checkpoint.trie_state_version,
                 checkpoint.finality_evidence_digest, commitment.header_digest,
                 commitment.expected_holder_count, commitment.expected_total_supply),
            )
            run_id = str(cursor.fetchone()[0])
            ranges = partition_ranges(commitment.expected_holder_count, partition_size)
            for partition_index, start, end in ranges:
                cursor.execute(
                    "INSERT INTO snapshot_partitions (run_id, partition_index, start_index, end_index) "
                    "VALUES (%s,%s,%s,%s)",
                    (run_id, partition_index, start, end),
                )
            cursor.execute("UPDATE snapshot_runs SET status='scanning' WHERE id=%s", (run_id,))
            self._close(connection, cursor)
            return {
                "run_id": run_id, "status": "scanning",
                "pinned_block_number": checkpoint.block_number,
                "pinned_block_hash": checkpoint.block_hash.hex(),
                "expected_holder_count": commitment.expected_holder_count,
                "expected_total_supply": str(commitment.expected_total_supply),
                "partition_count": len(ranges), "resumed": False,
            }
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def resume_run(self, tenant_id: str, run_id: str) -> dict:
        """Resume exclusively from the stored checkpoint; no new block input exists."""
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT id, migration_id, source_chain_id, pinned_block_number, pinned_block_hash, state_root, "
                "genesis_hash, trie_state_version, finality_evidence_digest, registry_header_digest, "
                "expected_holder_count, expected_total_supply, status, processed_holder_count, "
                "observed_total_supply, recombined_digest, failure_code "
                "FROM snapshot_runs WHERE id=%s AND tenant_id=%s",
                (run_id, tenant_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise SnapshotError("SNAPSHOT_RUN_NOT_FOUND")
            self._close(connection, cursor)
            return {
                "run_id": str(row[0]), "migration_id": str(row[1]), "source_chain_id": str(row[2]),
                "checkpoint": VerifiedCheckpoint(
                    source_chain_id=str(row[2]), block_number=int(row[3]), block_hash=bytes(row[4]),
                    state_root=bytes(row[5]), genesis_hash=bytes(row[6]), trie_state_version=int(row[7]),
                    finality_evidence_digest=bytes(row[8]),
                ),
                "registry_header_digest": bytes(row[9]),
                "expected_holder_count": int(row[10]), "expected_total_supply": int(row[11]),
                "status": str(row[12]), "processed_holder_count": int(row[13]),
                "observed_total_supply": int(row[14]),
                "recombined_digest": bytes(row[15]) if row[15] is not None else None,
                "failure_code": row[16],
            }
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def claim_partition(self, worker_id: str, lease_seconds: int = 90) -> dict | None:
        if not worker_id or not 5 <= lease_seconds <= 3600:
            raise SnapshotError("INVALID_WORKER_LEASE")
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT p.id, p.run_id, p.partition_index, p.start_index, p.end_index, p.status, "
                "p.attempt_count, p.max_attempts, r.migration_id, r.source_chain_id, "
                "r.pinned_block_number, r.pinned_block_hash, r.state_root, r.genesis_hash, "
                "r.trie_state_version, r.finality_evidence_digest "
                "FROM snapshot_partitions p JOIN snapshot_runs r ON r.id=p.run_id "
                "WHERE r.status='scanning' AND "
                "((p.status='queued' AND p.available_at <= now()) OR (p.status='leased' AND p.lease_until < now())) "
                "ORDER BY p.available_at, p.run_id, p.partition_index LIMIT 1 FOR UPDATE OF p SKIP LOCKED"
            )
            row = cursor.fetchone()
            if row is None:
                self._close(connection, cursor)
                return None
            attempt, maximum = int(row[6]), int(row[7])
            if attempt >= maximum:
                code = "PARTITION_LEASE_EXPIRED_RETRY_LIMIT" if row[5] == "leased" else "PARTITION_RETRY_LIMIT"
                cursor.execute(
                    "UPDATE snapshot_partitions SET status='permanent_failed', worker_id=NULL, lease_until=NULL, "
                    "last_error_code=%s WHERE id=%s",
                    (code, row[0]),
                )
                cursor.execute(
                    "INSERT INTO snapshot_failures (run_id, partition_index, failure_code, retryable) "
                    "VALUES (%s,%s,%s,false)",
                    (row[1], row[2], code),
                )
                cursor.execute(
                    "UPDATE snapshot_runs SET status='failed', failure_code=%s WHERE id=%s",
                    (code, row[1]),
                )
                self._close(connection, cursor)
                return None
            next_attempt = attempt + 1
            cursor.execute(
                "UPDATE snapshot_partitions SET status='leased', attempt_count=%s, worker_id=%s, "
                "lease_until=now()+make_interval(secs => %s), last_error_code=NULL "
                "WHERE id=%s RETURNING lease_until",
                (next_attempt, worker_id, lease_seconds, row[0]),
            )
            lease_until = cursor.fetchone()[0]
            result = {
                "partition_id": str(row[0]), "run_id": str(row[1]), "partition_index": int(row[2]),
                "start_index": int(row[3]), "end_index": int(row[4]), "attempt_count": next_attempt,
                "worker_id": worker_id, "lease_until": lease_until.isoformat(),
                "migration_id": str(row[8]), "checkpoint": VerifiedCheckpoint(
                    source_chain_id=str(row[9]), block_number=int(row[10]), block_hash=bytes(row[11]),
                    state_root=bytes(row[12]), genesis_hash=bytes(row[13]), trie_state_version=int(row[14]),
                    finality_evidence_digest=bytes(row[15]),
                ),
            }
            self._close(connection, cursor)
            return result
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def _fail_run(self, run_id: str, partition_index: int | None, worker_id: str | None, code: str, details: dict | None = None) -> None:
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT status FROM snapshot_runs WHERE id=%s FOR UPDATE", (run_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise SnapshotError("SNAPSHOT_RUN_NOT_FOUND")
            if row[0] not in ("reconciled", "failed", "cancelled"):
                if partition_index is not None:
                    cursor.execute(
                        "UPDATE snapshot_partitions SET status='permanent_failed', worker_id=NULL, lease_until=NULL, "
                        "last_error_code=%s WHERE run_id=%s AND partition_index=%s AND status <> 'completed'",
                        (code, run_id, partition_index),
                    )
                cursor.execute(
                    "INSERT INTO snapshot_failures (run_id, partition_index, worker_id, failure_code, retryable, details) "
                    "VALUES (%s,%s,%s,%s,false,%s::jsonb)",
                    (run_id, partition_index, worker_id, code, json.dumps(details or {}, sort_keys=True)),
                )
                cursor.execute(
                    "UPDATE snapshot_runs SET status='failed', failure_code=%s WHERE id=%s",
                    (code, run_id),
                )
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def retry_partition(self, run_id: str, partition_index: int, worker_id: str, error_code: str) -> bool:
        """Release a leased partition with bounded exponential retry; permanent proof mismatch uses _fail_run."""
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT id, attempt_count, max_attempts FROM snapshot_partitions "
                "WHERE run_id=%s AND partition_index=%s AND status='leased' AND worker_id=%s AND lease_until >= now() FOR UPDATE",
                (run_id, partition_index, worker_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise SnapshotError("PARTITION_LEASE_LOST")
            attempt, maximum = int(row[1]), int(row[2])
            if attempt >= maximum:
                cursor.execute(
                    "UPDATE snapshot_partitions SET status='permanent_failed', worker_id=NULL, lease_until=NULL, "
                    "last_error_code=%s WHERE id=%s", (error_code, row[0])
                )
                cursor.execute(
                    "INSERT INTO snapshot_failures (run_id, partition_index, worker_id, failure_code, retryable) "
                    "VALUES (%s,%s,%s,%s,true)", (run_id, partition_index, worker_id, error_code)
                )
                cursor.execute(
                    "UPDATE snapshot_runs SET status='failed', failure_code=%s WHERE id=%s",
                    ("RETRY_LIMIT_" + error_code, run_id),
                )
                self._close(connection, cursor)
                return False
            delay = min(2 ** attempt, 3600)
            cursor.execute(
                "UPDATE snapshot_partitions SET status='queued', worker_id=NULL, lease_until=NULL, "
                "available_at=now()+make_interval(secs => %s), last_error_code=%s WHERE id=%s",
                (delay, error_code, row[0]),
            )
            cursor.execute(
                "INSERT INTO snapshot_failures (run_id, partition_index, worker_id, failure_code, retryable) "
                "VALUES (%s,%s,%s,%s,true)", (run_id, partition_index, worker_id, error_code)
            )
            self._close(connection, cursor)
            return True
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def complete_partition(
        self,
        run_id: str,
        partition_index: int,
        worker_id: str,
        records: list[HolderRecord],
        verify_holder: Callable[[VerifiedCheckpoint, HolderRecord], VerifiedHolder | None],
        verifier_version: str,
    ) -> dict:
        """Verify every proof at the pinned root, persist once, and reconcile after the final partition."""
        if not verifier_version:
            raise SnapshotError("INVALID_VERIFIER_VERSION")

        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT r.status, r.pinned_block_number, r.pinned_block_hash, r.state_root, r.genesis_hash, "
                "r.source_chain_id, r.trie_state_version, r.finality_evidence_digest, "
                "p.start_index, p.end_index, p.status, p.worker_id, p.lease_until, p.partial_digest, "
                "p.lease_until >= now() "
                "FROM snapshot_runs r JOIN snapshot_partitions p ON p.run_id=r.id "
                "WHERE r.id=%s AND p.partition_index=%s",
                (run_id, partition_index),
            )
            row = cursor.fetchone()
            if row is None:
                raise SnapshotError("PARTITION_NOT_FOUND")
            if row[10] == "completed":
                digest = bytes(row[13]) if row[13] is not None else b""
                self._close(connection, cursor)
                connection = None
                return {"run_id": run_id, "partition_index": partition_index, "status": "completed",
                        "partial_digest": digest.hex(), "idempotent_replay": True}
            if row[0] != "scanning" or row[10] != "leased" or row[11] != worker_id or row[14] is not True:
                raise SnapshotError("PARTITION_LEASE_LOST")
            start, end = int(row[8]), int(row[9])
            checkpoint = VerifiedCheckpoint(
                source_chain_id=str(row[5]), block_number=int(row[1]), block_hash=bytes(row[2]),
                state_root=bytes(row[3]), genesis_hash=bytes(row[4]), trie_state_version=int(row[6]),
                finality_evidence_digest=bytes(row[7]),
            )
            self._close(connection, cursor)
            connection = None
        except BaseException as exc:
            if connection is not None:
                self._close(connection, cursor, exc)
            raise

        if not isinstance(records, list) or len(records) != end - start:
            self._fail_run(run_id, partition_index, worker_id, "INCOMPLETE_PARTITION",
                           {"expected": end - start, "actual": len(records) if isinstance(records, list) else None})
            raise SnapshotError("INCOMPLETE_PARTITION")
        if any(not isinstance(item, HolderRecord) for item in records):
            self._fail_run(run_id, partition_index, worker_id, "INVALID_HOLDER_RECORD")
            raise SnapshotError("INVALID_HOLDER_RECORD")
        if [item.source_index for item in records] != list(range(start, end)):
            self._fail_run(run_id, partition_index, worker_id, "NONCONTIGUOUS_PARTITION")
            raise SnapshotError("NONCONTIGUOUS_PARTITION")

        verified: list[VerifiedHolder] = []
        seen_accounts: set[bytes] = set()
        try:
            for record in records:
                if type(record.amount) is not int or not 0 <= record.amount <= 10**78 - 1:
                    raise SnapshotError("INVALID_HOLDER_AMOUNT")
                if not isinstance(record.source_account_id, bytes) or not 1 <= len(record.source_account_id) <= 64:
                    raise SnapshotError("INVALID_SOURCE_ACCOUNT")
                if not isinstance(record.storage_key, bytes) or not 1 <= len(record.storage_key) <= 512:
                    raise SnapshotError("INVALID_STORAGE_KEY")
                if not isinstance(record.proof_bundle, bytes) or not record.proof_bundle:
                    raise SnapshotError("MISSING_PROOF_BUNDLE")
                if record.source_account_id in seen_accounts:
                    raise SnapshotError("DUPLICATE_SOURCE_ACCOUNT")
                seen_accounts.add(record.source_account_id)
                result = verify_holder(checkpoint, record)
                if not isinstance(result, VerifiedHolder):
                    raise SnapshotError("STORAGE_PROOF_REJECTED")
                if (
                    result.source_index != record.source_index
                    or result.source_account_id != record.source_account_id
                    or result.storage_key != record.storage_key
                    or result.amount != record.amount
                ):
                    raise SnapshotError("VERIFIED_VALUE_MISMATCH")
                _digest(result.proof_digest, "proof_digest")
                verified.append(result)
        except SnapshotRetryableError as exc:
            retry_queued = self.retry_partition(run_id, partition_index, worker_id, exc.code)
            return {"run_id": run_id, "partition_index": partition_index,
                    "status": "queued" if retry_queued else "failed", "failure_code": exc.code}
        except Exception as exc:
            code = exc.code if isinstance(exc, SnapshotError) else "VERIFIER_ERROR"
            self._fail_run(run_id, partition_index, worker_id, code, {"verifier_version": verifier_version})
            if isinstance(exc, SnapshotError):
                raise
            raise SnapshotError(code) from exc

        partition_digest = canonical_inventory_digest(verified)
        proof_digest = sha256(b"".join(item.proof_digest for item in verified)).digest()
        amount_sum = sum(item.amount for item in verified)
        if amount_sum > 10**78 - 1:
            self._fail_run(run_id, partition_index, worker_id, "PARTITION_AMOUNT_OVERFLOW")
            raise SnapshotError("PARTITION_AMOUNT_OVERFLOW")

        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT status, expected_holder_count, expected_total_supply FROM snapshot_runs WHERE id=%s FOR UPDATE",
                (run_id,),
            )
            run = cursor.fetchone()
            cursor.execute(
                "SELECT start_index, end_index, status, worker_id, lease_until, attempt_count, lease_until >= now() "
                "FROM snapshot_partitions WHERE run_id=%s AND partition_index=%s FOR UPDATE",
                (run_id, partition_index),
            )
            part = cursor.fetchone()
            if run is None or part is None or run[0] != "scanning" or part[2] != "leased" or part[3] != worker_id or part[6] is not True:
                raise SnapshotError("PARTITION_LEASE_LOST")
            if int(part[0]) != start or int(part[1]) != end:
                raise SnapshotError("PARTITION_RANGE_CHANGED")

            for item in verified:
                cursor.execute(
                    "INSERT INTO snapshot_holders (run_id, source_index, source_account_id, source_account_digest, "
                    "storage_key, amount, proof_digest, partition_index) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (run_id, item.source_index, item.source_account_id, sha256(item.source_account_id).digest(),
                     item.storage_key, item.amount, item.proof_digest, partition_index),
                )
            cursor.execute(
                "UPDATE snapshot_partitions SET status='completed', worker_id=NULL, lease_until=NULL, "
                "processed_count=%s, amount_sum=%s, partial_digest=%s, proof_bundle_digest=%s, completed_at=now() "
                "WHERE run_id=%s AND partition_index=%s",
                (len(verified), amount_sum, partition_digest, proof_digest, run_id, partition_index),
            )
            cursor.execute(
                "UPDATE snapshot_runs SET processed_holder_count=processed_holder_count+%s, "
                "observed_total_supply=observed_total_supply+%s WHERE id=%s",
                (len(verified), amount_sum, run_id),
            )
            cursor.execute(
                "SELECT count(*) FILTER (WHERE status <> 'completed'), count(*) "
                "FROM snapshot_partitions WHERE run_id=%s",
                (run_id,),
            )
            incomplete, total_partitions = map(int, cursor.fetchone())
            result = {"run_id": run_id, "partition_index": partition_index,
                      "processed_count": len(verified), "status": "scanning"}
            if incomplete == 0 and total_partitions > 0:
                cursor.execute("UPDATE snapshot_runs SET status='reconciling' WHERE id=%s", (run_id,))
                cursor.execute(
                    "SELECT partition_index, start_index, end_index FROM snapshot_partitions "
                    "WHERE run_id=%s ORDER BY partition_index",
                    (run_id,),
                )
                ranges = [(int(x[0]), int(x[1]), int(x[2])) for x in cursor.fetchall()]
                expected_start = 0
                range_mismatch = False
                for expected_index, (partition_index_value, start_index, end_index) in enumerate(ranges):
                    if partition_index_value != expected_index or start_index != expected_start or end_index <= start_index:
                        range_mismatch = True
                        break
                    expected_start = end_index
                cursor.execute(
                    "SELECT source_index, source_account_id, storage_key, amount, proof_digest "
                    "FROM snapshot_holders WHERE run_id=%s ORDER BY source_index",
                    (run_id,),
                )
                rows = cursor.fetchall()
                all_records = [
                    VerifiedHolder(int(x[0]), bytes(x[1]), bytes(x[2]), int(x[3]), bytes(x[4]))
                    for x in rows
                ]
                actual_count = len(all_records)
                actual_total = sum(item.amount for item in all_records)
                recombined = canonical_inventory_digest(all_records)
                expected_count, expected_total = int(run[1]), int(run[2])
                mismatches = []
                if range_mismatch or expected_start != expected_count or actual_count != expected_count:
                    mismatches.append("HOLDER_COMPLETENESS_MISMATCH")
                if actual_total != expected_total:
                    mismatches.append("TOTAL_SUPPLY_MISMATCH")
                outcome = "failed" if mismatches else "verified"
                cursor.execute(
                    "INSERT INTO snapshot_reconciliations (run_id, outcome, pinned_block_hash, expected_holder_count, "
                    "actual_holder_count, expected_total_supply, actual_total_supply, recombined_digest, verifier_version, mismatch_codes) "
                    "VALUES (%s,%s,(SELECT pinned_block_hash FROM snapshot_runs WHERE id=%s),%s,%s,%s,%s,%s,%s,%s)",
                    (run_id, outcome, run_id, expected_count, actual_count, expected_total, actual_total,
                     recombined, verifier_version, mismatches),
                )
                if mismatches:
                    failure_code = "+".join(mismatches)
                    cursor.execute(
                        "UPDATE snapshot_runs SET status='failed', failure_code=%s, recombined_digest=%s WHERE id=%s",
                        (failure_code, recombined, run_id),
                    )
                    cursor.execute(
                        "INSERT INTO snapshot_failures (run_id, failure_code, retryable, details) "
                        "VALUES (%s,%s,false,%s::jsonb)",
                        (run_id, failure_code, json.dumps({"actual_count": actual_count, "actual_total": actual_total})),
                    )
                    result.update({"status": "failed", "failure_code": failure_code})
                else:
                    cursor.execute(
                        "UPDATE snapshot_runs SET status='reconciled', recombined_digest=%s WHERE id=%s",
                        (recombined, run_id),
                    )
                    result.update({"status": "reconciled", "recombined_digest": recombined.hex(),
                                   "holder_count": actual_count, "total_supply": str(actual_total)})
            self._close(connection, cursor)
            connection = None
            return result
        except BaseException as exc:
            if connection is not None:
                self._close(connection, cursor, exc)
            if getattr(exc, "sqlstate", None) in {"23505", "23503", "23514", "22003"}:
                self._fail_run(run_id, partition_index, worker_id, "DUPLICATE_OR_INVALID_SNAPSHOT_RECORD",
                               {"verifier_version": verifier_version})
                raise SnapshotError("DUPLICATE_OR_INVALID_SNAPSHOT_RECORD") from exc
            raise
