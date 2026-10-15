"""PostgreSQL-backed migration lifecycle and durable job/outbox primitives.

The caller must supply a connection factory for a least-privilege PostgreSQL role and
must pass claims only after cryptographic JWT verification. This module is not a JWT
verifier, chain proof verifier, or substitute for reviewed production authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Iterable


class OrchestrationError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


class LeaseLost(OrchestrationError):
    def __init__(self):
        super().__init__(409, "job_lease_lost", "The job lease is no longer owned by this worker.")


@dataclass(frozen=True)
class Actor:
    tenant_id: str
    subject: str
    roles: tuple[str, ...]
    actor_type: str = "user"


# Each edge requires a role and gates produced by trusted internal verifiers/reviewers.
TRANSITIONS: dict[tuple[str, str], tuple[frozenset[str], frozenset[str]]] = {
    ("draft", "prepared"): (frozenset({"owner", "admin", "operator"}), frozenset({"source_eligible", "mapping_window_closed"})),
    ("draft", "enumerating"): (frozenset({"owner", "admin", "operator"}), frozenset({"source_eligible"})),
    ("draft", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("prepared", "frozen"): (frozenset({"owner", "admin", "governance", "source_governance"}), frozenset({"freeze_finalized", "source_retired"})),
    ("prepared", "disputed"): (frozenset({"owner", "admin", "guardian"}), frozenset({"challenge_recorded"})),
    ("prepared", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("enumerating", "frozen"): (frozenset({"owner", "admin", "governance", "source_governance"}), frozenset({"freeze_finalized", "source_retired"})),
    ("enumerating", "disputed"): (frozenset({"owner", "admin", "guardian"}), frozenset({"challenge_recorded"})),
    ("enumerating", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("frozen", "verifying"): (frozenset({"owner", "admin", "verifier"}), frozenset({"header_verified", "trie_verified", "holders_complete", "bindings_verified"})),
    ("frozen", "disputed"): (frozenset({"owner", "admin", "guardian"}), frozenset({"challenge_recorded"})),
    ("frozen", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("verifying", "review"): (frozenset({"owner", "admin", "security_reviewer"}), frozenset({"manifest_domain_bound"})),
    ("verifying", "frozen"): (frozenset({"owner", "admin", "verifier"}), frozenset({"verification_failed", "source_snapshot_unchanged"})),
    ("verifying", "disputed"): (frozenset({"owner", "admin", "guardian"}), frozenset({"challenge_recorded"})),
    ("review", "approved"): (frozenset({"owner", "admin", "security_reviewer"}), frozenset({"review_complete", "disputes_cleared"})),
    ("review", "frozen"): (frozenset({"owner", "admin", "verifier"}), frozenset({"reverification_required"})),
    ("review", "disputed"): (frozenset({"owner", "admin", "guardian"}), frozenset({"challenge_recorded"})),
    ("review", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("approved", "funding"): (frozenset({"owner", "admin", "governance"}), frozenset({"funding_plan_approved"})),
    ("approved", "ready"): (frozenset({"owner", "admin", "governance"}), frozenset({"backing_verified", "disputes_cleared"})),
    ("approved", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_recorded"})),
    ("approved", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("funding", "ready"): (frozenset({"owner", "admin", "governance", "service"}), frozenset({"backing_verified"})),
    ("funding", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_recorded"})),
    ("ready", "activated"): (frozenset({"owner", "admin", "governance"}), frozenset({"source_retired", "backing_verified", "disputes_cleared"})),
    ("ready", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_recorded"})),
    ("activated", "claiming"): (frozenset({"owner", "admin", "service"}), frozenset({"first_settlement_finalized"})),
    ("activated", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_recorded"})),
    ("claiming", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_recorded"})),
    ("claiming", "completed"): (frozenset({"owner", "admin", "governance"}), frozenset({"claim_window_ended", "liabilities_reconciled"})),
    ("paused", "activated"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_resolved", "backing_verified", "no_prior_claims"})),
    ("paused", "claiming"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_resolved", "backing_verified", "prior_claims_reconciled"})),
    ("disputed", "frozen"): (frozenset({"owner", "admin", "verifier"}), frozenset({"dispute_resolved", "freeze_finalized", "source_retired"})),
    ("disputed", "cancelled"): (frozenset({"owner", "admin", "governance"}), frozenset({"no_settlement"})),
    ("incident", "paused"): (frozenset({"owner", "admin", "guardian"}), frozenset({"incident_reviewed"})),
    ("incident", "verifying"): (frozenset({"owner", "admin", "verifier"}), frozenset({"incident_resolved", "source_snapshot_unchanged"})),
    ("incident", "frozen"): (frozenset({"owner", "admin", "verifier"}), frozenset({"incident_resolved", "freeze_finalized", "source_retired"})),
}
VALID_ACTOR_TYPES = {"user", "service", "governance", "chain"}


def canonical_request_hash(payload: Any) -> bytes:
    """Hash canonical JSON, rejecting NaN and other non-standard JSON values."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256(encoded.encode("utf-8")).digest()


def _json_load(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class DurableOrchestrator:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connect = connection_factory

    def _open(self):
        connection = self._connect()
        cursor = connection.cursor()
        return connection, cursor

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

    @staticmethod
    def _validate_actor(actor: Actor) -> None:
        if not isinstance(actor, Actor) or not actor.tenant_id or not actor.subject or not actor.roles:
            raise OrchestrationError(401, "unauthorized", "A verified tenant-scoped actor is required.")
        if actor.actor_type not in VALID_ACTOR_TYPES:
            raise OrchestrationError(401, "unauthorized", "Actor type is not trusted.")

    @staticmethod
    def _idempotency_begin(cursor: Any, tenant_id: str, actor_subject: str, operation: str, key: str, request_hash: bytes):
        if not isinstance(key, str) or len(key.strip()) < 8 or len(key) > 200:
            raise OrchestrationError(400, "invalid_request", "Idempotency key must contain 8–200 characters.")
        cursor.execute(
            "SELECT request_hash, response_status, response_body, resource_id, actor_subject "
            "FROM idempotency_records WHERE tenant_id=%s AND operation=%s AND idempotency_key=%s FOR UPDATE",
            (tenant_id, operation, key),
        )
        saved = cursor.fetchone()
        if saved is not None:
            if saved[4] != actor_subject:
                raise OrchestrationError(404, "not_found", "Idempotent operation not found.")
            if bytes(saved[0]) != request_hash:
                raise OrchestrationError(409, "idempotency_conflict", "Idempotency key was reused with a different request.")
            if saved[1] is None or saved[2] is None:
                raise OrchestrationError(409, "operation_in_progress", "The idempotent operation has no committed response.")
            return {"status": int(saved[1]), "body": _json_load(saved[2]), "resource_id": str(saved[3]) if saved[3] else None}

        cursor.execute(
            "INSERT INTO idempotency_records (tenant_id, operation, actor_subject, idempotency_key, request_hash) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id, operation, idempotency_key) DO NOTHING RETURNING id",
            (tenant_id, operation, actor_subject, key, request_hash),
        )
        inserted = cursor.fetchone()
        if inserted is None:
            cursor.execute(
                "SELECT request_hash, response_status, response_body, resource_id, actor_subject "
                "FROM idempotency_records WHERE tenant_id=%s AND operation=%s AND idempotency_key=%s FOR UPDATE",
                (tenant_id, operation, key),
            )
            saved = cursor.fetchone()
            if saved is None:
                raise OrchestrationError(409, "operation_in_progress", "Idempotency record is concurrently being created.")
            if saved[4] != actor_subject:
                raise OrchestrationError(404, "not_found", "Idempotent operation not found.")
            if bytes(saved[0]) != request_hash:
                raise OrchestrationError(409, "idempotency_conflict", "Idempotency key was reused with a different request.")
            if saved[1] is None or saved[2] is None:
                raise OrchestrationError(409, "operation_in_progress", "The idempotent operation has no committed response.")
            return {"status": int(saved[1]), "body": _json_load(saved[2]), "resource_id": str(saved[3]) if saved[3] else None}
        return None

    @staticmethod
    def _idempotency_finish(cursor: Any, tenant_id: str, operation: str, key: str, status: int, body: dict, resource_id: str | None):
        cursor.execute(
            "UPDATE idempotency_records SET response_status=%s, response_body=%s::jsonb, resource_id=%s "
            "WHERE tenant_id=%s AND operation=%s AND idempotency_key=%s",
            (status, _dump(body), resource_id, tenant_id, operation, key),
        )

    def transition_migration(
        self,
        actor: Actor,
        migration_id: str,
        target: str,
        expected_version: int,
        idempotency_key: str,
        reason_code: str,
        verified_gates: Iterable[str],
        correlation_id: str | None = None,
    ) -> dict:
        """Perform one role/gate-checked, versioned transition in one DB transaction.

        verified_gates must be emitted by trusted internal verifiers/reviewers, never copied
        directly from client JSON. SQL triggers independently enforce allowed state edges,
        attribution, state-event creation and transactional outbox insertion.
        """
        self._validate_actor(actor)
        if not reason_code or expected_version < 1:
            raise OrchestrationError(400, "invalid_request", "Reason and positive expected_version are required.")
        gates = frozenset(verified_gates)
        connection, cursor = self._open()
        error = None
        try:
            fingerprint = {
                "migration_id": migration_id, "target": target, "expected_version": expected_version,
                "reason_code": reason_code, "gates": sorted(gates), "correlation_id": correlation_id,
            }
            request_hash = canonical_request_hash(fingerprint)
            replay = self._idempotency_begin(cursor, actor.tenant_id, actor.subject, "migration.transition", idempotency_key, request_hash)
            if replay is not None:
                self._close(connection, cursor)
                return replay["body"]

            cursor.execute(
                "SELECT status, version FROM migrations WHERE id=%s AND tenant_id=%s FOR UPDATE",
                (migration_id, actor.tenant_id),
            )
            current = cursor.fetchone()
            if current is None:
                raise OrchestrationError(404, "not_found", "Migration not found.")
            current_state, current_version = str(current[0]), int(current[1])
            if current_version != expected_version:
                raise OrchestrationError(409, "version_conflict", "Migration changed; refresh and retry with a new idempotency key.")
            rule = TRANSITIONS.get((current_state, target))
            if rule is None:
                raise OrchestrationError(409, "invalid_transition", f"Transition {current_state} -> {target} is not allowed.")
            roles, required_gates = rule
            if not roles.intersection(actor.roles):
                raise OrchestrationError(403, "forbidden", "Actor role cannot perform this transition.")
            if not required_gates.issubset(gates):
                raise OrchestrationError(422, "precondition_failed", "Required independently verified lifecycle gates are missing.")

            cursor.execute(
                "SELECT set_config('metorah.actor_type', %s, true), "
                "set_config('metorah.actor_id', %s, true), "
                "set_config('metorah.reason_code', %s, true), "
                "set_config('metorah.correlation_id', %s, true)",
                (actor.actor_type, actor.subject, reason_code, correlation_id or ""),
            )
            cursor.execute(
                "UPDATE migrations SET status=%s, version=version+1 "
                "WHERE id=%s AND tenant_id=%s AND version=%s RETURNING id, status, version, updated_at",
                (target, migration_id, actor.tenant_id, expected_version),
            )
            updated = cursor.fetchone()
            if updated is None:
                raise OrchestrationError(409, "version_conflict", "Migration changed during transition.")
            body = {
                "migration_id": str(updated[0]), "status": str(updated[1]),
                "version": int(updated[2]), "updated_at": updated[3].isoformat(),
            }
            self._idempotency_finish(cursor, actor.tenant_id, "migration.transition", idempotency_key, 200, body, str(updated[0]))
            self._close(connection, cursor)
            return body
        except BaseException as exc:
            error = exc
            self._close(connection, cursor, error)
            raise

    def enqueue_job(self, actor: Actor, migration_id: str, job_kind: str, idempotency_key: str, payload: dict) -> dict:
        self._validate_actor(actor)
        if not job_kind or not isinstance(payload, dict):
            raise OrchestrationError(400, "invalid_request", "job_kind and JSON object payload are required.")
        connection, cursor = self._open()
        try:
            request = {"migration_id": migration_id, "job_kind": job_kind, "payload": payload}
            request_hash = canonical_request_hash(request)
            operation = "job.enqueue"
            replay = self._idempotency_begin(cursor, actor.tenant_id, actor.subject, operation, idempotency_key, request_hash)
            if replay is not None:
                self._close(connection, cursor)
                return replay["body"]
            cursor.execute("SELECT id FROM migrations WHERE id=%s AND tenant_id=%s FOR UPDATE", (migration_id, actor.tenant_id))
            if cursor.fetchone() is None:
                raise OrchestrationError(404, "not_found", "Migration not found.")
            cursor.execute(
                "INSERT INTO jobs (migration_id, job_kind, idempotency_key, payload) "
                "VALUES (%s,%s,%s,%s::jsonb) RETURNING id, state, created_at",
                (migration_id, job_kind, idempotency_key, _dump(payload)),
            )
            row = cursor.fetchone()
            body = {"id": str(row[0]), "state": str(row[1]), "created_at": row[2].isoformat()}
            self._idempotency_finish(cursor, actor.tenant_id, operation, idempotency_key, 202, body, str(row[0]))
            self._close(connection, cursor)
            return body
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def claim_next_job(self, worker_id: str, lease_seconds: int = 60) -> dict | None:
        if not worker_id or lease_seconds < 5 or lease_seconds > 3600:
            raise OrchestrationError(400, "invalid_request", "Worker ID and lease between 5 and 3600 seconds are required.")
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT id, migration_id, job_kind, payload, state, attempt_count, max_attempts, last_started_at "
                "FROM jobs WHERE ((state IN ('queued','retry_wait') AND available_at <= now()) "
                "OR (state='running' AND lease_until < now())) "
                "ORDER BY available_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED"
            )
            row = cursor.fetchone()
            if row is None:
                self._close(connection, cursor)
                return None
            job_id, migration_id, kind, payload, state, attempts, max_attempts, last_started = row
            attempts, max_attempts = int(attempts), int(max_attempts)
            if state == "running":
                cursor.execute(
                    "INSERT INTO job_attempts (job_id, attempt_number, started_at, finished_at, outcome, error_code) "
                    "VALUES (%s,%s,COALESCE(%s,now()),now(),'failed','WORKER_LEASE_EXPIRED') "
                    "ON CONFLICT (job_id, attempt_number) DO NOTHING",
                    (job_id, attempts, last_started),
                )
                cursor.execute(
                    "INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id, details) "
                    "VALUES (%s,%s,'lease_expired',NULL,'{}'::jsonb)",
                    (job_id, attempts),
                )
                if attempts >= max_attempts:
                    cursor.execute(
                        "UPDATE jobs SET state='failed', worker_id=NULL, lease_until=NULL, "
                        "last_error_code='WORKER_LEASE_EXPIRED' WHERE id=%s",
                        (job_id,),
                    )
                    self._close(connection, cursor)
                    return None
            next_attempt = attempts + 1
            cursor.execute(
                "UPDATE jobs SET state='running', attempt_count=%s, worker_id=%s, "
                "lease_until=now()+make_interval(secs => %s), last_started_at=now(), "
                "last_heartbeat_at=now(), last_error_code=NULL WHERE id=%s "
                "RETURNING id, migration_id, job_kind, payload, state, attempt_count, lease_until",
                (next_attempt, worker_id, lease_seconds, job_id),
            )
            claimed = cursor.fetchone()
            cursor.execute(
                "INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id) "
                "VALUES (%s,%s,'started',%s)",
                (job_id, next_attempt, worker_id),
            )
            self._close(connection, cursor)
            return {
                "id": str(claimed[0]), "migration_id": str(claimed[1]), "job_kind": str(claimed[2]),
                "payload": _json_load(claimed[3]), "state": str(claimed[4]),
                "attempt_count": int(claimed[5]), "lease_until": claimed[6].isoformat(),
                "worker_id": worker_id,
            }
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def heartbeat_job(self, job_id: str, worker_id: str, lease_seconds: int = 60) -> str:
        if lease_seconds < 5 or lease_seconds > 3600:
            raise OrchestrationError(400, "invalid_request", "Lease must be between 5 and 3600 seconds.")
        connection, cursor = self._open()
        try:
            cursor.execute(
                "UPDATE jobs SET last_heartbeat_at=now(), lease_until=now()+make_interval(secs => %s) "
                "WHERE id=%s AND state='running' AND worker_id=%s AND lease_until >= now() "
                "RETURNING attempt_count, lease_until",
                (lease_seconds, job_id, worker_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise LeaseLost()
            cursor.execute(
                "INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id) "
                "VALUES (%s,%s,'heartbeat',%s)",
                (job_id, int(row[0]), worker_id),
            )
            self._close(connection, cursor)
            return row[1].isoformat()
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def finish_job(self, job_id: str, worker_id: str, succeeded: bool, error_code: str | None = None) -> dict:
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT attempt_count, max_attempts, last_started_at, state FROM jobs "
                "WHERE id=%s AND worker_id=%s AND state='running' AND lease_until >= now() FOR UPDATE",
                (job_id, worker_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise LeaseLost()
            attempts, max_attempts, started_at, _state = int(row[0]), int(row[1]), row[2], row[3]
            if succeeded:
                final_state, outcome = "succeeded", "succeeded"
                delay = 0
                error_code = None
            elif attempts < max_attempts:
                final_state, outcome = "retry_wait", "failed"
                delay = min(2 ** attempts, 3600)
                error_code = error_code or "JOB_FAILED"
            else:
                final_state, outcome = "failed", "failed"
                delay = 0
                error_code = error_code or "JOB_FAILED"
            cursor.execute(
                "INSERT INTO job_attempts (job_id, attempt_number, started_at, finished_at, outcome, error_code) "
                "VALUES (%s,%s,COALESCE(%s,now()),now(),%s,%s)",
                (job_id, attempts, started_at, outcome, error_code),
            )
            cursor.execute(
                "INSERT INTO job_attempt_events (job_id, attempt_number, event_type, worker_id, details) "
                "VALUES (%s,%s,%s,%s,%s::jsonb)",
                (job_id, attempts, outcome, worker_id, _dump({"error_code": error_code} if error_code else {})),
            )
            cursor.execute(
                "UPDATE jobs SET state=%s, worker_id=NULL, lease_until=NULL, last_error_code=%s, "
                "available_at=now()+make_interval(secs => %s) WHERE id=%s "
                "RETURNING id, state, attempt_count, completed_at, available_at",
                (final_state, error_code, delay, job_id),
            )
            updated = cursor.fetchone()
            result = {"id": str(updated[0]), "state": str(updated[1]), "attempt_count": int(updated[2])}
            if updated[3] is not None:
                result["completed_at"] = updated[3].isoformat()
            if final_state == "retry_wait":
                result["retry_at"] = updated[4].isoformat()
            self._close(connection, cursor)
            return result
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def claim_outbox_batch(self, worker_id: str, limit: int = 50, lease_seconds: int = 30) -> list[dict]:
        if not worker_id or not 1 <= limit <= 500 or not 5 <= lease_seconds <= 3600:
            raise OrchestrationError(400, "invalid_request", "Invalid outbox worker, batch limit, or lease.")
        connection, cursor = self._open()
        try:
            cursor.execute(
                "SELECT d.event_id, e.tenant_id, e.migration_id, e.event_key, e.event_type, "
                "e.aggregate_version, e.payload, e.occurred_at "
                "FROM outbox_delivery d JOIN outbox_events e ON e.id=d.event_id "
                "WHERE ((d.state IN ('pending','failed') AND d.available_at <= now()) "
                "OR (d.state='leased' AND d.lease_until < now())) "
                "ORDER BY d.available_at, e.occurred_at LIMIT %s FOR UPDATE OF d SKIP LOCKED",
                (limit,),
            )
            rows = cursor.fetchall()
            result = []
            for row in rows:
                cursor.execute(
                    "UPDATE outbox_delivery SET state='leased', worker_id=%s, "
                    "lease_until=now()+make_interval(secs => %s), attempt_count=attempt_count+1, "
                    "updated_at=now() WHERE event_id=%s",
                    (worker_id, lease_seconds, row[0]),
                )
                result.append({
                    "event_id": str(row[0]), "tenant_id": str(row[1]), "migration_id": str(row[2]),
                    "event_key": row[3], "event_type": row[4], "aggregate_version": int(row[5]),
                    "payload": _json_load(row[6]), "occurred_at": row[7].isoformat(),
                })
            self._close(connection, cursor)
            return result
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def mark_outbox_published(self, event_id: str, worker_id: str) -> None:
        connection, cursor = self._open()
        try:
            cursor.execute(
                "UPDATE outbox_delivery SET state='published', published_at=now(), worker_id=NULL, "
                "lease_until=NULL, last_error=NULL, updated_at=now() "
                "WHERE event_id=%s AND state='leased' AND worker_id=%s AND lease_until >= now()",
                (event_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise LeaseLost()
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise

    def fail_outbox_delivery(self, event_id: str, worker_id: str, error: str) -> None:
        connection, cursor = self._open()
        try:
            cursor.execute(
                "UPDATE outbox_delivery SET state='failed', available_at=now()+make_interval(secs => "
                "LEAST(3600, GREATEST(1, power(2, LEAST(attempt_count, 12))::integer))), "
                "worker_id=NULL, lease_until=NULL, last_error=%s, updated_at=now() "
                "WHERE event_id=%s AND state='leased' AND worker_id=%s AND lease_until >= now()",
                (error[:1000], event_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise LeaseLost()
            self._close(connection, cursor)
        except BaseException as exc:
            self._close(connection, cursor, exc)
            raise
