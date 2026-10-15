"""Deterministic, offline reference model for Metorah's migration lifecycle.

NOT a chain client, trusted verifier, entitlement ledger or production role
authorization. Actor strings and evidence flags are injected TEST FIXTURES.
A future backend must cryptographically authenticate these before use.
"""
from dataclasses import dataclass
from typing import Mapping


class LifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class Entitlement:
    index: int
    beneficiary: str
    amount: int


@dataclass(frozen=True)
class Event:
    request_id: str
    action: str
    actor: str
    before: str
    after: str
    index: int | None = None
    amount: int | None = None


RULES: Mapping[tuple[str, str], tuple[str, frozenset[str]]] = {
    ("DRAFT", "PREPARED"): ("operator", frozenset({"source_eligible", "mapping_window_closed"})),
    ("DRAFT", "CANCELLED"): ("governance", frozenset({"no_settlement"})),
    ("PREPARED", "CANCELLED"): ("governance", frozenset({"no_settlement"})),
    ("PREPARED", "FROZEN"): ("source_governance", frozenset({"freeze_finalized", "source_retired"})),
    ("FROZEN", "VERIFIED"): ("verifier", frozenset({"header_verified", "trie_verified", "holders_complete", "bindings_verified"})),
    ("VERIFIED", "REVIEW"): ("security_reviewer", frozenset({"manifest_domain_bound"})),
    ("REVIEW", "ACTIVATED"): ("governance", frozenset({"review_complete", "backing_verified", "disputes_cleared", "source_retired"})),
    ("DISPUTED", "FROZEN"): ("verifier", frozenset({"dispute_resolved", "freeze_finalized", "source_retired"})),
    ("DISPUTED", "CANCELLED"): ("governance", frozenset({"no_settlement"})),
    ("ACTIVATED", "PAUSED"): ("guardian", frozenset()),
    ("CLAIMING", "PAUSED"): ("guardian", frozenset()),
    ("PAUSED", "ACTIVATED"): ("guardian", frozenset({"incident_resolved", "backing_verified"})),
    ("PAUSED", "CLAIMING"): ("guardian", frozenset({"incident_resolved", "backing_verified"})),
    ("CLAIMING", "COMPLETED"): ("governance", frozenset({"claim_window_ended", "liabilities_reconciled"})),
}
for initial in ("PREPARED", "FROZEN", "VERIFIED", "REVIEW"):
    RULES[(initial, "DISPUTED")] = ("guardian", frozenset({"challenge_recorded"}))


class Migration:
    def __init__(self, entitlements: tuple[Entitlement, ...], source_total: int, funded_total: int):
        if type(source_total) is not int or type(funded_total) is not int or source_total < 0 or funded_total < 0:
            raise LifecycleError("INVALID_TOTAL")
        if not isinstance(entitlements, tuple) or any(
            not isinstance(x, Entitlement)
            or type(x.index) is not int or x.index < 0
            or not isinstance(x.beneficiary, str) or not x.beneficiary
            or type(x.amount) is not int or x.amount <= 0
            for x in entitlements
        ):
            raise LifecycleError("INVALID_ENTITLEMENT")
        self._allocation = {x.index: x for x in entitlements}
        if len(self._allocation) != len(entitlements):
            raise LifecycleError("DUPLICATE_INDEX")
        if sum(x.amount for x in entitlements) != source_total:
            raise LifecycleError("SOURCE_ALLOCATION_MISMATCH")
        self.source_total = source_total
        self.funded_total = funded_total
        self.state = "DRAFT"
        self._claimed: set[int] = set()
        self._requests: dict[str, tuple[tuple, Event]] = {}
        self.events: list[Event] = []

    @property
    def claimed_total(self) -> int:
        return sum(self._allocation[i].amount for i in self._claimed)

    @property
    def outstanding_total(self) -> int:
        return self.source_total - self.claimed_total

    def _previous(self, request_id: str, fingerprint: tuple) -> Event | None:
        if not isinstance(request_id, str) or not request_id:
            raise LifecycleError("INVALID_REQUEST_ID")
        saved = self._requests.get(request_id)
        if saved is None:
            return None
        if saved[0] != fingerprint:
            raise LifecycleError("IDEMPOTENCY_KEY_REUSE")
        return saved[1]

    def _record(self, request_id: str, fingerprint: tuple, event: Event) -> Event:
        self._requests[request_id] = (fingerprint, event)
        self.events.append(event)
        return event

    def transition(self, target: str, actor: str, gates: frozenset[str], request_id: str) -> Event:
        if not isinstance(gates, frozenset) or any(not isinstance(x, str) for x in gates):
            raise LifecycleError("INVALID_GATES")
        fingerprint = ("transition", target, actor, tuple(sorted(gates)))
        old = self._previous(request_id, fingerprint)
        if old:
            return old
        rule = RULES.get((self.state, target))
        if rule is None:
            raise LifecycleError("FORBIDDEN_TRANSITION")
        required_role, required_gates = rule
        if actor != required_role:
            raise LifecycleError("UNAUTHORIZED_ROLE_FIXTURE")
        if not required_gates.issubset(gates):
            raise LifecycleError("MISSING_EVIDENCE_FIXTURE")
        if target == "ACTIVATED" and self.funded_total < self.source_total:
            raise LifecycleError("BACKING_SHORTFALL")
        if target == "CANCELLED" and self._claimed:
            raise LifecycleError("CANNOT_CANCEL_SETTLED")
        if self.state == "PAUSED" and target != ("CLAIMING" if self._claimed else "ACTIVATED"):
            raise LifecycleError("INVALID_RESUME_STATE")
        prev = self.state
        self.state = target
        return self._record(request_id, fingerprint, Event(request_id, "transition", actor, prev, target))

    def claim(self, index: int, beneficiary: str, amount: int, request_id: str) -> Event:
        fingerprint = ("claim", index, beneficiary, amount)
        old = self._previous(request_id, fingerprint)
        if old:
            return old
        if self.state not in ("ACTIVATED", "CLAIMING"):
            raise LifecycleError("CLAIM_NOT_ACTIVE")
        ent = self._allocation.get(index) if type(index) is int else None
        if ent is None or ent.beneficiary != beneficiary or ent.amount != amount or type(amount) is not int:
            raise LifecycleError("INVALID_ENTITLEMENT_PROOF_FIXTURE")
        if index in self._claimed:
            raise LifecycleError("ALREADY_CLAIMED")
        if self.claimed_total + ent.amount > min(self.source_total, self.funded_total):
            raise LifecycleError("SETTLEMENT_EXCEEDS_ALLOCATION_OR_BACKING")
        prev = self.state
        self._claimed.add(index)
        self.state = "CLAIMING"
        return self._record(request_id, fingerprint, Event(request_id, "claim", beneficiary, prev, "CLAIMING", index, amount))

    def assert_invariants(self) -> None:
        assert sum(x.amount for x in self._allocation.values()) == self.source_total
        assert self._claimed.issubset(self._allocation.keys())
        assert 0 <= self.claimed_total <= self.source_total
        assert self.claimed_total <= self.funded_total
        assert self.claimed_total + self.outstanding_total == self.source_total
        if self._claimed:
            assert self.state in ("CLAIMING", "PAUSED", "COMPLETED")
