"""Offline preactivation review and challenge gate. Never authorizes fund movement."""
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re

HEX = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
KINDS = {"WRONG_ROOT", "OMITTED_HOLDER", "UNFINALIZED_BLOCK", "INVALID_STORAGE_PROOF",
         "BAD_BENEFICIARY", "SOURCE_FORK", "SUPPLY_MISMATCH", "OTHER"}

class Rejected(ValueError):
    pass

def check(ok, reason):
    if not ok:
        raise Rejected(reason)

def hash_record(record):
    return sha256(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def name(value):
    check(isinstance(value, str) and NAME.fullmatch(value) is not None, "INVALID_IDENTIFIER")
    return value

def commitment(value):
    check(isinstance(value, str) and HEX.fullmatch(value) is not None, "INVALID_HASH")
    return value

@dataclass(frozen=True)
class Challenge:
    id: str
    kind: str
    filed_by: str
    evidence_sha256: str
    opened_at: int
    state: str = "OPEN"
    resolution_sha256: str | None = None
    resolved_by: str | None = None

@dataclass
class Review:
    migration_id: str
    manifest_sha256: str
    opened_at: int
    deadline: int
    proposer: str
    reviewers: frozenset[str]
    guardians: frozenset[str]
    state: str = "REVIEW"
    challenges: dict[str, Challenge] = field(default_factory=dict)
    approvals: set[str] = field(default_factory=set)
    hold: bool = False
    events: list[dict] = field(default_factory=list)
    latest_event_sha256: str = "0" * 64
    revision: int = 0

    @classmethod
    def open(cls, migration_id, manifest_sha256, opened_at, deadline, proposer, reviewers, guardians):
        name(migration_id); commitment(manifest_sha256); name(proposer)
        check(type(opened_at) is int and opened_at >= 0 and type(deadline) is int and deadline > opened_at, "BAD_REVIEW_WINDOW")
        check(isinstance(reviewers, (set, frozenset)) and len(reviewers) >= 2, "TWO_REVIEWERS_REQUIRED")
        check(isinstance(guardians, (set, frozenset)) and len(guardians) >= 1, "GUARDIAN_REQUIRED")
        for actor in reviewers | guardians:
            name(actor)
        check(proposer not in reviewers and proposer not in guardians, "CONFLICT_OF_INTEREST")
        check(not (reviewers & guardians), "REVIEWER_GUARDIAN_CONFLICT")
        instance = cls(migration_id, manifest_sha256, opened_at, deadline, proposer, frozenset(reviewers), frozenset(guardians))
        instance._record("OPEN", proposer, opened_at, {"manifest_sha256": manifest_sha256, "deadline": deadline})
        return instance

    def _record(self, action, actor, at, details):
        check(type(at) is int and at >= self.opened_at, "INVALID_TIMESTAMP")
        if self.events:
            check(at >= self.events[-1]["at"], "NONMONOTONIC_TIMESTAMP")
        item = {"seq": len(self.events), "prev_sha256": self.latest_event_sha256, "action": action,
                "actor": actor, "at": at, "details": details, "migration_id": self.migration_id, "revision": self.revision}
        item["sha256"] = hash_record(item)
        self.events.append(item)
        self.latest_event_sha256 = item["sha256"]

    def _active(self):
        check(self.state == "REVIEW", "REVIEW_NOT_ACTIVE")

    def challenge(self, challenge_id, kind, actor, evidence_sha256, at):
        self._active(); name(challenge_id); name(actor); commitment(evidence_sha256)
        check(kind in KINDS, "UNKNOWN_CHALLENGE_KIND")
        check(challenge_id not in self.challenges, "DUPLICATE_CHALLENGE")
        check(type(at) is int and self.opened_at <= at <= self.deadline, "CHALLENGE_WINDOW_CLOSED")
        self._record("CHALLENGE", actor, at, {"id": challenge_id, "kind": kind, "evidence_sha256": evidence_sha256})
        self.challenges[challenge_id] = Challenge(challenge_id, kind, actor, evidence_sha256, at)
        self.approvals.clear()

    def resolve(self, challenge_id, actor, decision, resolution_sha256, at):
        self._active(); name(actor); commitment(resolution_sha256)
        check(actor in self.reviewers, "REVIEWER_REQUIRED")
        check(decision in ("UPHELD", "REJECTED"), "BAD_DECISION")
        check(challenge_id in self.challenges, "UNKNOWN_CHALLENGE")
        previous = self.challenges[challenge_id]
        check(previous.state == "OPEN", "CHALLENGE_ALREADY_RESOLVED")
        check(actor != previous.filed_by, "SELF_ADJUDICATION_FORBIDDEN")
        self._record("RESOLVE", actor, at, {"id": challenge_id, "decision": decision, "resolution_sha256": resolution_sha256})
        self.challenges[challenge_id] = Challenge(previous.id, previous.kind, previous.filed_by,
            previous.evidence_sha256, previous.opened_at, decision, resolution_sha256, actor)
        self.approvals.clear()
        if decision == "UPHELD":
            self.state = "INVALIDATED"

    def set_hold(self, actor, enabled, at):
        self._active(); name(actor)
        check(actor in self.guardians, "GUARDIAN_REQUIRED")
        check(type(enabled) is bool, "INVALID_HOLD_FLAG")
        self._record("HOLD" if enabled else "UNHOLD", actor, at, {})
        self.hold = enabled
        self.approvals.clear()

    def approve(self, actor, at):
        self._active(); name(actor)
        check(actor in self.reviewers, "REVIEWER_REQUIRED")
        check(not self.hold and not any(c.state == "OPEN" for c in self.challenges.values()), "UNRESOLVED_OBJECTION")
        self._record("APPROVE", actor, at, {"manifest_sha256": self.manifest_sha256})
        self.approvals.add(actor)

    def cancel(self, actor, at):
        self._active(); name(actor)
        check(actor == self.proposer or actor in self.guardians, "CANCEL_AUTHORIZATION_REQUIRED")
        self._record("CANCEL", actor, at, {})
        self.state = "CANCELLED"

    def replace(self, actor, new_manifest_sha256, at, new_deadline):
        check(self.state in ("REVIEW", "INVALIDATED", "CANCELLED"), "REPLACEMENT_FORBIDDEN")
        check(actor == self.proposer, "PROPOSER_REQUIRED")
        commitment(new_manifest_sha256)
        check(new_manifest_sha256 != self.manifest_sha256, "SAME_MANIFEST_FORBIDDEN")
        check(type(new_deadline) is int and type(at) is int and new_deadline > at, "BAD_REVIEW_WINDOW")
        self._record("REPLACE", actor, at, {"successor_manifest_sha256": new_manifest_sha256})
        self.state = "REPLACED"
        successor = Review.open(self.migration_id, new_manifest_sha256, at, new_deadline,
                                self.proposer, set(self.reviewers), set(self.guardians))
        successor.revision = self.revision + 1
        successor.events[0]["revision"] = successor.revision
        opening = {k: v for k, v in successor.events[0].items() if k != "sha256"}
        successor.events[0]["sha256"] = hash_record(opening)
        successor.latest_event_sha256 = successor.events[0]["sha256"]
        return successor

    def decision(self, now):
        check(type(now) is int and now >= 0, "INVALID_TIMESTAMP")
        reasons = []
        if self.state != "REVIEW": reasons.append("NOT_IN_REVIEW")
        if now <= self.deadline: reasons.append("REVIEW_WINDOW_NOT_ELAPSED")
        if self.hold: reasons.append("GUARDIAN_HOLD")
        if any(c.state == "OPEN" for c in self.challenges.values()): reasons.append("OPEN_CHALLENGES")
        if any(c.state == "UPHELD" for c in self.challenges.values()): reasons.append("UPHELD_CHALLENGE")
        if self.approvals != set(self.reviewers): reasons.append("REVIEWER_APPROVALS_MISSING")
        return {"review_policy_pass": not reasons, "reasons": reasons, "can_activate": False,
                "can_claim": False, "source_chain_authenticated": False,
                "manifest_sha256": self.manifest_sha256, "migration_id": self.migration_id,
                "event_head_sha256": self.latest_event_sha256}

    def verify_history(self):
        prev = "0" * 64
        for i, event in enumerate(self.events):
            if event.get("seq") != i or event.get("prev_sha256") != prev:
                return False
            content = {k: v for k, v in event.items() if k != "sha256"}
            if hash_record(content) != event.get("sha256"):
                return False
            prev = event["sha256"]
        return prev == self.latest_event_sha256
