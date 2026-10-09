"""Quality-gated task lifecycle built on fenced queue operations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .leases import JobLease, QueueStore
from .git_broker import Candidate
from .models import TaskState
from .state_store import StateConflict, StateStore
from .testing import TestEvidenceStore, TestIdentity


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class ReviewResult:
    verdict: str | None
    infrastructure_status: str
    evidence_digest: str
    required_changes: tuple[str, ...] = ()
    schema_valid: bool = True


class Pipeline:
    def __init__(
        self, state: StateStore, queue: QueueStore, tests: TestEvidenceStore
    ) -> None:
        self.state = state
        self.queue = queue
        self.tests = tests

    def complete_coding(
        self,
        lease: JobLease,
        candidate: Candidate,
        level1_identity: TestIdentity,
        evidence_digest: str,
        *,
        now: float | None = None,
    ) -> int:
        candidate_digest = candidate.candidate_digest
        self._validate_candidate(lease, candidate_digest)
        if (
            candidate.rfc_id != lease.rfc_id
            or candidate.revision_digest != lease.revision_digest
            or candidate.base_commit != lease.base_commit
        ):
            raise StateConflict("coding completion candidate does not match its lease")
        if level1_identity.level != 1 or level1_identity.candidate_digest != candidate_digest:
            raise StateConflict("coding completion requires matching Level 1 evidence")
        return self.queue.finish_and_transition(
            lease,
            "passed",
            {
                "candidate_digest": candidate_digest,
                "branch": candidate.branch,
                "commit_sha": candidate.commit_sha,
                "tree_sha": candidate.tree_sha,
                "diff_digest": candidate.diff_digest,
                "level1_evidence": evidence_digest,
            },
            TaskState.CODING,
            TaskState.TESTING,
            reason="Coder candidate and Level 1 gates passed",
            next_kind="test_l2",
            next_idempotency_key=f"test-l2:{lease.rfc_id}:{candidate_digest}",
            next_candidate_digest=candidate_digest,
            test_record=(level1_identity, "PASS", evidence_digest),
            now=now,
        )

    def complete_level2(
        self,
        lease: JobLease,
        identity: TestIdentity,
        status: str,
        evidence_digest: str,
        *,
        now: float | None = None,
    ) -> int:
        if lease.kind != "test_l2" or identity.level != 2:
            raise StateConflict("Level 2 result submitted for the wrong job")
        self._validate_candidate(lease, identity.candidate_digest)
        if status == "PASS":
            target = TaskState.REVIEWING
            next_kind = "review"
            next_key = f"review:{lease.rfc_id}:{identity.candidate_digest}"
            reason = "module tests and Python differential gate passed"
            outcome = "passed"
        elif status == "FAIL":
            target = TaskState.AMENDMENT
            next_kind = "coding"
            next_key = f"amend-test:{lease.rfc_id}:{identity.candidate_digest}:{lease.attempt}"
            reason = "module or Python differential gate failed"
            outcome = "failed"
        else:
            raise StateConflict("test infrastructure failures require bounded job retry")
        return self.queue.finish_and_transition(
            lease,
            outcome,
            {"candidate_digest": identity.candidate_digest, "evidence": evidence_digest},
            TaskState.TESTING,
            target,
            reason=reason,
            next_kind=next_kind,
            next_idempotency_key=next_key,
            next_candidate_digest=(identity.candidate_digest if next_kind == "review" else None),
            test_record=(identity, status, evidence_digest),
            now=now,
        )

    def complete_review(
        self,
        lease: JobLease,
        result: ReviewResult,
        *,
        now: float | None = None,
    ) -> int | None:
        if lease.kind != "review" or not lease.candidate_digest:
            raise StateConflict("review result submitted for the wrong job")
        if not DIGEST_RE.fullmatch(result.evidence_digest):
            raise ValueError("review evidence must be a sha256 digest")
        if result.infrastructure_status == "FAILED":
            if result.verdict is not None:
                raise StateConflict("review infrastructure failure cannot carry a verdict")
            return self.queue.retry_review_infrastructure(
                lease,
                {
                    "candidate_digest": lease.candidate_digest,
                    "verdict": None,
                    "infrastructure_status": result.infrastructure_status,
                    "evidence": result.evidence_digest,
                },
                {
                    "candidate_digest": lease.candidate_digest,
                    "infrastructure_status": result.infrastructure_status,
                    "evidence_digest": result.evidence_digest,
                },
                now=now,
            )
        elif result.infrastructure_status == "PASS" and result.verdict == "PASS":
            if not result.schema_valid:
                raise StateConflict("schema-invalid review cannot PASS")
            if result.required_changes:
                raise StateConflict("PASS review cannot contain required changes")
            target = TaskState.LEAD_REVIEW
            next_kind = None
            next_key = None
            outcome = "passed"
            reason = "independent Reviewer passed the candidate"
        elif result.infrastructure_status == "PASS" and result.verdict == "REQUEST_CHANGES":
            if not result.schema_valid:
                raise StateConflict("schema-invalid review cannot request changes")
            if not result.required_changes:
                raise StateConflict("REQUEST_CHANGES requires actionable findings")
            target = TaskState.AMENDMENT
            next_kind = "coding"
            next_key = f"amend-review:{lease.rfc_id}:{lease.candidate_digest}:{lease.attempt}"
            outcome = "failed"
            reason = "independent Reviewer requested same-RFC amendment"
        else:
            raise StateConflict("invalid Reviewer result")
        return self.queue.finish_and_transition(
            lease,
            outcome,
            {
                "candidate_digest": lease.candidate_digest,
                "verdict": result.verdict,
                "infrastructure_status": result.infrastructure_status,
                "evidence": result.evidence_digest,
                "required_changes": list(result.required_changes),
            },
            TaskState.REVIEWING,
            target,
            reason=reason,
            next_kind=next_kind,
            next_idempotency_key=next_key,
            next_candidate_digest=(lease.candidate_digest if next_kind == "review" else None),
            review_record={
                "candidate_digest": lease.candidate_digest,
                "verdict": result.verdict,
                "infrastructure_status": result.infrastructure_status,
                "schema_valid": result.schema_valid,
                "evidence_digest": result.evidence_digest,
            },
            now=now,
        )

    def approve_for_integration(
        self,
        rfc_id: str,
        candidate_digest: str,
        actor: str,
        *,
        approval_channel: str,
        approval_evidence_digest: str,
        available_at: float | None = None,
    ) -> int:
        if not DIGEST_RE.fullmatch(candidate_digest):
            raise ValueError("candidate must be a sha256 digest")
        return self.queue.approve_reviewed_candidate(
            rfc_id,
            candidate_digest,
            actor,
            f"integration:{rfc_id}:{candidate_digest}",
            approval_channel=approval_channel,
            approval_evidence_digest=approval_evidence_digest,
            available_at=available_at,
        )

    def complete_integration(
        self,
        lease: JobLease,
        level3_identity: TestIdentity,
        evidence_digest: str,
        *,
        now: float | None = None,
    ) -> None:
        if lease.kind != "integration" or level3_identity.level != 3:
            raise StateConflict("Level 3 result submitted for the wrong integration job")
        self._validate_candidate(lease, level3_identity.candidate_digest)
        self.queue.finish_and_transition(
            lease,
            "passed",
            {
                "candidate_digest": level3_identity.candidate_digest,
                "level3_evidence": evidence_digest,
            },
            TaskState.INTEGRATING,
            TaskState.DONE,
            reason="Level 3 integration and full regression gates passed",
            test_record=(level3_identity, "PASS", evidence_digest),
            now=now,
        )

    @staticmethod
    def _validate_candidate(lease: JobLease, candidate_digest: str) -> None:
        if not DIGEST_RE.fullmatch(candidate_digest):
            raise ValueError("candidate must be a sha256 digest")
        if lease.candidate_digest and lease.candidate_digest != candidate_digest:
            raise StateConflict("candidate digest does not match leased job")
