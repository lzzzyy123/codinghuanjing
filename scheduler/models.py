"""Shared scheduler types and lifecycle rules."""

from __future__ import annotations

from enum import Enum


class TaskState(str, Enum):
    DRAFT = "Draft"
    VALIDATED = "Validated"
    READY = "Ready"
    LEASED = "Leased"
    CODING = "Coding"
    TESTING = "Testing"
    REVIEWING = "Reviewing"
    LEAD_REVIEW = "LeadReview"
    AMENDMENT = "Amendment"
    INTEGRATION_READY = "IntegrationReady"
    INTEGRATING = "Integrating"
    BLOCKED = "Blocked"
    REVIEW_INFRA_FAILED = "ReviewInfraFailed"
    DONE = "Done"


TERMINAL_STATES = {TaskState.DONE}


ALLOWED_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.DRAFT: {TaskState.VALIDATED, TaskState.BLOCKED},
    TaskState.VALIDATED: {TaskState.READY, TaskState.BLOCKED},
    TaskState.READY: {TaskState.LEASED, TaskState.BLOCKED},
    TaskState.LEASED: {TaskState.CODING, TaskState.READY, TaskState.BLOCKED},
    TaskState.CODING: {TaskState.READY, TaskState.TESTING, TaskState.BLOCKED},
    TaskState.TESTING: {TaskState.REVIEWING, TaskState.AMENDMENT, TaskState.BLOCKED},
    TaskState.REVIEWING: {
        TaskState.LEAD_REVIEW,
        TaskState.AMENDMENT,
        TaskState.REVIEW_INFRA_FAILED,
        TaskState.BLOCKED,
    },
    TaskState.REVIEW_INFRA_FAILED: {TaskState.REVIEWING, TaskState.BLOCKED},
    TaskState.LEAD_REVIEW: {
        TaskState.AMENDMENT,
        TaskState.INTEGRATION_READY,
        TaskState.BLOCKED,
    },
    TaskState.AMENDMENT: {TaskState.READY, TaskState.LEASED, TaskState.BLOCKED},
    TaskState.INTEGRATION_READY: {TaskState.INTEGRATING, TaskState.BLOCKED},
    TaskState.INTEGRATING: {TaskState.DONE, TaskState.AMENDMENT, TaskState.BLOCKED},
    TaskState.BLOCKED: {
        TaskState.VALIDATED,
        TaskState.READY,
        TaskState.AMENDMENT,
    },
    TaskState.DONE: set(),
}
