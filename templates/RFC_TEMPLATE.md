---
title: Short task title
# Optional; defaults to agent/<RFC filename stem>:
# branch: agent/RFC-YYYYMMDD-NNN
test_command: "pytest -q"
lint_command: ""
build_command: ""
---

# RFC-YYYYMMDD-NNN: Short Task Title

## Title

Short task title.

## Background

Why this change is needed.

## Goal

The outcome this RFC must produce.

## Non-Goals

Explicitly excluded work.

## Requirements

Exact functional and non-functional requirements.

## Acceptance Criteria

- [ ] Observable criterion one.
- [ ] Observable criterion two.

## Allowed Scope

Files, modules, or dependencies that may change.

## Forbidden Scope

Files, systems, interfaces, or behavior that must not change.

## Constraints

Compatibility, performance, security, style, or dependency constraints.

## Test Requirements

Required cases and expected commands. The worker executes the commands from YAML front matter independently at the fixed project root.

## Rollback

How to revert or disable the change.

## Notes

Additional implementation context. Do not include credentials.
