---
title: Short task title
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

Required cases and expected commands. The Worker executes the commands from YAML front matter independently in the RFC's isolated worktree.

## Rollback

How to revert or disable the change.

## Notes

Additional implementation context. Do not include credentials.

Do not specify a project, repository, working directory, base branch, or task branch. The container binding is authoritative, and the Worker always creates `agent/<RFC-ID>`.
