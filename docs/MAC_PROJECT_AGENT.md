# Mac Project Agent Operating Guide

This document is the operating contract for the Claude Code session on the Mac that discusses product work with the user. The Mac Project Agent does not SSH into the container to edit project code. It converts an agreed requirement into the one canonical RFC format, submits it, observes delivery, and reports the result. Only the user or an explicitly authorized upper-level process decides whether to merge the Pull Request.

## Responsibility And Flow

```text
discuss requirement with user
-> inspect and understand the project
-> clarify Goal, Non-Goals, boundaries, and Acceptance Criteria
-> create one RFC from templates/RFC_TEMPLATE.md
-> validate the RFC
-> submit-rfc.sh
-> wait and query rfc-status.sh
-> inspect container reports and the GitHub PR
-> report evidence to the user
-> user decides whether to merge
```

Never put `project`, `repository`, `working_directory`, `base_branch`, or `branch` in an RFC. The container is permanently bound to one GitHub repository. The Worker derives the exact branch `agent/<RFC-ID>`. Never include credentials in an RFC.

## One-Time Mac Client Configuration

From a checkout of this mother template:

```bash
cp tools/client.env.example tools/client.env
chmod 600 tools/client.env
```

Configure the project container's SSH host/port/user and `GITHUB_REPOSITORY=owner/repository`. Prefer a Mac SSH identity or SSH config; do not commit `tools/client.env`. The container's repository Deploy Key remains in the container and is not used for Mac SSH access.

## Create And Submit An RFC

Copy only `templates/RFC_TEMPLATE.md`, give it a new globally unique ID, and complete every section. Requirements and Acceptance Criteria should describe observable WHAT/WHY/BOUNDARY. Do not prescribe HOW unless it is an actual constraint. Ensure at least one front-matter test, lint, or build command is non-empty.

```bash
tools/submit-rfc.sh /path/to/RFC-20260924-003.md
```

The tool uploads to a hidden temporary filename, asks the container to validate it, then atomically renames it into `todo/inbox`. This prevents the Worker from reading a partial upload.

## Observe And Create The PR

```bash
tools/rfc-status.sh RFC-20260924-003
tools/rfc-wait.sh RFC-20260924-003 3600
tools/create-pr.sh RFC-20260924-003
```

`rfc-status.sh` is a point-in-time query. `rfc-wait.sh` keeps one SSH request open until the RFC reaches `done`, `failed`, or `review_infra_failed`, or until its bounded timeout expires; use it instead of shell loops with repeated sleeps. Every status transition is also retained in `reports/<RFC-ID>/events.jsonl`. Status reports include branch, commit, tests, review, push, PR, and compare URL. `create-pr.sh` requires the Mac's `gh` authentication. It reads the Worker-generated PR description, creates or finds the open PR, and records its URL in `status.json`. It never merges.

Before reporting completion, inspect the PR diff and these container artifacts:

```text
reports/<RFC-ID>/status.json
reports/<RFC-ID>/events.jsonl
reports/<RFC-ID>/coder-report.md
reports/<RFC-ID>/review-report.md
reports/<RFC-ID>/tests.log
reports/<RFC-ID>/diff.patch
reports/<RFC-ID>/pr-description.md
```

If the RFC failed, report the exact failure and evidence. Do not silently reuse a completed RFC ID or broaden the old RFC; create a new RFC when the requested scope changes.
