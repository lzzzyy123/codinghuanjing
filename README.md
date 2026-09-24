# Single-Project Unattended Coding Worker

This repository installs one unattended Coding Worker for exactly one Git project:

```text
one OpenBayes container = one PROJECT_ROOT = one Coding Worker
```

The persistent installation lives at `/openbayes/home/coding-worker`. `/opt/coding-worker` is a compatibility symlink. The Worker implements:

```text
RFC -> isolated Coder -> independent tests -> isolated Reviewer
    -> PASS: commit task branch, never merge
    -> REQUEST_CHANGES: new Coder process, then review again
```

See [INSTALL.md](INSTALL.md) for a clean-container installation and recovery procedure.

## Project Binding

The only project is fixed in `config/worker.env`:

```text
PROJECT_ROOT=/openbayes/home/project
BASE_BRANCH=main
```

`PROJECT_ROOT=` is a supported unbound state. The daemon stays healthy but leaves `todo/inbox` untouched. After cloning a project, set `PROJECT_ROOT`, ensure `codingworker` owns or can write it, and restart:

```bash
/opt/coding-worker/bootstrap-runtime.sh
/opt/coding-worker/bin/coding-workerctl restart
/opt/coding-worker/bin/coding-workerctl doctor
```

Do not change `PROJECT_ROOT` while an RFC is in `todo/working`.

## Architecture

- PID 1 `runit` supervises a lightweight Python polling daemon.
- An exclusive `flock` permits only one Worker process.
- An atomic rename claims `inbox -> working`; files in `working` are recovered after restart.
- Every RFC gets a dedicated worktree below `worktrees/<RFC-ID>`.
- The default branch is `agent/<RFC-ID>`; an RFC may explicitly override `branch` with another `agent/...` name.
- Every Coder and Reviewer invocation is a fresh Claude Code process with session persistence disabled.
- The Worker, not the Agent, runs the RFC's lint/build/test commands and records exact output and exit codes.
- Reviewer output is strict JSON: `PASS` or `REQUEST_CHANGES`.
- Agent errors, tests, Git operations, coder cycles, and review cycles are bounded.
- `PASS` creates a commit on the task branch. The Worker never merges, pushes, deploys, or changes the configured base branch.
- First version concurrency is fixed at one.

## Source And Runtime Layout

```text
/openbayes/home/coding-worker/
├── .gitignore
├── README.md
├── INSTALL.md
├── install.sh
├── bootstrap-runtime.sh
├── bin/coding-workerctl
├── config/
│   ├── worker.env.example       # tracked, no secrets
│   └── worker.env               # ignored, root:root 0600
├── service/
│   ├── run
│   └── log/run
├── templates/RFC_TEMPLATE.md
├── worker/
│   ├── watcher.py
│   └── prompts/{coder,reviewer}.md
├── todo/{inbox,working,done,failed}/   # ignored runtime state
├── reports/                           # ignored runtime state
├── worktrees/                         # ignored runtime state
├── runtime/                           # ignored locks
└── worker/logs/                       # ignored logs
```

The bound project is outside this tree, normally `/openbayes/home/project`. Project code is never part of the Coding Worker repository.

## RFC Format

RFCs no longer contain a project, repository, base branch, or working directory. Those fields are rejected. Start from `templates/RFC_TEMPLATE.md`:

```yaml
---
title: Implement the requested behavior
test_command: "pytest -q"
lint_command: "ruff check ."
build_command: ""
---
```

At least one test/lint/build command is required. Commands execute from the root of the task worktree and are trusted operator input.

Upload to a temporary path and atomically rename into the queue:

```bash
scp -P <port> RFC-20260924-001.md root@<host>:/opt/coding-worker/todo/RFC-20260924-001.md.upload
ssh -p <port> root@<host> \
  'mv /opt/coding-worker/todo/RFC-20260924-001.md.upload /opt/coding-worker/todo/inbox/RFC-20260924-001.md'
```

Do not reuse a completed RFC ID.

## Operations

```bash
/opt/coding-worker/bin/coding-workerctl status
/opt/coding-worker/bin/coding-workerctl doctor
/opt/coding-worker/bin/coding-workerctl project
/opt/coding-worker/bin/coding-workerctl queue
/opt/coding-worker/bin/coding-workerctl logs
/opt/coding-worker/bin/coding-workerctl restart
/opt/coding-worker/bin/coding-workerctl stop
/opt/coding-worker/bin/coding-workerctl start
/opt/coding-worker/bin/coding-workerctl bootstrap
```

The machine-readable result is `reports/<RFC-ID>/status.json`. Each report also contains Coder and Reviewer reports, per-attempt raw envelopes, test logs, worker logs, the accepted diff, and failure history.

## Configuration

`config/worker.env` is sourced by the root-owned runit launcher before privileges are dropped to UID/GID 22022. Required settings are:

```text
PROJECT_ROOT=
BASE_BRANCH=main
LITELLM_BASE_URL=https://your-litellm.example.com
LITELLM_API_KEY=replace-me
MODEL=xiaosuan-8
```

The launcher maps LiteLLM values to Claude Code's Anthropic environment and automatically puts the gateway hostname in `NO_PROXY`, which is required for private OpenBayes gateway addresses.

## Crash Recovery

The RFC remains in `todo/working`, its branch and worktree remain intact, and every retry starts a new Agent context. Run `coding-workerctl restart`; the Worker resumes `working` before claiming another RFC. A commit created just before a crash is detected and reused instead of duplicated.

Failed worktrees are retained for diagnosis. Successful worktrees are removed after commit, while the branch and commit remain in `PROJECT_ROOT`.

## Security Boundary

- Never commit or copy `config/worker.env`.
- The API key is intentionally available to the Agent process environment; use a scoped, rate-limited LiteLLM key.
- RFC commands and project code execute as `codingworker`; this is a trusted single-tenant worker, not a hostile-code sandbox.
- The `.gitignore` excludes secrets, reports, queues, worktrees, locks, logs, virtual environments, and test fixtures.
- Copy or publish only files tracked by this repository. Never package the directory with `tar` without applying the ignore boundary.

## Known Behavior

Claude Code may print `unrecognized_model` for the custom `xiaosuan-8` alias. LiteLLM requests still use that exact model, and the CLI result is valid when its JSON envelope reports `subtype: success` and `is_error: false`.
