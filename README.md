# Single-Repository Unattended Coding Worker

This mother template installs one unattended Coding Worker for exactly one GitHub repository:

```text
one OpenBayes container = one GitHub repository = one project = one Worker
```

The persistent source and runtime root is `/openbayes/home/coding-worker`; `/opt/coding-worker` is a compatibility symlink. The complete delivery lifecycle is:

```text
RFC -> fetch origin/main -> agent/<RFC-ID> + isolated worktree
    -> fresh Coder -> Worker-run tests -> fresh independent Reviewer
    -> REQUEST_CHANGES: fresh Coder, bounded review loop
    -> PASS: commit -> non-force push task branch -> PR from the Mac
    -> human or upper-level project Agent decides whether to merge
```

The Worker never merges the base branch, force-pushes, deploys, or accepts a repository/path/branch from an RFC.

See [INSTALL.md](INSTALL.md) for clean-container installation and recovery. Mac requirement Agents must follow [docs/MAC_PROJECT_AGENT.md](docs/MAC_PROJECT_AGENT.md).

## First Installation

```bash
git clone https://github.com/lzzzyy123/codinghuanjing.git /openbayes/home/coding-worker
cd /openbayes/home/coding-worker
cp config/worker.env.example config/worker.env
chmod 600 config/worker.env
# Set the scoped LiteLLM URL/key; leave PROJECT_ROOT empty.
./install.sh
./bin/coding-workerctl deploy-key-init
```

Add the printed public key to the target repository at GitHub **Settings -> Deploy keys**, with **Allow write access** enabled. Then bind once:

```bash
./bin/coding-workerctl bind git@github.com:OWNER/REPOSITORY.git main
```

Binding refuses non-GitHub SSH URLs, an existing different project, or an invalid base branch. It clones into `/openbayes/home/project`, stores the real `origin` in Git config, updates `PROJECT_ROOT`, restarts the service, and runs the full doctor. It never deletes, resets, or overwrites an existing project.

## Repository Binding

Host-local binding lives in ignored `config/worker.env`:

```text
PROJECT_ROOT=/openbayes/home/project
BASE_BRANCH=main
GIT_REMOTE=origin
```

The remote URL from `git remote get-url origin` is authoritative. `PROJECT_ROOT=` is a supported unbound state: the daemon stays up but does not claim inbox RFCs.

```bash
/opt/coding-worker/bin/coding-workerctl project
```

Example output:

```text
Project root: /openbayes/home/project
Base branch: main
Remote: origin
Repository: git@github.com:OWNER/REPOSITORY.git
Current branch: main
Working tree: clean
Status: bound
```

## Authentication And Privilege Separation

The container uses one repository-scoped writable SSH Deploy Key, not a personal SSH key or broad PAT. The private key is ignored by Git, stored at `secrets/github_deploy_key`, owned by `codingworker`, and mode `0600`.

- The root daemon only orchestrates fixed Worker code and filesystem state.
- `codingworker:codingproject` performs Git operations and can read the Deploy Key.
- `codingagent:codingproject` runs Coder, Reviewer, and project commands. It cannot read the Deploy Key or modify project Git metadata/hooks.
- Git hooks are disabled for the bound clone. Agent children receive a small environment allowlist and no GitHub credential.
- The scoped LiteLLM credential necessarily reaches Claude Code as its Anthropic API credential.

This is process-level least privilege for a dedicated, single-tenant project container, not a hostile-code VM sandbox.

## Branch And Delivery Invariants

For every accepted RFC:

```text
RFC-20260924-003
<-> agent/RFC-20260924-003
<-> reports/RFC-20260924-003/
<-> one commit and GitHub PR
```

Before creating a new branch, the Worker must successfully fetch `origin/$BASE_BRANCH`; it branches from that remote-tracking commit, never a stale local main. The RFC cannot override branch/base/repository paths. After independent tests and review both pass, the Worker creates a commit:

```text
RFC-20260924-003: short title

RFC: RFC-20260924-003
Tests: PASS
Review: PASS
```

It then performs a normal, non-force push of only `agent/<RFC-ID>`. A failed fetch or push fails the task with evidence. The container has no GitHub API token, so it generates `pr-description.md` and a compare URL; the authenticated Mac creates the PR. This keeps API permission out of the project container.

## RFC Standard

`templates/RFC_TEMPLATE.md` is the only format. YAML front matter contains only a title and Worker-run commands:

```yaml
---
title: Implement the requested behavior
test_command: "pytest -q tests/relevant_module"
lint_command: "ruff check ."
build_command: ""
---
```

At least one test/lint/build command is required. These are module-level acceptance gates run before each review. A root-controlled `FULL_REGRESSION_COMMAND`, when configured, runs only after Reviewer PASS and before commit/push; RFC authors cannot override it. If the RFC test command is byte-identical to the full command, its passing result is reused. The following fields are rejected: `project`, `repository`, `working_directory`, `base_branch`, and `branch`. The body describes WHAT, WHY, boundaries, acceptance criteria, constraints, tests, and rollback. RFC commands are trusted operator input and run as `codingagent` in the isolated worktree.

Migration verification may additionally receive `HERMES_PYTHON_BASELINE_ROOT` and `HERMES_PYTHON_BASELINE_COMMIT` from root-owned Worker configuration. The source snapshot must be read-only to `codingagent`, must match the project's committed baseline identity, and is available only to Coder, Reviewer, and test processes; it is never copied into or used by the production Bun runtime.

## Daily Mac Flow

Configure ignored `tools/client.env` from its example, then:

```bash
tools/submit-rfc.sh RFC-20260924-003.md
tools/rfc-status.sh RFC-20260924-003
tools/rfc-wait.sh RFC-20260924-003 3600
tools/create-pr.sh RFC-20260924-003
```

Submission uses a partial `.upload-*` name, validates remotely, and atomically renames into `todo/inbox`. PR creation uses the Mac's authenticated `gh`, uploads no token to the container, records the PR URL in `status.json`, and never merges.

## Audit Trail

Each `reports/<RFC-ID>/` contains:

```text
status.json             machine state, branch, base commit, commit, push, PR
events.jsonl            append-only lifecycle transition stream for efficient waiting/audit
coder-report.md         implementation, files, decisions, alternatives, deviations, risks
review-report.md        human-readable acceptance/security/architecture/test review
coder-attempt-*.md      per-cycle Coder report history
review-attempt-*.md     per-cycle Reviewer report history
review-latest.json      machine-readable PASS or REQUEST_CHANGES
tests.log               Worker commands, exit codes, stdout, stderr, timeouts
diff.patch              accepted Git diff
pr-description.md       durable PR index content
worker.log              lifecycle events and failures
raw/                    independent Claude CLI envelopes and stderr
```

The container retains full execution evidence. The GitHub PR is the durable repository-visible index containing RFC ID, goal, acceptance criteria, summary, decisions, tests, verdict, and commit. Reports are not silently committed into business repositories.

For a Project Lead defect found before merge, `tools/amend-rfc.sh RFC-ID REPORT.md` queues a bounded correction cycle on the same RFC branch and preserves the existing PR URL and all prior evidence. Merged RFCs cannot be amended, and amendments cannot change scope.

The current deployment remains single-Worker. [docs/MULTI_WORKER_EXPANSION.md](docs/MULTI_WORKER_EXPANSION.md) defines the ownership, dependency, isolation, and integration gates required before an operator-approved 2-4 Worker rollout.

The additive DAG scheduler implementation and its shadow-first cutover contract are documented in [docs/DAG_SCHEDULER.md](docs/DAG_SCHEDULER.md). Shadow mode does not claim the production filesystem queue, start Agents, alter `MAX_CONCURRENT_TASKS=1`, or replace the current runit service.

## Operations

```bash
coding-workerctl project
coding-workerctl status
coding-workerctl logs
coding-workerctl queue
coding-workerctl rfc-status RFC-YYYYMMDD-NNN
coding-workerctl doctor
coding-workerctl restart
coding-workerctl stop
coding-workerctl start
coding-workerctl bootstrap
```

Deploy Key and binding commands:

```bash
coding-workerctl deploy-key-init
coding-workerctl deploy-key-show
coding-workerctl bind git@github.com:OWNER/REPOSITORY.git main
coding-workerctl record-pr RFC-ID https://github.com/OWNER/REPOSITORY/pull/123
```

`doctor` verifies runtime permissions, service health, LiteLLM and exact model availability, a real Claude Code call, binding, remote/base, fetch/auth, a non-destructive `git push --dry-run`, and Deploy Key isolation. It does not modify main or create a remote branch.

## Crash And Failure Behavior

An exclusive flock permits one daemon. Atomic rename claims `inbox -> working`; startup recovers `working` before new work. Agent/test/Git timeouts and coder/reviewer/error cycles are bounded. Terminal failures move the RFC to `todo/failed` and retain worktree/reports. Successful RFCs move to `todo/done`; successful worktrees are removed by default after the pushed commit is verified.

Never reuse a completed RFC ID. After correcting an infrastructure failure, a failed RFC may be deliberately requeued; its existing exact task branch/worktree and report history make recovery idempotent.

## Persistent Layout

```text
/openbayes/home/
├── coding-worker/                 mother source + host-local runtime
│   ├── bin/
│   ├── config/worker.env          ignored, root:root 0600
│   ├── docs/
│   ├── secrets/                   ignored, Deploy Key, 0700
│   ├── service/
│   ├── templates/
│   ├── tools/
│   ├── worker/
│   ├── todo/{inbox,working,done,failed}/
│   ├── reports/
│   ├── worktrees/
│   └── runtime/
├── project/                       the one bound GitHub clone
├── coding-worker-home/
├── coding-agent-home/
└── .local/                        pinned Node.js + Claude Code
```

After an OpenBayes runtime rebuild, restore users, permissions, `/opt`, `/etc/service`, `/usr/local/bin/coding-workerctl`, and `/init.sh` links with:

```bash
/openbayes/home/coding-worker/bootstrap-runtime.sh
```

## Never Commit Or Copy

Do not publish `config/worker.env`, `secrets/`, Deploy Keys, API keys, `tools/client.env`, `.venv`, project code, queues, reports, worktrees, runtime locks, service state, logs, or E2E fixtures. Copy or push only tracked mother-template files. A final secret scan is required before release.
