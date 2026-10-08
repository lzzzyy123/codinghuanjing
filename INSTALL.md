# Installation And Recovery Guide

This document rebuilds the Single-Repository Coding Worker on a new Ubuntu/OpenBayes container without any prior chat context. One installation permanently serves one GitHub repository.

## 1. Inspect The New Container

Required environment:

- Ubuntu (currently verified on 20.04.6 LTS)
- root SSH
- PID 1 `runsvdir` and `/etc/service`
- persistent `/openbayes/home`
- outbound HTTPS/SSH to Node.js, npm, LiteLLM, and GitHub

```bash
cat /etc/os-release
ps -p 1 -o pid,comm,args
test -d /etc/service
df -h /openbayes/home
git --version
curl --version
command -v chpst
```

Do not use `/opt` as the source of truth. OpenBayes only guarantees `/openbayes/home` persistence.

## 2. Obtain The Mother Template

```bash
git clone https://github.com/lzzzyy123/codinghuanjing.git \
  /openbayes/home/coding-worker
cd /openbayes/home/coding-worker
```

For an offline transfer, copy only Git-tracked files. Never copy credentials or another container's runtime state.

## 3. Create The Host Configuration

```bash
install -m 600 -o root -g root \
  config/worker.env.example config/worker.env
```

Initially leave the project unbound, and configure a scoped LiteLLM credential:

```text
CODING_WORKER_HOME=/openbayes/home/coding-worker
AGENT_CLI=/openbayes/home/.local/bin/claude
PROJECT_ROOT=
BASE_BRANCH=main
GIT_REMOTE=origin

LITELLM_BASE_URL=https://your-litellm.example.com
LITELLM_API_KEY=your-scoped-key
MODEL=xiaosuan-8

MAX_CONCURRENT_TASKS=1
MAX_REVIEW_CYCLES=3
MAX_CODER_CYCLES=5
MAX_CONSECUTIVE_ERRORS=3
AGENT_TIMEOUT=1800
TEST_TIMEOUT=1200
GIT_TIMEOUT=180
FULL_REGRESSION_COMMAND=
POLL_INTERVAL=5
KEEP_SUCCESS_WORKTREES=false
```

Never put the LiteLLM key in the template repository, RFC, prompt, project, report, command example, or Git history.

## 4. Install The Persistent Runtime

```bash
chmod 755 install.sh bootstrap-runtime.sh
./install.sh
```

The idempotent installer:

1. validates Ubuntu, runit, architecture, Git/curl/xz/OpenSSH;
2. downloads pinned Node.js 22.23.3 below `/openbayes/home/.local`;
3. verifies its official SHA-256 checksum;
4. installs pinned Claude Code 2.1.281 in the same persistent prefix;
5. creates the persistent Python virtual environment;
6. installs pinned PyYAML;
7. preserves any existing `config/worker.env`;
8. runs `bootstrap-runtime.sh`.

It does not delete or overwrite a project, queue, report, task branch, Deploy Key, or real configuration.

## 5. Runtime Users And Permissions

`bootstrap-runtime.sh` creates or validates:

```text
codingworker UID 22022   Git and Deploy Key identity
codingagent  UID 22023   Coder/Reviewer/test identity
codingproject GID 22024  shared read/write access to task worktrees
```

The root daemon reads the root-only environment and performs queue/report orchestration. Every Git command is dropped to `codingworker:codingproject`; every Agent and project test command is dropped to `codingagent:codingproject`. Project `.git` metadata is Agent-read-only, local Git hooks are disabled, and the Deploy private key is not readable by `codingagent`.

The bootstrap also creates persistent state directories and these runtime links:

```text
/opt/coding-worker -> /openbayes/home/coding-worker
/etc/service/coding-worker -> /openbayes/home/coding-worker/service
/usr/local/bin/coding-workerctl -> /openbayes/home/coding-worker/bin/coding-workerctl
/init.sh -> /openbayes/home/coding-worker/bootstrap-runtime.sh
```

It refuses to replace a regular file at those link paths.

## 6. Validate LiteLLM And Claude Code

```bash
./bin/coding-workerctl doctor
```

In the unbound state, project checks are `SKIP`, not a daemon error. Doctor calls `/v1/models`, requires the exact configured `xiaosuan-8` model ID, and executes a real Claude Code smoke request through LiteLLM. It redacts the API key.

Expected installed components:

```bash
/openbayes/home/.local/bin/node --version
/openbayes/home/.local/bin/claude --version
/openbayes/home/coding-worker/.venv/bin/python --version
```

## 7. Generate A Repository Deploy Key

```bash
./bin/coding-workerctl deploy-key-init
```

The command creates:

```text
secrets/github_deploy_key       private, codingworker, 0600
secrets/github_deploy_key.pub   public
secrets/known_hosts             GitHub SSH host keys, 0600
```

Verify the displayed GitHub SSH fingerprints against GitHub's published fingerprints. In the target GitHub repository, open **Settings -> Deploy keys -> Add deploy key**, paste:

```bash
./bin/coding-workerctl deploy-key-show
```

Enable **Allow write access**. This is the only manual GitHub authentication step. Use exactly one Deploy Key per repository/container; do not copy a personal private key or broad PAT into the container.

If the Mac `gh` session has repository administration permission, it may add the key through the GitHub API, but the token remains on the Mac.

## 8. Bind The One GitHub Repository

After the writable Deploy Key is present on GitHub:

```bash
./bin/coding-workerctl bind git@github.com:OWNER/REPOSITORY.git main
```

Binding:

1. accepts only a GitHub SSH repository URL;
2. refuses an existing non-Git/different project;
3. clones to `/openbayes/home/project` without deleting anything;
4. validates `origin` and `origin/main`;
5. stores a fixed `core.sshCommand` for the one Deploy Key;
6. disables project-local hooks and protects `.git` from Agent writes;
7. configures ownership for isolated worktrees;
8. writes `PROJECT_ROOT`, `BASE_BRANCH`, and `GIT_REMOTE` to ignored host config;
9. restores bootstrap links/permissions, restarts runit, and runs doctor.

The same command is idempotent for the same URL. It refuses to rebind a populated container to another repository. Build a new container for another project.

Inspect the authoritative binding:

```bash
./bin/coding-workerctl project
git -C /openbayes/home/project remote get-url origin
git -C /openbayes/home/project status
git -C /openbayes/home/project branch
```

## 9. Full Doctor

```bash
./bin/coding-workerctl doctor
```

The bound-project doctor checks:

- queue/report/runtime permissions;
- runit service;
- LiteLLM `/v1/models` and exact model;
- real Claude Code call;
- project root and Git repository;
- configured origin URL and SSH form;
- base branch and clean main worktree;
- `git fetch` and `git ls-remote` authentication;
- write permission with `git push --dry-run` to a diagnostic branch (no branch is created);
- Deploy Key owner/mode and its unreadability by `codingagent`.

Doctor never commits, pushes main, resets a branch, creates a real diagnostic branch, or changes project content.

## 10. Configure The Mac Project Agent

On the Mac checkout:

```bash
cp tools/client.env.example tools/client.env
chmod 600 tools/client.env
```

Set SSH host, port, user, optional Mac-to-container identity, remote root, and `GITHUB_REPOSITORY=OWNER/REPOSITORY`. This file is ignored. Read `docs/MAC_PROJECT_AGENT.md` before generating requirements.

## 11. Submit The Canonical RFC

Start only from `templates/RFC_TEMPLATE.md`. Use a unique filename such as `RFC-20260924-003.md`. Do not include project/repository/working-directory/base-branch/task-branch fields; the parser rejects them. Configure at least one non-empty test/lint/build command.

```bash
tools/submit-rfc.sh RFC-20260924-003.md
```

The client uploads a `.upload-*` file. The container validates the front matter and unique RFC ID, then atomically renames it into `todo/inbox`. A half-uploaded file is never claimed.

## 12. RFC Runtime Lifecycle

For a new RFC, the Worker must successfully:

1. atomically move `inbox -> working`;
2. `git fetch origin` for the exact configured base branch;
3. create exact branch `agent/<RFC-ID>` from `refs/remotes/origin/main`;
4. create an isolated worktree;
5. start a fresh Coder process and validate its standardized report;
6. execute RFC module commands itself and log exit/stdout/stderr/timeout;
7. start a fresh independent Reviewer and validate structured JSON;
8. return REQUEST_CHANGES to a fresh Coder within bounded cycles, or accept PASS;
9. after review PASS, execute the root-controlled full regression gate (or reuse an identical passing RFC test command);
10. commit only after module tests, review, and full regression PASS;
11. normally push only the exact task branch and verify remote SHA;
12. generate compare URL and PR description;
13. move `working -> done` and optionally remove the successful worktree.

Fetch/push/Agent/test/Git failures are bounded and become `failed` reports. The Worker never merges, deploys, force-pushes, or pushes the base branch.

## 13. Create The Pull Request From The Mac

The container intentionally has no GitHub API token. With Mac `gh` authenticated:

```bash
tools/rfc-status.sh RFC-20260924-003
tools/create-pr.sh RFC-20260924-003
```

The PR tool requires tests/review/push PASS, reads the generated standard description, creates or finds an open PR, then records its URL in the container. It does not merge. The PR is the permanent GitHub index; the container keeps complete execution reports.

## 14. E2E Acceptance Checklist

Use a disposable repository with an initial `main` commit and a repository-scoped writable Deploy Key. Submit an RFC without repository/path/branch fields and verify:

```bash
./bin/coding-workerctl rfc-status RFC-ID
cat reports/RFC-ID/status.json
cat reports/RFC-ID/coder-report.md
cat reports/RFC-ID/review-report.md
cat reports/RFC-ID/tests.log
git -C /openbayes/home/project show-ref agent/RFC-ID
git -C /openbayes/home/project ls-remote --heads origin agent/RFC-ID
```

Acceptance requires automatic discovery, a branch based on the fetched remote base, actual code changes, actual Worker tests, distinct fresh Coder/Reviewer processes, complete reports, PASS, commit, matching GitHub branch SHA, a PR, and unchanged/unmerged main.

## 15. Routine Service Operations

```bash
coding-workerctl status
coding-workerctl logs
coding-workerctl queue
coding-workerctl project
coding-workerctl rfc-status RFC-ID
coding-workerctl restart
coding-workerctl stop
coding-workerctl start
```

Low-level status:

```bash
SVDIR=/etc/service sv status coding-worker
```

## 16. Failure And Crash Recovery

The Worker holds an exclusive flock. Claimed RFCs stay in `todo/working`; startup resumes them before new inbox tasks. A commit/push that completed just before a crash is detected/reused rather than force-overwritten. Failed worktrees and reports remain for diagnosis.

After correcting a transient infrastructure failure, an operator may deliberately requeue its RFC file. Do not reuse an ID whose status is already `done`, and do not delete an existing branch/report to hide history.

## 17. OpenBayes Environment Reconstruction

The durable sources are below `/openbayes/home`:

```text
/openbayes/home/coding-worker
/openbayes/home/.local
/openbayes/home/coding-worker-home
/openbayes/home/coding-agent-home
/openbayes/home/project
```

If `/etc/service`, `/opt`, users, or `/init.sh` disappeared while persistent data survived:

```bash
cd /openbayes/home/coding-worker
./bootstrap-runtime.sh
./bin/coding-workerctl start
./bin/coding-workerctl doctor
```

Run `./install.sh` instead if Node.js, Claude Code, or `.venv` is missing. Bootstrap never redownloads dependencies and never replaces project data.

## 18. Files To Copy And Files Never To Copy

Copy/version only tracked template source: installers, bootstrap, Worker Python, prompts, service definitions, CLI, Mac tools/examples, RFC/PR templates, README, INSTALL, docs, and `.gitignore`.

Never copy, package, or commit:

- `config/worker.env` or any API key;
- `secrets/`, private/public Deploy Key, or known-host state from another project;
- `tools/client.env`;
- `.venv` or installed host binaries;
- `todo`, `reports`, `worktrees`, `runtime`, logs, locks, or runit supervise state;
- `/openbayes/home/project` or any business source;
- E2E repositories, RFCs, fixtures, or generated output.

Before publishing template changes, require a clean `git status`, inspect `git diff --cached`, and scan tracked content for API keys, private-key headers, tokens, runtime paths, report data, and project artifacts.
