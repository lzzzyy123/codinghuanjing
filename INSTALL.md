# Installation And Recovery Guide

This document rebuilds the Single-Project Coding Worker on a clean Ubuntu/OpenBayes container without relying on prior conversation context.

## 1. Preconditions

The supported OpenBayes layout is:

- Ubuntu
- PID 1 is `runsvdir`
- `/etc/service` is the active runit service directory
- `/openbayes/home` is persistent
- root SSH access is available
- outbound HTTPS can reach Node.js, npm, GitHub, and the LiteLLM gateway

Inspect the host:

```bash
cat /etc/os-release
ps -p 1 -o pid,comm,args
df -h /openbayes/home
git --version
curl --version
```

Do not install the source under `/opt`; OpenBayes does not guarantee that path survives environment reconstruction.

## 2. Obtain The Mother Template

```bash
git clone https://github.com/lzzzyy123/codinghuanjing.git /openbayes/home/coding-worker
cd /openbayes/home/coding-worker
```

For an offline copy, transfer only repository-tracked files. Do not copy another host's `config/worker.env`, queue, reports, worktrees, locks, logs, virtual environment, or project repository.

## 3. Create Host Configuration

```bash
install -m 600 -o root -g root \
  config/worker.env.example config/worker.env
```

Edit `config/worker.env`. For the first installation it is valid to leave `PROJECT_ROOT=` empty:

```text
CODING_WORKER_HOME=/openbayes/home/coding-worker
AGENT_CLI=/openbayes/home/.local/bin/claude

PROJECT_ROOT=
BASE_BRANCH=main

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
POLL_INTERVAL=5
KEEP_SUCCESS_WORKTREES=false
```

Do not place credentials in shell scripts, RFCs, prompts, project repositories, logs, reports, or Git history.

## 4. Run The Idempotent Installer

```bash
chmod 755 install.sh bootstrap-runtime.sh
./install.sh
```

`install.sh` performs the following:

1. Checks Ubuntu, runit, CPU architecture, and required system commands.
2. Downloads pinned Node.js into `/openbayes/home/.local`.
3. Verifies the Node.js archive against the official SHA-256 manifest.
4. Installs a pinned Claude Code version into the persistent prefix.
5. Creates `.venv` below the persistent Coding Worker tree.
6. Installs pinned Python dependencies into that virtual environment.
7. Creates `config/worker.env` from the secret-free example if it is missing.
8. Calls `bootstrap-runtime.sh` to create users, directories, permissions, and runit links.

The installer is safe to rerun after a dependency or base-image change. It does not overwrite an existing `config/worker.env`, project repository, RFC queue, report, or task branch.

## 5. Runtime Bootstrap Details

`bootstrap-runtime.sh` is the fast recovery path. It does not download dependencies. It:

- creates or validates `codingworker` UID/GID 22022;
- creates runtime directories and permissions;
- enforces `config/worker.env` mode `0600`;
- creates `/opt/coding-worker -> /openbayes/home/coding-worker`;
- creates `/etc/service/coding-worker -> .../service`;
- creates `/init.sh -> .../bootstrap-runtime.sh` when `/init.sh` is absent or already a symlink;
- validates the bound project without changing its ownership.

Run it after any OpenBayes runtime reconstruction:

```bash
/openbayes/home/coding-worker/bootstrap-runtime.sh
```

If the persistent Node.js installation or Python virtual environment is absent or broken, run `install.sh` instead.

## 6. Verify Dependencies

```bash
/openbayes/home/coding-worker/bin/coding-workerctl doctor
```

Expected components include Node.js 22, Claude Code, Python, PyYAML, the configured LiteLLM URL, and an active runit service. With `PROJECT_ROOT=` the doctor reports `PROJECT=UNBOUND`; that is healthy and the inbox is paused.

To verify the LiteLLM model list without putting the key directly in command history:

```bash
set -a
. /openbayes/home/coding-worker/config/worker.env
set +a
gateway_host=${LITELLM_BASE_URL#*://}
gateway_host=${gateway_host%%/*}
curl --noproxy "$gateway_host" -fsS "$LITELLM_BASE_URL/v1/models" \
  -H "Authorization: Bearer $LITELLM_API_KEY"
```

Confirm the response contains the exact model ID configured as `MODEL`, normally `xiaosuan-8`.

## 7. Bind The One Project

Create or clone the project below persistent storage as `codingworker`. Example:

```bash
env HOME=/openbayes/home/coding-worker-home \
  chpst -u codingworker:codingworker \
  git clone <PROJECT_GIT_URL> /openbayes/home/project
```

For an existing repository, make sure `codingworker` can read and write it. Do not recursively change ownership until you have confirmed the path is the intended project.

Set:

```text
PROJECT_ROOT=/openbayes/home/project
BASE_BRANCH=main
```

Then validate and restart:

```bash
/openbayes/home/coding-worker/bootstrap-runtime.sh
/openbayes/home/coding-worker/bin/coding-workerctl restart
/openbayes/home/coding-worker/bin/coding-workerctl doctor
```

The Worker never clones projects from RFC data and never accepts a project path in an RFC. Do not rebind while `todo/working` is non-empty.

## 8. Runit Operations

```bash
/opt/coding-worker/bin/coding-workerctl status
/opt/coding-worker/bin/coding-workerctl start
/opt/coding-worker/bin/coding-workerctl stop
/opt/coding-worker/bin/coding-workerctl restart
/opt/coding-worker/bin/coding-workerctl logs
```

Equivalent low-level usage is:

```bash
SVDIR=/etc/service sv status coding-worker
```

The service launches as root only long enough to read the `0600` configuration, then `chpst` executes the Worker as `codingworker`.

## 9. Submit An RFC

Copy `templates/RFC_TEMPLATE.md` and use a globally unique filename such as `RFC-20260924-001.md`. Its YAML front matter contains task and command data only:

```yaml
---
title: Add a small tested feature
test_command: "pytest -q"
lint_command: ""
build_command: ""
---
```

The fields `project`, `repository`, `base_branch`, and `working_directory` are forbidden. `branch` is optional and otherwise defaults to `agent/<RFC-ID>`.

Upload atomically:

```bash
scp -P <port> RFC-20260924-001.md \
  root@<host>:/opt/coding-worker/todo/RFC-20260924-001.md.upload
ssh -p <port> root@<host> \
  'mv /opt/coding-worker/todo/RFC-20260924-001.md.upload /opt/coding-worker/todo/inbox/RFC-20260924-001.md'
```

## 10. E2E Acceptance Checklist

Observe these facts rather than trusting an Agent claim:

```bash
/opt/coding-worker/bin/coding-workerctl queue
cat /opt/coding-worker/reports/RFC-20260924-001/status.json
tail -F /opt/coding-worker/reports/RFC-20260924-001/worker.log
git -C /openbayes/home/project worktree list
git -C /openbayes/home/project log --oneline --all
```

Acceptance requires:

- the RFC moves `inbox -> working -> done`;
- an `agent/<RFC-ID>` branch is created from configured `BASE_BRANCH`;
- Coder and Reviewer raw reports have different session IDs;
- the Worker-generated `tests.log` contains actual commands, exit codes, stdout, and stderr;
- `review-latest.json` contains `PASS`;
- `status.json` contains `status: done`, `tests_passed: true`, and a commit SHA;
- the base branch remains unchanged and no merge or push occurs.

## 11. Failure And Crash Recovery

Terminal failures move the RFC to `todo/failed` and leave a failure report. Failed worktrees are preserved. After fixing the cause, move the RFC back to `inbox`; the same ID reuses its task branch/worktree and records a new attempt.

If the process dies while an RFC is in `working`, run:

```bash
/opt/coding-worker/bin/coding-workerctl restart
```

The Worker recovers `working` before claiming another task. Coder and Reviewer contexts are always recreated rather than resumed.

## 12. Rebuild Recovery

After an OpenBayes environment rebuild, first confirm these persistent paths still exist:

```text
/openbayes/home/coding-worker
/openbayes/home/.local
/openbayes/home/coding-worker-home
/openbayes/home/project
```

Then run:

```bash
cd /openbayes/home/coding-worker
./bootstrap-runtime.sh
./bin/coding-workerctl start
./bin/coding-workerctl doctor
```

Use `./install.sh` if bootstrap reports a missing Node.js/Claude/Python runtime.

## 13. What To Copy And What Never To Copy

Copy or publish repository-tracked source files only: installer, bootstrap, Worker source, prompts, service definitions, CLI, configuration example, RFC template, README, INSTALL guide, and `.gitignore`.

Never copy or commit:

- `config/worker.env` or any API key;
- `.venv` or host-installed binaries;
- `todo`, `reports`, `worktrees`, `runtime`, or logs;
- `service/**/supervise` state;
- a bound project repository;
- smoke-test projects, generated RFCs, or temporary output.
