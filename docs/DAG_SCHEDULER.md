# DAG Scheduler V2

This is the operator contract for the versioned multi-Agent migration scheduler. It is additive to the production single-task watcher. The default and currently supported deployment mode is `shadow`: it validates and materializes the RFC DAG and records durable state without claiming the legacy queue, recovering active leases, or starting model processes.

## Control Boundaries

```text
Mac Project Lead
  -> versioned RFC Markdown + content-addressed DAG
  -> GitHub PR / merge decisions

container schedulerd (persistent, shadow first)
  -> SQLite WAL state + transactional evidence outbox + immutable event projection
  -> dependency/contract/ownership admission
  -> role queues, leases, heartbeats, fencing, recovery

isolated runners (cutover approval required)
  -> Coder pool -> Level 1 -> test queue Level 2
  -> immutable Reviewer pool -> LeadReview
  -> integration queue Level 3 -> reviewed branch push

Git broker
  -> only component allowed to mutate Git metadata, commit, or push
  -> never merges main; remote branch publication is fast-forward-only with pre/post lease checks
```

The legacy `worker/watcher.py`, filesystem queue, reports and global lock remain unchanged and are the rollback path. Shadow schedulerd never reads or renames `todo/inbox` entries.

## Durable Invariants

- RFC revisions and interface contracts are content-addressed and immutable.
- An active task pins one revision digest. A revision cannot be replaced while leased or running.
- The fixed classification must partition all 806 in-scope paths exactly once.
- Planned exact paths and directory prefixes have exactly one owner, and the Git broker rejects every candidate that changes an undeclared path.
- Shared manifests and the Parity ledger use per-RFC change requests and designated single-writer brokers; module Coders never edit those files directly.
- A dependency is not Ready until its exact revision is merged and its contract hashes match.
- The RFC-055 base is a separate external gate. Root RFCs remain `Validated` until Git ancestry proves the merged base contains commit `a7b6dd8...`.
- Every result mutation requires the current lease ID and monotonically increasing fencing token.
- Reviewer infrastructure failure retains the same candidate and requeues Review. `REQUEST_CHANGES` creates a same-RFC amendment job.
- Test evidence is accepted only when its command digest matches the RFC revision's exact level gate and Level 2/3 uses the registry's fixed Python baseline. Reuse additionally requires candidate and environment identity matches.
- Coder author identity is candidate-pinned. Agent role/model/process identity is immutable, and Reviewer Agent/process identity must differ from the Coder's.
- Coding jobs pin an exact Git base commit. Operator delivery commands first fetch remote `main` into a dedicated trusted ref, then bind base-delivery and dependency merge evidence to the fetched commit and verified ancestry.
- Git commits and pushes pass through the single-writer broker. Reviewer input is a detached read-only snapshot.
- Remote publication uses a durable pre-push journal and read-only ref reconciler; active-runner startup wiring, trusted-main fetch freshness, supervised test receipts, kernel process containment and verified UID/GID separation remain mandatory cutover blockers. Shadow mode does not claim them.
- `Done` means Level 3 passed for the reviewed candidate. It does not mean merged. No component automatically merges main.
- Merge authorization is an append-only, audit-only decision. It recomputes the
  exact local RFC ref, commit tree, binary diff, ownership and candidate-bound
  Coder/test/Reviewer/Project Lead/publication evidence. Ordinary modules may be
  classified `AUTO_MERGE_ELIGIBLE`; protected control, security, credential,
  permission, shared-resource and gate changes are classified
  `NEEDS_HUMAN_APPROVAL`. Missing or stale evidence is `BLOCKED`. No merge
  executor, production wiring, remote fetch, push, or GitHub API call is enabled.
- Level 3 evidence is bound to the exact trusted-main commit and candidate tree.
  Authorization also checks a configured Project Lead principal and approval
  channel, immutable candidate-bound approval evidence, the fixed approved Python
  baseline, the pinned remote repository identity, and the live remote branch.
  An immutable eligibility row is historical evidence, never executable authority.
  A future broker must reserve it with its authenticated identity, an idempotency
  key, an expected-main compare-and-swap value, a bounded lease and a fencing token.
  The reservation is consumed exactly once after full revalidation. Expired
  reservations remain blocked until explicit abort/reconciliation, and every
  reservation transition is append-only audit evidence. The actual forge merge
  must use the same expected-main CAS and an exact candidate-head lease in one
  atomic remote ref transaction. A dormant, explicitly invoked merge CAS primitive
  now records its intent before the write and consumes authorization only after
  remote reconciliation proves both refs. It is not wired to a service, runner,
  scheduler queue, GitHub API or production configuration.
- Cost and token metrics may be observed but never pause or terminate scheduling. Resource, timeout, throttling and repeated-failure protections remain mandatory.

## Three Test Levels

| Level | Timing | Required evidence |
| --- | --- | --- |
| 1 | Coder development | Typecheck, build/smoke and frozen interface checks for the candidate digest |
| 2 | Complete module | Full module suite, real Python-to-Bun differential tests, independent Reviewer |
| 3 | Integration batch | Cross-module tests, full regression, aggregate differential and Python-free runtime acceptance |

Level 1 does not replace Level 2 or 3. Cache hits require an exact identity match and retain their original evidence digest.

## Commands

These commands do not change the legacy Worker service:

```bash
coding-workerctl scheduler-validate \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/project/baseline/classification.json

coding-workerctl scheduler-init \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3 \
  /openbayes/home/project/baseline/classification.json

coding-workerctl scheduler-status \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3

coding-workerctl scheduler-history \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3 \
  RFC-20261008-056

coding-workerctl scheduler-record-base-delivery \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3 \
  /openbayes/home/project/baseline/classification.json \
  /openbayes/home/project \
  d53e537a481c50783497993602f3fbbe808eecd9 \
  project-lead

coding-workerctl scheduler-record-merge \
  DAG DATABASE CLASSIFICATION REPOSITORY RFC_ID CANDIDATE_DIGEST MERGE_COMMIT \
  project-lead

coding-workerctl scheduler-replay /openbayes/home/coding-worker/reports
coding-workerctl scheduler-canary
```

`scheduler-validate` and `scheduler-init` are production gates. Both require the
pinned classification file, verify its digest, and prove that the DAG owns each
of the 806 `in_scope` paths exactly once. The underlying Python CLI has an
explicit `--test-mode` escape hatch for synthetic fixtures with smaller
partitions; `coding-workerctl` deliberately does not expose that flag.

The two record commands are the only supported operator path for admitting an
already merged base or RFC. They refresh remote `main`, verify Git ancestry,
bind the trusted-main SHA to the database record, and refresh readiness. Legacy
records without that proof never satisfy dependency admission. There is no
manual `scheduler-recover` command: an active supervisor must prove an expired
executor and all descendants are quiescent before its lease or shared locks can
be released.

## Active Runner CLI Contract (Not Yet Enabled)

The existing daemon only reconciles shadow state and must remain unchanged
until production cutover is approved. A real runner needs one new process
entrypoint, not daemon-side model execution:

```text
coding-scheduler-runner \
  --database STATE.sqlite3 \
  --dag RFC_DAG.json \
  --classification classification.json \
  --runtime-root RUNTIME_ROOT \
  --repository PROJECT_ROOT \
  --agent-id UNIQUE_ID \
  --role coder|tester|reviewer|integrator \
  --model MODEL_ID \
  [--once]
```

On startup it must validate the same classification/DAG identity, register one
agent identity and role, then repeatedly perform `claim -> start -> heartbeat ->
fenced result`. Role/kind compatibility remains owned by `QueueStore`.
Coder/integrator processes request mutable isolated worktrees through the Git
broker; Reviewers receive only detached read-only snapshots; testers execute
the commands pinned in the leased RFC revision. The process must stop cleanly
on lease loss and may publish no result after its fencing token expires.

No runner command may merge `main`, hold the Deploy Key directly, bypass
resource admission, or accept `--test-mode`. `coding-workerctl` should expose
runner start/stop/status only after runit service definitions, Unix identities,
resource limits, and the production-switch approval token exist.

The standalone shadow service is `service/scheduler/run`. Installing its runit link is a production control-plane change and requires explicit operator approval. The daemon itself rejects every mode other than `shadow` and deliberately does not enqueue runnable jobs because it has no bound, freshness-verified project Git ref.

## Resource Admission And Concurrency

The measured container has 6 vCPU, a 6,291,456,000-byte memory cgroup, no swap and no GPU. Provider parallel-request limits are unpublished. It must not start at 4C+2R.

| Configuration | Current-container use | Rationale |
| --- | --- | --- |
| 1C+1R | first real model canary | at most two expensive processes; isolates model throttling and memory behavior |
| 2C+1R | conditional second canary | only after measured headroom stays above 1 GiB and no model 429/OOM trend appears |
| 2C+2R | requires measured upgrade or proof | Reviewer latency is historically lower, so the second Reviewer may add little throughput |
| 4C+2R | target after resource upgrade | recommend at least 12 vCPU, 16 GiB RAM, adequate swap and provider concurrency >= 6 |
| 4C+4R | not recommended initially | historical Reviewer median is much shorter than Coder median, making Review overprovisioned |

Historical envelopes show median Coder time near 190 seconds and Reviewer time near 69 seconds. The ideal model-stage limit for 4C+2R is therefore Coder-bound at roughly four times serial model throughput. Tests, dependencies and integration reduce expected end-to-end gain; use a 2-3x planning range until real canaries produce measurements.

Admission checks use expensive-process count, reclaimable-cache-adjusted memory headroom, disk free space, per-CPU load and OOM evidence. There is no daily, per-RFC or cumulative cost limit.

## Staged Cutover

1. Merge and ancestry-verify RFC-055. Until then every root task remains non-Ready.
2. Merge the scheduler and RFC DAG PRs. Run schedulerd in shadow alongside the unchanged watcher.
3. Replay legacy histories, run the synthetic queue-only 4C+2R crash-recovery canary, and validate Unix identities in the real container. This canary does not measure model throughput, worktree isolation, Git publication, or test execution.
4. With separate approval, run a 1C+1R real-model canary on isolated canary tasks. Do not submit migration RFCs yet.
5. If resource and provider telemetry is stable, test 2C+1R on dependency-independent modules.
6. With separate production-switch approval, disable legacy claiming, enable runner services and schedule only the first Ready batch.
7. Scale only after ten conflict-free parallel pairs and successful Level 3 batch integration.

## Rollback

Before active cutover, stop or omit the optional scheduler service and discard its shadow database; the legacy watcher and queue are unaffected. After active cutover, stop runner processes, let leases expire, preserve SQLite/evidence/worktrees, and re-enable the legacy watcher only for RFCs that were never claimed by V2. Never allow both systems to claim the same RFC source.

Rollback does not delete branches, reports, artifacts or revision history. Remote task branches remain non-force-pushed and main remains human-controlled.
