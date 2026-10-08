# DAG Scheduler V2

This is the operator contract for the versioned multi-Agent migration scheduler. It is additive to the production single-task watcher. The default and currently supported deployment mode is `shadow`: it validates and materializes the RFC DAG, records durable state, and performs lease recovery without claiming the legacy queue or starting model processes.

## Control Boundaries

```text
Mac Project Lead
  -> versioned RFC Markdown + content-addressed DAG
  -> GitHub PR / merge decisions

container schedulerd (persistent, shadow first)
  -> SQLite WAL state + append-only evidence
  -> dependency/contract/ownership admission
  -> role queues, leases, heartbeats, fencing, recovery

isolated runners (cutover approval required)
  -> Coder pool -> Level 1 -> test queue Level 2
  -> immutable Reviewer pool -> LeadReview
  -> integration queue Level 3 -> reviewed branch push

Git broker
  -> only component allowed to mutate Git metadata, commit, or push
  -> never merges main and never force-pushes
```

The legacy `worker/watcher.py`, filesystem queue, reports and global lock remain unchanged and are the rollback path. Shadow schedulerd never reads or renames `todo/inbox` entries.

## Durable Invariants

- RFC revisions and interface contracts are content-addressed and immutable.
- An active task pins one revision digest. A revision cannot be replaced while leased or running.
- The fixed classification must partition all 806 in-scope paths exactly once.
- Planned target paths have exactly one owner. Shared resources use named lock keys or a single integration owner.
- A dependency is not Ready until its exact revision is merged and its contract hashes match.
- The RFC-055 base is a separate external gate. Root RFCs remain `Validated` until Git ancestry proves the merged base contains commit `a7b6dd8...`.
- Every result mutation requires the current lease ID and monotonically increasing fencing token.
- Reviewer infrastructure failure retains the same candidate and requeues Review. `REQUEST_CHANGES` creates a same-RFC amendment job.
- Test evidence is reusable only when revision, candidate, command, environment and Python baseline identities all match.
- Git commits and pushes pass through the single-writer broker. Reviewer input is a detached read-only snapshot.
- `Done` means Level 3 passed for the reviewed candidate. It does not mean merged. No component automatically merges main.
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
  /openbayes/home/project/coordination/rfc-dag.v1.json

coding-workerctl scheduler-init \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3

coding-workerctl scheduler-status \
  /openbayes/home/project/coordination/rfc-dag.v1.json \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3

coding-workerctl scheduler-history \
  /openbayes/home/coding-worker/runtime/scheduler/state.sqlite3 \
  RFC-20261008-056

coding-workerctl scheduler-replay /openbayes/home/coding-worker/reports
coding-workerctl scheduler-canary
```

The standalone shadow service is `service/scheduler/run`. Installing its runit link is a production control-plane change and requires explicit operator approval. The daemon itself rejects every mode other than `shadow`.

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
3. Replay legacy histories, run synthetic 4C+2R and crash recovery, and validate Unix identities in the real container.
4. With separate approval, run a 1C+1R real-model canary on isolated canary tasks. Do not submit migration RFCs yet.
5. If resource and provider telemetry is stable, test 2C+1R on dependency-independent modules.
6. With separate production-switch approval, disable legacy claiming, enable runner services and schedule only the first Ready batch.
7. Scale only after ten conflict-free parallel pairs and successful Level 3 batch integration.

## Rollback

Before active cutover, stop or omit the optional scheduler service and discard its shadow database; the legacy watcher and queue are unaffected. After active cutover, stop runner processes, let leases expire, preserve SQLite/evidence/worktrees, and re-enable the legacy watcher only for RFCs that were never claimed by V2. Never allow both systems to claim the same RFC source.

Rollback does not delete branches, reports, artifacts or revision history. Remote task branches remain non-force-pushed and main remains human-controlled.
