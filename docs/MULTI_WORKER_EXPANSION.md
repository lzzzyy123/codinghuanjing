# Multi-Worker Expansion Design

This document describes a future 2-4 Worker deployment. It does not enable concurrency in the current container. `MAX_CONCURRENT_TASKS=1` remains mandatory until the single-Worker lifecycle is stable in production and an operator explicitly approves expansion.

## Invariants

- One container runs one Worker process and one active RFC at a time.
- Every Worker uses its own repository clone, task worktree root, queue, reports, runtime lock, Agent home, and repository-scoped Deploy Key.
- Every RFC keeps the branch `agent/<RFC-ID>` and has one writing Worker for its entire lifecycle.
- Coder, independent Reviewer, module gates, Project Lead verification, PR, and final full regression remain mandatory.
- Workers never merge, force-push, push a base branch, share a writable worktree, or infer compatibility from another Worker's test result.

## Scheduling Contract

Before dispatch, the Project Lead records the RFC's capability, dependencies, public interface contract, and owned file globs in a central read-only schedule. A task is eligible only when all declared dependencies are merged into its pinned base commit.

Two RFCs may run together only when all of these are true:

1. Their owned file globs do not overlap.
2. Neither changes a public interface consumed by the other.
3. Neither depends on unmerged behavior from the other.
4. Shared generated files, lockfiles, Parity Ledger rows, and root configuration have a single named owner.
5. Both can be validated independently from their own pinned base commits.

The first expansion should use two Workers. Increase to three or four only after at least ten parallel pairs complete without ownership conflicts, hidden dependencies, or integration rollback.

## Recommended Capability Lanes

| Lane | Primary ownership | Must not own concurrently |
| --- | --- | --- |
| Runtime | configuration, profiles, lifecycle, packaging | provider or tool implementations |
| Provider | provider transports, request/response normalization | agent loop and shared contracts without an explicit interface RFC |
| Tools | registry, execution, permissions, MCP | session or gateway persistence |
| Stateful integrations | sessions, memory, cron, gateway adapters | shared schemas without an explicit interface RFC |

These are scheduling lanes, not permanent architecture boundaries. An RFC that crosses lanes is serialized and assigned one owner.

## Interface Changes

Shared contract changes use a short interface RFC first. It lands type definitions, wire contracts, compatibility fixtures, and no consumer migration. Dependent module RFCs then pin that merged commit. This prevents separate Workers from inventing incompatible versions of the same interface.

## Integration Gate

Each module PR must pass its own module gates and root-controlled full regression. Before merging a parallel batch, create a temporary integration branch from the latest base, merge the exact reviewed commits without modification, and run:

- dependency installation from the committed lockfile;
- lint and build;
- the complete Bun suite;
- baseline and Parity Ledger validation;
- affected Python-to-TypeScript differential suites;
- cross-capability end-to-end tests for every changed interface.

An integration failure returns the responsible RFC to its same-RFC amendment cycle. It does not authorize a direct fix on the integration branch.

## Evidence And Recovery

The scheduler records Worker ID, pinned base SHA, owned paths, dependencies, task branch, candidate fingerprint, test evidence, Reviewer verdict, and integration result. A crashed Worker may resume only its own RFC. Reassignment requires proving the candidate branch and reports are byte-identical; otherwise the replacement Worker reruns tests and independent review.

## Rollout Preconditions

- The current single Worker has durable status events and bounded waiting deployed.
- Reviewer infrastructure failures are distinct from code review failures and reviewer-only recovery is proven.
- Same-RFC amendments are proven without simultaneous writers.
- The fixed full regression command is configured and cannot be changed by an RFC.
- At least one real Python-to-TypeScript differential suite passes in CI-like isolation.
- The Project Lead approves the additional containers, Deploy Keys, and scheduler authority.

Until every precondition holds, keep `MAX_CONCURRENT_TASKS=1` and sequence module RFCs by the Parity Ledger dependency graph.
