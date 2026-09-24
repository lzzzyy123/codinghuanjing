#!/usr/bin/env bash
set -euo pipefail

TOOL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG=${CODING_WORKER_CLIENT_CONFIG:-$TOOL_DIR/client.env}
RFC_ID=${1:-}

fail() { echo "ERROR: $*" >&2; exit 1; }
[ -f "$CONFIG" ] || fail "Missing $CONFIG; copy client.env.example and configure it"
# shellcheck disable=SC1090
source "$CONFIG"
[[ "$RFC_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail "Usage: create-pr.sh RFC-ID"
[[ "$REMOTE_ROOT" =~ ^/[A-Za-z0-9/._-]+$ ]] || fail "Unsafe REMOTE_ROOT"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY=owner/repository is required}"
command -v gh >/dev/null 2>&1 || fail "GitHub CLI (gh) is required on the Mac"

ssh_options=(-p "$SSH_PORT")
[[ -z "${SSH_IDENTITY_FILE:-}" ]] || ssh_options+=(-i "$SSH_IDENTITY_FILE")
remote=(ssh "${ssh_options[@]}" -- "$SSH_USER@$SSH_HOST")
status=$("${remote[@]}" "$REMOTE_ROOT/bin/coding-workerctl rfc-status '$RFC_ID'")
branch=$(awk -F': ' '$1 == "Branch" {print $2}' <<<"$status")
title=$(awk -F': ' '$1 == "Title" {print $2}' <<<"$status")
commit=$(awk -F': ' '$1 == "Commit" {print $2}' <<<"$status")
tests=$(awk -F': ' '$1 == "Tests" {print $2}' <<<"$status")
review=$(awk -F': ' '$1 == "Review" {print $2}' <<<"$status")
push=$(awk -F': ' '$1 == "Push" {print $2}' <<<"$status")
[[ "$tests" == PASS && "$review" == PASS && "$push" == PASS && "$commit" != - ]] || fail \
    "RFC is not ready for a PR; expected tests/review/push PASS"

project=$("${remote[@]}" "$REMOTE_ROOT/bin/coding-workerctl project")
base=$(awk -F': ' '$1 == "Base branch" {print $2}' <<<"$project")
repository=$(awk -F': ' '$1 == "Repository" {print $2}' <<<"$project")
[[ "$repository" == "git@github.com:$GITHUB_REPOSITORY.git" ]] || fail \
    "Mac GITHUB_REPOSITORY does not match the container's authoritative origin"
body=$(mktemp)
trap 'rm -f "$body"' EXIT
"${remote[@]}" "cat '$REMOTE_ROOT/reports/$RFC_ID/pr-description.md'" >"$body"

url=$(gh pr list --repo "$GITHUB_REPOSITORY" --head "$branch" --state open --json url --jq '.[0].url')
if [[ -z "$url" ]]; then
    pr_title=$RFC_ID
    [[ -z "$title" || "$title" == - ]] || pr_title="$RFC_ID: $title"
    url=$(gh pr create --repo "$GITHUB_REPOSITORY" --base "$base" --head "$branch" \
        --title "$pr_title" --body-file "$body")
fi
[[ "$url" =~ ^https://github\.com/.+/pull/[0-9]+$ ]] || fail "Could not determine PR URL"
"${remote[@]}" "$REMOTE_ROOT/bin/coding-workerctl record-pr '$RFC_ID' '$url'"
echo "$url"
echo "PR created or found. This tool never merges it."
