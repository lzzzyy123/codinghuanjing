#!/usr/bin/env bash
set -euo pipefail

TOOL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG=${CODING_WORKER_CLIENT_CONFIG:-$TOOL_DIR/client.env}
RFC_PATH=${1:-}

fail() { echo "ERROR: $*" >&2; exit 1; }
[ -f "$CONFIG" ] || fail "Missing $CONFIG; copy client.env.example and configure it"
# shellcheck disable=SC1090
source "$CONFIG"
: "${SSH_HOST:?SSH_HOST is required}"
: "${SSH_PORT:?SSH_PORT is required}"
: "${SSH_USER:?SSH_USER is required}"
: "${REMOTE_ROOT:?REMOTE_ROOT is required}"
[ -f "$RFC_PATH" ] || fail "Usage: submit-rfc.sh RFC-YYYYMMDD-NNN.md"

name=$(basename "$RFC_PATH")
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md$ ]] || fail "Unsafe RFC filename: $name"
[[ "$REMOTE_ROOT" =~ ^/[A-Za-z0-9/._-]+$ ]] || fail "Unsafe REMOTE_ROOT"
upload=".upload-${name%.md}-$$-$(date +%s)"
ssh_options=(-p "$SSH_PORT")
scp_options=(-P "$SSH_PORT")
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
    ssh_options+=(-i "$SSH_IDENTITY_FILE")
    scp_options+=(-i "$SSH_IDENTITY_FILE")
fi

scp "${scp_options[@]}" -- "$RFC_PATH" \
    "$SSH_USER@$SSH_HOST:$REMOTE_ROOT/todo/inbox/$upload"
ssh "${ssh_options[@]}" -- "$SSH_USER@$SSH_HOST" \
    "$REMOTE_ROOT/bin/coding-workerctl enqueue-upload '$upload' '$name'"
