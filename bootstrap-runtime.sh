#!/bin/sh
set -eu

SCRIPT_PATH=$(readlink -f "$0")
BASE=$(dirname "$SCRIPT_PATH")
WORKER_USER=codingworker
WORKER_UID=22022
WORKER_GID=22022
WORKER_HOME=/openbayes/home/coding-worker-home
AGENT_USER=codingagent
AGENT_UID=22023
AGENT_HOME=/openbayes/home/coding-agent-home
PROJECT_GROUP=codingproject
PROJECT_GID=22024

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    fail "bootstrap-runtime.sh must run as root"
fi

case "$BASE" in
    /openbayes/home/* | /output/*) ;;
    *) fail "Coding Worker must live below persistent /openbayes/home" ;;
esac

[ -f "$BASE/config/worker.env" ] || fail \
    "Missing $BASE/config/worker.env; copy config/worker.env.example and configure it first"
[ -x "$BASE/.venv/bin/python" ] || fail \
    "Missing persistent Python environment; run $BASE/install.sh first"
[ -x /openbayes/home/.local/bin/claude ] || fail \
    "Missing Claude Code; run $BASE/install.sh first"
[ "$(ps -p 1 -o comm=)" = "runsvdir" ] || fail "PID 1 is not runsvdir"
[ -d /etc/service ] || fail "/etc/service does not exist"

if getent group "$WORKER_USER" >/dev/null 2>&1; then
    [ "$(getent group "$WORKER_USER" | cut -d: -f3)" = "$WORKER_GID" ] || fail \
        "$WORKER_USER group exists with an unexpected GID"
else
    getent group "$WORKER_GID" >/dev/null 2>&1 && fail "GID $WORKER_GID is already in use"
    groupadd --system --gid "$WORKER_GID" "$WORKER_USER"
fi

if getent passwd "$WORKER_USER" >/dev/null 2>&1; then
    [ "$(id -u "$WORKER_USER")" = "$WORKER_UID" ] || fail \
        "$WORKER_USER user exists with an unexpected UID"
else
    getent passwd "$WORKER_UID" >/dev/null 2>&1 && fail "UID $WORKER_UID is already in use"
    useradd --system --uid "$WORKER_UID" --gid "$WORKER_USER" \
        --home-dir "$WORKER_HOME" --create-home --shell /bin/bash "$WORKER_USER"
fi

if getent group "$PROJECT_GROUP" >/dev/null 2>&1; then
    [ "$(getent group "$PROJECT_GROUP" | cut -d: -f3)" = "$PROJECT_GID" ] || fail \
        "$PROJECT_GROUP group exists with an unexpected GID"
else
    getent group "$PROJECT_GID" >/dev/null 2>&1 && fail "GID $PROJECT_GID is already in use"
    groupadd --system --gid "$PROJECT_GID" "$PROJECT_GROUP"
fi

if getent passwd "$AGENT_USER" >/dev/null 2>&1; then
    [ "$(id -u "$AGENT_USER")" = "$AGENT_UID" ] || fail \
        "$AGENT_USER user exists with an unexpected UID"
else
    getent passwd "$AGENT_UID" >/dev/null 2>&1 && fail "UID $AGENT_UID is already in use"
    useradd --system --uid "$AGENT_UID" --gid "$PROJECT_GROUP" \
        --home-dir "$AGENT_HOME" --create-home --shell /bin/bash "$AGENT_USER"
fi

mkdir -p \
    "$BASE/todo/inbox" "$BASE/todo/working" "$BASE/todo/done" "$BASE/todo/failed" \
    "$BASE/reports" "$BASE/worktrees" "$BASE/runtime" "$BASE/secrets" \
    "$BASE/worker/logs/service" "$WORKER_HOME" "$AGENT_HOME" /opt

if [ -e /opt/coding-worker ] && [ ! -L /opt/coding-worker ]; then
    fail "/opt/coding-worker exists and is not a symlink; refusing to replace it"
fi
ln -sfn "$BASE" /opt/coding-worker

if [ -e /etc/service/coding-worker ] && [ ! -L /etc/service/coding-worker ]; then
    fail "/etc/service/coding-worker exists and is not a symlink; refusing to replace it"
fi
ln -sfn "$BASE/service" /etc/service/coding-worker

if [ -e /usr/local/bin/coding-workerctl ] && [ ! -L /usr/local/bin/coding-workerctl ]; then
    fail "/usr/local/bin/coding-workerctl exists and is not a symlink; refusing to replace it"
fi
ln -sfn "$BASE/bin/coding-workerctl" /usr/local/bin/coding-workerctl

if [ ! -e /init.sh ] || [ -L /init.sh ]; then
    ln -sfn "$BASE/bootstrap-runtime.sh" /init.sh
else
    echo "WARNING: /init.sh is a regular file; leaving it unchanged" >&2
fi

chown -R root:"$PROJECT_GROUP" "$BASE/todo" "$BASE/reports" "$BASE/runtime"
chmod -R u+rwX,g+rX,o-rwx "$BASE/todo" "$BASE/reports" "$BASE/runtime"
find "$BASE/todo" "$BASE/reports" -type d -exec chmod g+s {} +

chown -R "$WORKER_USER:$PROJECT_GROUP" "$BASE/worktrees"
chmod -R u+rwX,g+rX,o-rwx "$BASE/worktrees"
chmod 750 "$BASE/worktrees"

chown -R "$WORKER_USER:$WORKER_USER" "$BASE/worker/logs" "$WORKER_HOME" "$BASE/secrets"
chmod 700 "$WORKER_HOME" "$BASE/secrets"
find "$BASE/secrets" -type f -exec chmod 600 {} +
chown -R "$AGENT_USER:$PROJECT_GROUP" "$AGENT_HOME"
chmod 700 "$AGENT_HOME"
chown root:root "$BASE/config/worker.env"
chmod 600 "$BASE/config/worker.env"
chmod 755 "$BASE/worker/watcher.py" "$BASE/service/run" "$BASE/service/log/run" \
    "$BASE/bin/coding-workerctl" "$BASE/bin/agent-exec" \
    "$BASE/bin/git-exec" \
    "$BASE/bin/bind-project" "$BASE/bin/setup-deploy-key" \
    "$BASE/bootstrap-runtime.sh" "$BASE/install.sh"

set -a
. "$BASE/config/worker.env"
set +a

if [ -n "${PROJECT_ROOT:-}" ]; then
    case "$PROJECT_ROOT" in
        /openbayes/home/* | /output/*) ;;
        *) fail "PROJECT_ROOT must be below persistent /openbayes/home" ;;
    esac
    project_canonical=$(readlink -f "$PROJECT_ROOT")
    case "$project_canonical" in
        "$BASE" | "$BASE"/*) fail "PROJECT_ROOT must be outside the Coding Worker source tree" ;;
    esac
    [ -d "$PROJECT_ROOT/.git" ] || fail "PROJECT_ROOT is not a Git repository: $PROJECT_ROOT"
    if ! chpst -u "$WORKER_USER:$PROJECT_GROUP" test -r "$PROJECT_ROOT" || \
       ! chpst -u "$WORKER_USER:$PROJECT_GROUP" test -w "$PROJECT_ROOT" || \
       ! chpst -u "$WORKER_USER:$PROJECT_GROUP" test -x "$PROJECT_ROOT"; then
        fail "$WORKER_USER must be able to read and write PROJECT_ROOT; clone as that user or fix ownership"
    fi
    if ! chpst -u "$AGENT_USER:$PROJECT_GROUP" test -r "$PROJECT_ROOT" || \
       ! chpst -u "$AGENT_USER:$PROJECT_GROUP" test -x "$PROJECT_ROOT"; then
        fail "$AGENT_USER must be able to read PROJECT_ROOT through $PROJECT_GROUP"
    fi
fi

echo "Coding Worker runtime integration restored at $BASE"
