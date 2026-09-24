#!/bin/sh
set -eu

SCRIPT_PATH=$(readlink -f "$0")
BASE=$(dirname "$SCRIPT_PATH")
PERSISTENT_PREFIX=/openbayes/home/.local
NODE_VERSION=${NODE_VERSION:-22.23.3}
CLAUDE_CODE_VERSION=${CLAUDE_CODE_VERSION:-2.1.281}
PYYAML_VERSION=${PYYAML_VERSION:-6.0.2}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "install.sh must run as root"
[ -r /etc/os-release ] || fail "Cannot identify the operating system"
. /etc/os-release
[ "$ID" = "ubuntu" ] || fail "This installer currently supports Ubuntu only"
[ "$(ps -p 1 -o comm=)" = "runsvdir" ] || fail \
    "PID 1 must be runsvdir; use a different service adapter on non-runit hosts"

case "$BASE" in
    /openbayes/home/* | /output/*) ;;
    *) fail "Copy this repository below /openbayes/home before installing" ;;
esac

missing_packages=""
command -v curl >/dev/null 2>&1 || missing_packages="$missing_packages curl"
command -v git >/dev/null 2>&1 || missing_packages="$missing_packages git"
command -v sha256sum >/dev/null 2>&1 || missing_packages="$missing_packages coreutils"
command -v xz >/dev/null 2>&1 || missing_packages="$missing_packages xz-utils"
command -v ssh-keygen >/dev/null 2>&1 || missing_packages="$missing_packages openssh-client"
if [ -n "$missing_packages" ]; then
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y ca-certificates $missing_packages
fi

machine=$(uname -m)
case "$machine" in
    x86_64) node_arch=x64 ;;
    aarch64 | arm64) node_arch=arm64 ;;
    *) fail "Unsupported CPU architecture: $machine" ;;
esac

node_name="node-v${NODE_VERSION}-linux-${node_arch}"
node_dir="$PERSISTENT_PREFIX/$node_name"
mkdir -p "$PERSISTENT_PREFIX/bin"

if [ ! -x "$node_dir/bin/node" ]; then
    download_dir=$(mktemp -d)
    trap 'rm -rf "$download_dir"' EXIT HUP INT TERM
    sums_url="https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"
    archive_url="https://nodejs.org/dist/v${NODE_VERSION}/${node_name}.tar.xz"
    curl -fsSL "$sums_url" -o "$download_dir/SHASUMS256.txt"
    curl -fsSL "$archive_url" -o "$download_dir/${node_name}.tar.xz"
    expected=$(awk -v file="${node_name}.tar.xz" '$2 == file { print $1 }' "$download_dir/SHASUMS256.txt")
    [ -n "$expected" ] || fail "Node.js checksum was not found"
    actual=$(sha256sum "$download_dir/${node_name}.tar.xz" | awk '{ print $1 }')
    [ "$actual" = "$expected" ] || fail "Node.js checksum verification failed"
    tar -xJf "$download_dir/${node_name}.tar.xz" -C "$PERSISTENT_PREFIX"
    rm -rf "$download_dir"
    trap - EXIT HUP INT TERM
fi

ln -sfn "$node_dir/bin/node" "$PERSISTENT_PREFIX/bin/node"
ln -sfn "$node_dir/bin/npm" "$PERSISTENT_PREFIX/bin/npm"
ln -sfn "$node_dir/bin/npx" "$PERSISTENT_PREFIX/bin/npx"
ln -sfn "$node_dir/bin/corepack" "$PERSISTENT_PREFIX/bin/corepack"
export PATH="$PERSISTENT_PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if ! "$PERSISTENT_PREFIX/bin/claude" --version 2>/dev/null | grep -q "$CLAUDE_CODE_VERSION"; then
    npm install --global --prefix "$PERSISTENT_PREFIX" \
        "@anthropic-ai/claude-code@$CLAUDE_CODE_VERSION"
fi

python_bin=""
for candidate in /usr/local/bin/python3 /usr/bin/python3; do
    if [ -x "$candidate" ]; then
        python_bin=$candidate
        break
    fi
done
[ -n "$python_bin" ] || fail "Python 3 is required"

if [ ! -x "$BASE/.venv/bin/python" ]; then
    if ! "$python_bin" -m venv "$BASE/.venv"; then
        apt-get update
        apt-get install -y python3-venv python3-pip
        /usr/bin/python3 -m venv "$BASE/.venv"
    fi
fi
"$BASE/.venv/bin/pip" install "PyYAML==$PYYAML_VERSION"

if [ ! -f "$BASE/config/worker.env" ]; then
    install -m 600 -o root -g root "$BASE/config/worker.env.example" "$BASE/config/worker.env"
    echo "Created config/worker.env from the example. Set LiteLLM credentials before production use."
fi

chmod 755 "$BASE/install.sh" "$BASE/bootstrap-runtime.sh" "$BASE/bin/"* \
    "$BASE/worker/watcher.py" "$BASE/worker/doctor.py" "$BASE/worker/control.py"
"$BASE/bootstrap-runtime.sh"

sleep 2
SVDIR=/etc/service sv up coding-worker || true
echo "Node.js: $(node --version)"
echo "Claude Code: $("$PERSISTENT_PREFIX/bin/claude" --version)"
echo "Python: $("$BASE/.venv/bin/python" --version)"
echo "Installation complete. Run: $BASE/bin/coding-workerctl doctor"
