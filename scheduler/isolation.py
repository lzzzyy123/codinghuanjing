"""Filesystem layout for independently isolated scheduler actors."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class AgentPaths:
    home: Path
    cache: Path
    logs: Path


class IsolationLayout:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def agent_paths(self, agent_id: str) -> AgentPaths:
        if not IDENTITY_RE.fullmatch(agent_id):
            raise ValueError("invalid agent identity")
        home = self.root / "agents" / agent_id / "home"
        cache = self.root / "agents" / agent_id / "cache"
        logs = self.root / "agents" / agent_id / "logs"
        for path in (home, cache, logs):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        return AgentPaths(home, cache, logs)

    def task_worktree(self, rfc_id: str) -> Path:
        if not IDENTITY_RE.fullmatch(rfc_id):
            raise ValueError("invalid RFC identity")
        return self.root / "worktrees" / rfc_id

    def reviewer_snapshot(self, rfc_id: str, commit_sha: str) -> Path:
        if not IDENTITY_RE.fullmatch(rfc_id) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise ValueError("invalid snapshot identity")
        return self.root / "review-snapshots" / rfc_id / commit_sha
