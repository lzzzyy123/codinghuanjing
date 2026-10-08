"""Content-addressed, credential-redacted scheduler evidence."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .state_store import StateStore, utc_now


SECRET_PATTERN = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|"
    r"(?:api[_-]?key|auth[_-]?token|password)\s*[:=]\s*)([^\s,}\]]+)"
)


def redact_text(value: str, known_secrets: tuple[str, ...] = ()) -> str:
    redacted = value
    for secret in known_secrets:
        if len(secret) >= 4:
            redacted = redacted.replace(secret, "[REDACTED]")
    return SECRET_PATTERN.sub(r"\1[REDACTED]", redacted)


class ArtifactStore:
    def __init__(self, state: StateStore, root: Path):
        self.state = state
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def put_text(
        self, kind: str, value: str, *, known_secrets: tuple[str, ...] = ()
    ) -> str:
        if not kind.strip():
            raise ValueError("artifact kind must be non-empty")
        content = redact_text(value, known_secrets).encode("utf-8")
        digest_hex = hashlib.sha256(content).hexdigest()
        digest = "sha256:" + digest_hex
        relative = Path(digest_hex[:2]) / digest_hex[2:]
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            try:
                os.write(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink()
        elif destination.read_bytes() != content:
            raise RuntimeError(f"artifact digest collision: {digest}")
        with self.state.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO artifacts VALUES (?, ?, ?, ?, 1, ?)",
                (digest, kind, str(relative), len(content), utc_now()),
            )
        return digest

    def read_text(self, digest: str) -> str:
        with self.state.connect() as connection:
            row = connection.execute(
                "SELECT relative_path FROM artifacts WHERE digest = ?", (digest,)
            ).fetchone()
        if row is None:
            raise KeyError(digest)
        return (self.root / row["relative_path"]).read_text(encoding="utf-8")
