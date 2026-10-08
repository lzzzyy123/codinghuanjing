"""Load and validate a content-addressed RFC dependency graph."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


RFC_ID_RE = re.compile(r"^RFC-[0-9]{8}-[0-9]{3}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_TEST_LEVELS = ("level1", "level2")


class RegistryError(ValueError):
    """The RFC registry is malformed or internally inconsistent."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def content_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def revision_payload(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "revision_digest"}


def normalized_relative_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{field} entries must be non-empty strings")
    if value != value.strip() or "\\" in value:
        raise RegistryError(f"{field} contains a non-canonical path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RegistryError(f"{field} must contain normalized relative paths: {value!r}")
    return str(path)


def string_list(value: object, field: str, *, non_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or (non_empty and not value):
        requirement = "a non-empty list" if non_empty else "a list"
        raise RegistryError(f"{field} must be {requirement}")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise RegistryError(f"{field} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise RegistryError(f"{field} contains duplicate entries")
    return tuple(value)


def contract_map(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RegistryError(f"{field} must be an object")
    result: dict[str, str] = {}
    for name, digest in value.items():
        if not isinstance(name, str) or not name.strip():
            raise RegistryError(f"{field} contains an invalid contract name")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise RegistryError(f"{field}.{name} must be a sha256 digest")
        result[name] = digest
    return result


@dataclass(frozen=True)
class RfcRevision:
    rfc_id: str
    title: str
    capability_group: str
    revision: int
    revision_digest: str
    python_sources: tuple[str, ...]
    target_files: tuple[str, ...]
    depends_on: tuple[str, ...]
    provides: dict[str, str]
    requires: dict[str, str]
    level1_tests: tuple[str, ...]
    level2_tests: tuple[str, ...]
    integration_batch: str
    acceptance_criteria: tuple[str, ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class Registry:
    schema_version: int
    baseline_commit: str
    classification_sha256: str
    in_scope_count: int
    rfcs: dict[str, RfcRevision]
    topological_order: tuple[str, ...]
    digest: str

    def ancestors(self, rfc_id: str) -> set[str]:
        found: set[str] = set()
        stack = list(self.rfcs[rfc_id].depends_on)
        while stack:
            dependency = stack.pop()
            if dependency in found:
                continue
            found.add(dependency)
            stack.extend(self.rfcs[dependency].depends_on)
        return found


def _parse_rfc(value: object, index: int) -> RfcRevision:
    if not isinstance(value, dict):
        raise RegistryError(f"rfcs[{index}] must be an object")
    rfc_id = value.get("id")
    if not isinstance(rfc_id, str) or not RFC_ID_RE.fullmatch(rfc_id):
        raise RegistryError(f"rfcs[{index}].id is invalid")
    title = value.get("title")
    capability = value.get("capability_group")
    if not isinstance(title, str) or not title.strip():
        raise RegistryError(f"{rfc_id}.title must be non-empty")
    if not isinstance(capability, str) or not capability.strip():
        raise RegistryError(f"{rfc_id}.capability_group must be non-empty")
    revision = value.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise RegistryError(f"{rfc_id}.revision must be a positive integer")
    digest = value.get("revision_digest")
    expected_digest = content_digest(revision_payload(value))
    if digest != expected_digest:
        raise RegistryError(
            f"{rfc_id}.revision_digest mismatch: expected {expected_digest}"
        )
    sources = tuple(
        normalized_relative_path(item, f"{rfc_id}.python_sources")
        for item in string_list(value.get("python_sources"), f"{rfc_id}.python_sources")
    )
    targets = tuple(
        normalized_relative_path(item, f"{rfc_id}.target_files")
        for item in string_list(value.get("target_files"), f"{rfc_id}.target_files")
    )
    dependencies = string_list(
        value.get("depends_on", []), f"{rfc_id}.depends_on", non_empty=False
    )
    if any(not RFC_ID_RE.fullmatch(item) for item in dependencies):
        raise RegistryError(f"{rfc_id}.depends_on contains an invalid RFC ID")
    contracts = value.get("contracts")
    if not isinstance(contracts, dict):
        raise RegistryError(f"{rfc_id}.contracts must be an object")
    provides = contract_map(contracts.get("provides", {}), f"{rfc_id}.contracts.provides")
    requires = contract_map(contracts.get("requires", {}), f"{rfc_id}.contracts.requires")
    tests = value.get("tests")
    if not isinstance(tests, dict):
        raise RegistryError(f"{rfc_id}.tests must be an object")
    for level in REQUIRED_TEST_LEVELS:
        if level not in tests:
            raise RegistryError(f"{rfc_id}.tests.{level} is required")
    level1 = string_list(tests["level1"], f"{rfc_id}.tests.level1")
    level2 = string_list(tests["level2"], f"{rfc_id}.tests.level2")
    batch = value.get("integration_batch")
    if not isinstance(batch, str) or not batch.strip():
        raise RegistryError(f"{rfc_id}.integration_batch must be non-empty")
    acceptance = string_list(
        value.get("acceptance_criteria"), f"{rfc_id}.acceptance_criteria"
    )
    return RfcRevision(
        rfc_id=rfc_id,
        title=title.strip(),
        capability_group=capability.strip(),
        revision=revision,
        revision_digest=digest,
        python_sources=sources,
        target_files=targets,
        depends_on=dependencies,
        provides=provides,
        requires=requires,
        level1_tests=level1,
        level2_tests=level2,
        integration_batch=batch.strip(),
        acceptance_criteria=acceptance,
        raw=dict(value),
    )


def _topological_order(rfcs: dict[str, RfcRevision]) -> tuple[str, ...]:
    incoming = {rfc_id: len(rfc.depends_on) for rfc_id, rfc in rfcs.items()}
    followers: dict[str, list[str]] = {rfc_id: [] for rfc_id in rfcs}
    for rfc in rfcs.values():
        for dependency in rfc.depends_on:
            if dependency not in rfcs:
                raise RegistryError(f"{rfc.rfc_id} depends on unknown {dependency}")
            if dependency == rfc.rfc_id:
                raise RegistryError(f"{rfc.rfc_id} cannot depend on itself")
            followers[dependency].append(rfc.rfc_id)
    ready = sorted(rfc_id for rfc_id, count in incoming.items() if count == 0)
    ordered: list[str] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for follower in sorted(followers[current]):
            incoming[follower] -= 1
            if incoming[follower] == 0:
                ready.append(follower)
                ready.sort()
    if len(ordered) != len(rfcs):
        cyclic = sorted(rfc_id for rfc_id, count in incoming.items() if count)
        raise RegistryError("RFC dependency cycle: " + ", ".join(cyclic))
    return tuple(ordered)


def _validate_unique_ownership(rfcs: Iterable[RfcRevision], field: str) -> None:
    owners: dict[str, str] = {}
    for rfc in rfcs:
        for path in getattr(rfc, field):
            previous = owners.get(path)
            if previous:
                raise RegistryError(
                    f"{field} ownership collision for {path}: {previous} and {rfc.rfc_id}"
                )
            owners[path] = rfc.rfc_id


def _validate_contracts(registry: Registry) -> None:
    providers: dict[str, tuple[str, str]] = {}
    for rfc in registry.rfcs.values():
        for name, digest in rfc.provides.items():
            previous = providers.get(name)
            if previous:
                raise RegistryError(
                    f"contract {name} has multiple providers: {previous[0]} and {rfc.rfc_id}"
                )
            providers[name] = (rfc.rfc_id, digest)
    for rfc in registry.rfcs.values():
        ancestors = registry.ancestors(rfc.rfc_id)
        for name, digest in rfc.requires.items():
            provider = providers.get(name)
            if not provider:
                raise RegistryError(f"{rfc.rfc_id} requires unprovided contract {name}")
            provider_id, provided_digest = provider
            if provider_id not in ancestors:
                raise RegistryError(
                    f"{rfc.rfc_id} requires {name} but does not depend on provider {provider_id}"
                )
            if digest != provided_digest:
                raise RegistryError(
                    f"{rfc.rfc_id} requires {name} at {digest}, provider has {provided_digest}"
                )


def load_registry(path: Path) -> Registry:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot load registry {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise RegistryError("registry root must be an object")
    if document.get("schema_version") != 1:
        raise RegistryError("schema_version must be 1")
    baseline = document.get("baseline")
    if not isinstance(baseline, dict):
        raise RegistryError("baseline must be an object")
    commit = baseline.get("commit")
    classification = baseline.get("classification_sha256")
    count = baseline.get("in_scope_count")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise RegistryError("baseline.commit must be a full Git SHA")
    if not isinstance(classification, str) or not SHA256_RE.fullmatch(classification):
        raise RegistryError("baseline.classification_sha256 must be a sha256 digest")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise RegistryError("baseline.in_scope_count must be a positive integer")
    values = document.get("rfcs")
    if not isinstance(values, list) or not values:
        raise RegistryError("rfcs must be a non-empty list")
    parsed = [_parse_rfc(value, index) for index, value in enumerate(values)]
    rfcs = {rfc.rfc_id: rfc for rfc in parsed}
    if len(rfcs) != len(parsed):
        raise RegistryError("RFC IDs must be unique")
    order = _topological_order(rfcs)
    _validate_unique_ownership(parsed, "python_sources")
    _validate_unique_ownership(parsed, "target_files")
    registry = Registry(
        schema_version=1,
        baseline_commit=commit,
        classification_sha256=classification,
        in_scope_count=count,
        rfcs=rfcs,
        topological_order=order,
        digest=content_digest(document),
    )
    _validate_contracts(registry)
    return registry


def with_revision_digest(value: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with its canonical revision digest populated."""
    result = dict(value)
    result["revision_digest"] = content_digest(revision_payload(result))
    return result
