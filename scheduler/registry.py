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


@dataclass(frozen=True)
class SharedResource:
    name: str
    files: tuple[str, ...]
    writer: str
    request_template: str
    request_owner: str
    application_stage: str


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
    config_sources: tuple[str, ...]
    target_files: tuple[str, ...]
    target_prefixes: tuple[str, ...]
    source_targets: dict[str, str]
    config_targets: dict[str, str]
    shared_change_requests: dict[str, str]
    lock_keys: tuple[str, ...]
    depends_on: tuple[str, ...]
    provides: dict[str, str]
    requires: dict[str, str]
    contract_definitions: dict[str, Any]
    level1_tests: tuple[str, ...]
    level2_tests: tuple[str, ...]
    level3_tests: tuple[str, ...]
    integration_batch: str
    acceptance_criteria: tuple[str, ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class Registry:
    schema_version: int
    baseline_commit: str
    classification_sha256: str
    in_scope_count: int
    config_data_count: int
    baseline_tree: str | None
    base_delivery_rfc: str | None
    base_delivery_commit: str | None
    shared_resources: dict[str, SharedResource]
    frozen_control_paths: tuple[str, ...]
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
    supersedes = value.get("supersedes")
    if revision == 1 and supersedes is not None:
        raise RegistryError(f"{rfc_id} revision 1 cannot supersede another revision")
    if revision > 1:
        if not isinstance(supersedes, dict):
            raise RegistryError(f"{rfc_id} revision {revision} requires supersedes lineage")
        if supersedes.get("revision") != revision - 1:
            raise RegistryError(f"{rfc_id}.supersedes.revision must be {revision - 1}")
        predecessor = supersedes.get("revision_digest")
        if not isinstance(predecessor, str) or not SHA256_RE.fullmatch(predecessor):
            raise RegistryError(f"{rfc_id}.supersedes.revision_digest is invalid")
    digest = value.get("revision_digest")
    expected_digest = content_digest(revision_payload(value))
    if digest != expected_digest:
        raise RegistryError(
            f"{rfc_id}.revision_digest mismatch: expected {expected_digest}"
        )
    sources = tuple(
        normalized_relative_path(item, f"{rfc_id}.python_sources")
        for item in string_list(
            value.get("python_sources"), f"{rfc_id}.python_sources", non_empty=False
        )
    )
    if not sources and not value.get("source_coverage_exempt_reason"):
        raise RegistryError(
            f"{rfc_id} has no in-scope sources and requires source_coverage_exempt_reason"
        )
    source_digest = value.get("source_files_sha256")
    if source_digest is not None and source_digest != content_digest(list(sources)):
        raise RegistryError(f"{rfc_id}.source_files_sha256 mismatch")
    config_sources = tuple(
        normalized_relative_path(item, f"{rfc_id}.config_sources")
        for item in string_list(
            value.get("config_sources", []),
            f"{rfc_id}.config_sources",
            non_empty=False,
        )
    )
    targets = tuple(
        normalized_relative_path(item, f"{rfc_id}.target_files")
        for item in string_list(value.get("target_files"), f"{rfc_id}.target_files")
    )
    target_prefixes = tuple(
        normalized_relative_path(item, f"{rfc_id}.target_prefixes")
        for item in string_list(
            value.get("target_prefixes", []),
            f"{rfc_id}.target_prefixes",
            non_empty=False,
        )
    )
    shared_change_requests_value = value.get("shared_change_requests", {})
    if not isinstance(shared_change_requests_value, dict):
        raise RegistryError(f"{rfc_id}.shared_change_requests must be an object")
    shared_change_requests = {
        str(name): normalized_relative_path(
            path, f"{rfc_id}.shared_change_requests.{name}"
        )
        for name, path in shared_change_requests_value.items()
        if isinstance(name, str) and name.strip()
    }
    if len(shared_change_requests) != len(shared_change_requests_value):
        raise RegistryError(
            f"{rfc_id}.shared_change_requests contains an invalid resource name"
        )
    source_targets_value = value.get("source_targets")
    if not isinstance(source_targets_value, dict):
        raise RegistryError(f"{rfc_id}.source_targets must be an object")
    source_targets: dict[str, str] = {}
    for source, target in source_targets_value.items():
        normalized_source = normalized_relative_path(source, f"{rfc_id}.source_targets")
        normalized_target = normalized_relative_path(target, f"{rfc_id}.source_targets")
        source_targets[normalized_source] = normalized_target
    if set(source_targets) != set(sources):
        missing = sorted(set(sources) - set(source_targets))
        extra = sorted(set(source_targets) - set(sources))
        raise RegistryError(
            f"{rfc_id}.source_targets must map every owned source exactly once; "
            f"missing={missing[:10]}, extra={extra[:10]}"
        )
    undeclared_targets = sorted(set(source_targets.values()) - set(targets))
    if undeclared_targets:
        raise RegistryError(
            f"{rfc_id}.source_targets references undeclared targets: {undeclared_targets[:10]}"
        )
    config_targets_value = value.get("config_targets", {})
    if not isinstance(config_targets_value, dict):
        raise RegistryError(f"{rfc_id}.config_targets must be an object")
    config_targets: dict[str, str] = {}
    for source, target in config_targets_value.items():
        normalized_source = normalized_relative_path(source, f"{rfc_id}.config_targets")
        normalized_target = normalized_relative_path(target, f"{rfc_id}.config_targets")
        config_targets[normalized_source] = normalized_target
    if set(config_targets) != set(config_sources):
        missing = sorted(set(config_sources) - set(config_targets))
        extra = sorted(set(config_targets) - set(config_sources))
        raise RegistryError(
            f"{rfc_id}.config_targets must map every config source exactly once; "
            f"missing={missing[:10]}, extra={extra[:10]}"
        )
    undeclared_config_targets = sorted(set(config_targets.values()) - set(targets))
    if undeclared_config_targets:
        raise RegistryError(
            f"{rfc_id}.config_targets references undeclared targets: "
            f"{undeclared_config_targets[:10]}"
        )
    lock_keys = string_list(
        value.get("lock_keys"), f"{rfc_id}.lock_keys"
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
    definitions = contracts.get("definitions")
    if not isinstance(definitions, dict):
        raise RegistryError(f"{rfc_id}.contracts.definitions must be an object")
    if set(definitions) != set(provides):
        raise RegistryError(
            f"{rfc_id}.contracts.definitions must exactly match provided contracts"
        )
    for name, definition in definitions.items():
        if content_digest(definition) != provides[name]:
            raise RegistryError(
                f"{rfc_id}.contracts.definitions.{name} does not match its hash"
            )
    tests = value.get("tests")
    if not isinstance(tests, dict):
        raise RegistryError(f"{rfc_id}.tests must be an object")
    for level in REQUIRED_TEST_LEVELS:
        if level not in tests:
            raise RegistryError(f"{rfc_id}.tests.{level} is required")
    level1 = string_list(tests["level1"], f"{rfc_id}.tests.level1")
    level2 = string_list(tests["level2"], f"{rfc_id}.tests.level2")
    level3 = string_list(
        tests.get("level3", []), f"{rfc_id}.tests.level3", non_empty=False
    )
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
        config_sources=config_sources,
        target_files=targets,
        target_prefixes=target_prefixes,
        source_targets=source_targets,
        config_targets=config_targets,
        shared_change_requests=shared_change_requests,
        lock_keys=lock_keys,
        depends_on=dependencies,
        provides=provides,
        requires=requires,
        contract_definitions=dict(definitions),
        level1_tests=level1,
        level2_tests=level2,
        level3_tests=level3,
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


def _validate_target_ownership(rfcs: Iterable[RfcRevision]) -> None:
    values = list(rfcs)
    _validate_unique_ownership(values, "target_files")
    _validate_unique_ownership(values, "target_prefixes")
    owners: list[tuple[str, bool, str]] = []
    for rfc in values:
        owners.extend((path, False, rfc.rfc_id) for path in rfc.target_files)
        owners.extend((path, True, rfc.rfc_id) for path in rfc.target_prefixes)
    for index, (path, is_prefix, owner) in enumerate(owners):
        for other_path, other_is_prefix, other_owner in owners[index + 1 :]:
            if owner == other_owner:
                continue
            overlaps = (
                path == other_path
                or (is_prefix and other_path.startswith(path + "/"))
                or (other_is_prefix and path.startswith(other_path + "/"))
            )
            if overlaps:
                raise RegistryError(
                    "target ownership collision for "
                    f"{path} and {other_path}: {owner} and {other_owner}"
                )


def _parse_shared_resources(value: object) -> dict[str, SharedResource]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not value:
        raise RegistryError("shared_resources must be a non-empty object when present")
    resources: dict[str, SharedResource] = {}
    owned_files: dict[str, str] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(raw, dict):
            raise RegistryError("shared_resources contains an invalid entry")
        files = tuple(
            normalized_relative_path(item, f"shared_resources.{name}.files")
            for item in string_list(raw.get("files"), f"shared_resources.{name}.files")
        )
        writer = raw.get("writer")
        template = raw.get("request_template")
        request_owner = raw.get("request_owner")
        application_stage = raw.get("application_stage")
        if not isinstance(writer, str) or not writer.strip():
            raise RegistryError(f"shared_resources.{name}.writer must be non-empty")
        if not isinstance(template, str) or template.count("{rfc_id}") != 1:
            raise RegistryError(
                f"shared_resources.{name}.request_template must contain one {{rfc_id}}"
            )
        if request_owner not in {"coder", "control-plane"}:
            raise RegistryError(
                f"shared_resources.{name}.request_owner must be coder or control-plane"
            )
        if application_stage not in {"before-level1", "after-level3"}:
            raise RegistryError(
                f"shared_resources.{name}.application_stage is invalid"
            )
        if request_owner == "coder" and application_stage != "before-level1":
            raise RegistryError(f"Coder request {name} must be applied before Level 1")
        if request_owner == "control-plane" and application_stage != "after-level3":
            raise RegistryError(f"control-plane request {name} must be produced after Level 3")
        normalized_relative_path(
            template.replace("{rfc_id}", "RFC-20000101-001"),
            f"shared_resources.{name}.request_template",
        )
        for path in files:
            previous = owned_files.get(path)
            if previous:
                raise RegistryError(
                    f"shared resource file {path} is declared by {previous} and {name}"
                )
            owned_files[path] = name
        resources[name] = SharedResource(
            name,
            files,
            writer.strip(),
            template,
            request_owner,
            application_stage,
        )
    return resources


def _validate_shared_resources(
    resources: dict[str, SharedResource], rfcs: Iterable[RfcRevision]
) -> None:
    if not resources:
        for rfc in rfcs:
            if rfc.shared_change_requests:
                raise RegistryError(
                    f"{rfc.rfc_id} declares requests without shared_resources"
                )
        return
    shared_files = {path for resource in resources.values() for path in resource.files}
    for rfc in rfcs:
        if set(rfc.shared_change_requests) != set(resources):
            raise RegistryError(
                f"{rfc.rfc_id}.shared_change_requests must exactly name all shared resources"
            )
        for name, resource in resources.items():
            expected = resource.request_template.replace("{rfc_id}", rfc.rfc_id)
            if rfc.shared_change_requests[name] != expected:
                raise RegistryError(
                    f"{rfc.rfc_id}.shared_change_requests.{name} must be {expected}"
                )
        direct = sorted(shared_files.intersection(rfc.target_files))
        if direct:
            raise RegistryError(
                f"{rfc.rfc_id} directly owns broker-managed shared files: {direct}"
            )
        prefixed = sorted(
            path
            for path in shared_files
            if any(path == prefix or path.startswith(prefix + "/") for prefix in rfc.target_prefixes)
        )
        if prefixed:
            raise RegistryError(
                f"{rfc.rfc_id} target prefix captures broker-managed shared files: {prefixed}"
            )
        for name, request in rfc.shared_change_requests.items():
            resource = resources[name]
            is_owned = request in rfc.target_files
            if resource.request_owner == "coder" and not is_owned:
                raise RegistryError(f"{rfc.rfc_id} must own Coder request {request}")
            if resource.request_owner == "control-plane" and is_owned:
                raise RegistryError(
                    f"{rfc.rfc_id} cannot own control-plane request {request}"
                )


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


def _validate_interface_artifacts(path: Path, rfcs: Iterable[RfcRevision]) -> None:
    parent = path.resolve().parent
    repository = parent.parent if parent.name == "coordination" else parent
    for rfc in rfcs:
        artifact_value = rfc.raw.get("interface_artifact")
        artifact_digest = rfc.raw.get("interface_artifact_sha256")
        if artifact_value is None and artifact_digest is None:
            continue
        artifact_path = normalized_relative_path(
            artifact_value, f"{rfc.rfc_id}.interface_artifact"
        )
        if not isinstance(artifact_digest, str) or not SHA256_RE.fullmatch(artifact_digest):
            raise RegistryError(f"{rfc.rfc_id}.interface_artifact_sha256 is invalid")
        resolved = (repository / artifact_path).resolve()
        try:
            resolved.relative_to(repository)
        except ValueError as exc:
            raise RegistryError(f"{rfc.rfc_id}.interface_artifact escapes repository") from exc
        try:
            artifact = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(
                f"cannot load {rfc.rfc_id} interface artifact {artifact_path}: {exc}"
            ) from exc
        if content_digest(artifact) != artifact_digest:
            raise RegistryError(f"{rfc.rfc_id} interface artifact digest mismatch")
        if not isinstance(artifact, dict):
            raise RegistryError(f"{rfc.rfc_id} interface artifact must be an object")
        if artifact.get("owner") != rfc.rfc_id or artifact.get("revision") != rfc.revision:
            raise RegistryError(f"{rfc.rfc_id} interface artifact identity mismatch")
        for name, definition in rfc.contract_definitions.items():
            if not isinstance(definition, dict):
                raise RegistryError(f"{rfc.rfc_id} contract {name} definition is invalid")
            if (
                definition.get("interfaceArtifact") != artifact_path
                or definition.get("interfaceArtifactSha256") != artifact_digest
            ):
                raise RegistryError(
                    f"{rfc.rfc_id} contract {name} does not bind its interface artifact"
                )


def load_registry(path: Path, classification_path: Path | None = None) -> Registry:
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
    tree = baseline.get("tree")
    classification = baseline.get("classification_sha256")
    count = baseline.get("in_scope_count")
    config_count = baseline.get("config_data_count")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise RegistryError("baseline.commit must be a full Git SHA")
    if tree is not None and (not isinstance(tree, str) or not COMMIT_RE.fullmatch(tree)):
        raise RegistryError("baseline.tree must be a full Git SHA")
    if not isinstance(classification, str) or not SHA256_RE.fullmatch(classification):
        raise RegistryError("baseline.classification_sha256 must be a sha256 digest")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise RegistryError("baseline.in_scope_count must be a positive integer")
    if not isinstance(config_count, int) or isinstance(config_count, bool) or config_count < 0:
        raise RegistryError("baseline.config_data_count must be a non-negative integer")
    values = document.get("rfcs")
    if not isinstance(values, list) or not values:
        raise RegistryError("rfcs must be a non-empty list")
    parsed = [_parse_rfc(value, index) for index, value in enumerate(values)]
    shared_resources = _parse_shared_resources(document.get("shared_resources"))
    frozen_control_paths = tuple(
        normalized_relative_path(item, "frozen_control_paths")
        for item in string_list(
            document.get("frozen_control_paths", []),
            "frozen_control_paths",
            non_empty=False,
        )
    )
    rfcs = {rfc.rfc_id: rfc for rfc in parsed}
    if len(rfcs) != len(parsed):
        raise RegistryError("RFC IDs must be unique")
    order = _topological_order(rfcs)
    _validate_unique_ownership(parsed, "python_sources")
    _validate_unique_ownership(parsed, "config_sources")
    _validate_target_ownership(parsed)
    _validate_shared_resources(shared_resources, parsed)
    for rfc in parsed:
        captured = sorted(
            frozen
            for frozen in frozen_control_paths
            if any(
                frozen == target
                or target.startswith(frozen + "/")
                or frozen.startswith(target + "/")
                for target in rfc.target_files
            )
            or any(
                frozen == prefix
                or frozen.startswith(prefix + "/")
                or prefix.startswith(frozen + "/")
                for prefix in rfc.target_prefixes
            )
        )
        if captured:
            raise RegistryError(
                f"{rfc.rfc_id} captures frozen control paths: {captured}"
            )
    registry = Registry(
        schema_version=1,
        baseline_commit=commit,
        classification_sha256=classification,
        in_scope_count=count,
        config_data_count=config_count,
        baseline_tree=tree,
        base_delivery_rfc=None,
        base_delivery_commit=None,
        shared_resources=shared_resources,
        frozen_control_paths=frozen_control_paths,
        rfcs=rfcs,
        topological_order=order,
        digest=content_digest(document),
    )
    base_delivery = document.get("base_delivery")
    if base_delivery is not None:
        if not isinstance(base_delivery, dict):
            raise RegistryError("base_delivery must be an object")
        base_rfc = base_delivery.get("rfc")
        base_commit = base_delivery.get("commit")
        if not isinstance(base_rfc, str) or not RFC_ID_RE.fullmatch(base_rfc):
            raise RegistryError("base_delivery.rfc is invalid")
        if not isinstance(base_commit, str) or not COMMIT_RE.fullmatch(base_commit):
            raise RegistryError("base_delivery.commit must be a full Git SHA")
        if base_delivery.get("required_merge_state") != "merged":
            raise RegistryError("base_delivery.required_merge_state must be merged")
        object.__setattr__(registry, "base_delivery_rfc", base_rfc)
        object.__setattr__(registry, "base_delivery_commit", base_commit)
    _validate_contracts(registry)
    _validate_interface_artifacts(path, parsed)
    if classification_path is not None:
        validate_exact_partition(registry, classification_path)
    return registry


def validate_exact_partition(registry: Registry, classification_path: Path) -> None:
    try:
        content = classification_path.read_bytes()
        classification = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot load classification {classification_path}: {exc}") from exc
    actual_digest = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual_digest != registry.classification_sha256:
        raise RegistryError(
            f"classification digest mismatch: expected {registry.classification_sha256}, got {actual_digest}"
        )
    if not isinstance(classification, list):
        raise RegistryError("classification root must be a list")
    expected: set[str] = set()
    expected_config: set[str] = set()
    for index, entry in enumerate(classification):
        if not isinstance(entry, dict):
            raise RegistryError(f"classification[{index}] must be an object")
        if entry.get("disposition") == "in_scope":
            expected.add(normalized_relative_path(entry.get("path"), "classification.path"))
        elif entry.get("disposition") == "config_data":
            expected_config.add(
                normalized_relative_path(entry.get("path"), "classification.path")
            )
    actual = {path for rfc in registry.rfcs.values() for path in rfc.python_sources}
    actual_config = {
        path for rfc in registry.rfcs.values() for path in rfc.config_sources
    }
    if len(expected) != registry.in_scope_count:
        raise RegistryError(
            f"classification contains {len(expected)} in-scope paths, expected {registry.in_scope_count}"
        )
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise RegistryError(
            f"RFC source partition mismatch; missing={missing[:10]}, extra={extra[:10]}"
        )
    if len(expected_config) != registry.config_data_count:
        raise RegistryError(
            f"classification contains {len(expected_config)} config-data paths, "
            f"expected {registry.config_data_count}"
        )
    if actual_config != expected_config:
        missing = sorted(expected_config - actual_config)
        extra = sorted(actual_config - expected_config)
        raise RegistryError(
            f"RFC config-data partition mismatch; missing={missing[:10]}, extra={extra[:10]}"
        )


def with_revision_digest(value: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with its canonical revision digest populated."""
    result = dict(value)
    result["revision_digest"] = content_digest(revision_payload(result))
    return result
