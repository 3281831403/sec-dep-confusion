"""Dependency resolution helpers for a two-index package setup.

The module works with three plain data structures:

* a requirement is either a string such as ``corp.pay.gateway>=1.0,<2.0`` or a
  mapping with ``name``, ``spec`` and ``source`` keys;
* a source is a mapping with ``url``, ``internal``, ``packages`` (a mapping of
  package name to a list of versions) and, for internal sources, ``namespaces``;
* a lockfile is a mapping of package name to an exact version.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

__all__ = [
    "parse_requirement",
    "namespace_of",
    "source_allowed",
    "resolve",
    "detect_shadowing",
    "validate_policy",
    "record_provenance",
    "resolve_batch",
]


_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<spec>.*)$")
_SPEC_RE = re.compile(
    r"^(?:==|!=|>=|<=|>|<)\s*[0-9][0-9A-Za-z.*+!-]*"
    r"(?:\s*,\s*(?:==|!=|>=|<=|>|<)\s*[0-9][0-9A-Za-z.*+!-]*)*$"
)


def parse_requirement(text):
    """Parse a requirement string into its name, version spec and source."""
    if not isinstance(text, str):
        raise TypeError("requirement must be a string")
    raw = text.strip()
    if not raw:
        raise ValueError("empty requirement")

    source = None
    if " @ " in raw:
        raw, source = raw.split(" @ ", 1)
        raw = raw.strip()
        source = source.strip()
        if not source:
            raise ValueError("missing source after @")

    match = _NAME_RE.match(raw)
    if match is None:
        raise ValueError("invalid requirement: %r" % text)

    name = match.group("name")
    spec = match.group("spec").strip()
    if spec and _SPEC_RE.match(spec) is None:
        raise ValueError("invalid version spec: %r" % text)
    return {"name": name, "spec": spec or "*", "source": source}


def namespace_of(name):
    """Return the namespace prefix of a package name, split on dots."""
    if not isinstance(name, str):
        raise TypeError("name must be a string")
    parts = [part for part in name.strip().split(".") if part]
    if len(parts) < 2:
        return ""
    return ".".join(parts[:-1])


def _normalize_name(name):
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def _name_in_prefix(name, prefix):
    name_parts = [part for part in str(name).lower().split(".") if part]
    prefix_parts = [part for part in str(prefix).lower().split(".") if part]
    if not prefix_parts or len(name_parts) < len(prefix_parts):
        return False
    return name_parts[: len(prefix_parts)] == prefix_parts


def _has_internal_namespace(name, policy):
    prefixes = (policy or {}).get("internal_prefixes") or []
    namespace = namespace_of(name).lower()
    for prefix in prefixes:
        if namespace.startswith(str(prefix).strip().lower()):
            return True
    return False


def _is_internal_source(source, policy):
    allowed = (policy or {}).get("internal_sources") or []
    host = (urlsplit(str(source)).hostname or "").lower()
    for entry in allowed:
        allowed_host = (urlsplit(str(entry)).hostname or "").lower()
        if allowed_host and host.endswith(allowed_host):
            return True
    return False


def source_allowed(name, source, policy):
    """Return True when the source may serve the named package."""
    if not source:
        return False
    if not _has_internal_namespace(name, policy):
        return True
    return _is_internal_source(source, policy)


def _compare_versions(left, right):
    left_text = str(left)
    right_text = str(right)
    if left_text == right_text:
        return 0
    return -1 if left_text < right_text else 1


def _satisfies(version, spec):
    if spec in (None, "", "*"):
        return True
    for clause in str(spec).split(","):
        clause = clause.strip()
        if not clause:
            continue
        operator = None
        for candidate in ("==", "!=", ">=", "<=", ">", "<"):
            if clause.startswith(candidate):
                operator = candidate
                break
        if operator is None:
            if _compare_versions(version, clause) != 0:
                return False
            continue
        target = clause[len(operator) :].strip()
        comparison = _compare_versions(version, target)
        accepted = {
            "==": comparison == 0,
            "!=": comparison != 0,
            ">=": comparison >= 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            "<": comparison < 0,
        }[operator]
        if not accepted:
            return False
    return True


def _best_version(versions, spec):
    candidates = [version for version in versions if _satisfies(version, spec)]
    if not candidates:
        return None
    best = candidates[0]
    for version in candidates[1:]:
        if _compare_versions(version, best) > 0:
            best = version
    return best


def _ordered_sources(sources):
    return sorted(
        sources or [],
        key=lambda item: (0 if item.get("internal") else 1, str(item.get("url") or "")),
    )


def _source_versions(source, name):
    target = _normalize_name(name)
    for package, versions in (source.get("packages") or {}).items():
        if _normalize_name(package) == target:
            return [str(version) for version in versions]
    return []


def _internal_prefixes(sources):
    prefixes = []
    for source in sources:
        if source.get("internal"):
            prefixes.extend(source.get("namespaces") or [])
    return prefixes


def resolve(requirements, sources, lockfile):
    """Resolve requirements, preferring locked versions and internal sources."""
    ordered = _ordered_sources(sources)
    prefixes = _internal_prefixes(ordered)
    locks = {}
    for name, version in (lockfile or {}).items():
        locks[_normalize_name(name)] = str(version)

    packages = {}
    errors = []
    for requirement in requirements or []:
        parsed = (
            parse_requirement(requirement)
            if isinstance(requirement, str)
            else dict(requirement)
        )
        name = parsed["name"]
        spec = parsed.get("spec") or "*"
        internal = any(_name_in_prefix(name, prefix) for prefix in prefixes)

        locked = locks.get(_normalize_name(name))
        if locked is not None and spec in ("", "*"):
            target = locked
        else:
            target = None

        candidate_sources = [
            source for source in ordered if not internal or source.get("internal")
        ]
        available = []
        for source in candidate_sources:
            versions = _source_versions(source, name)
            if versions:
                available.append((source, versions))

        if internal and not available:
            for source in ordered:
                if source.get("internal"):
                    continue
                versions = _source_versions(source, name)
                if versions:
                    available.append((source, versions))

        if target is None:
            all_versions = []
            for _, versions in available:
                all_versions.extend(versions)
            target = _best_version(all_versions, spec)

        if target is None:
            errors.append(
                {
                    "name": name,
                    "reason": "no available version satisfies %s" % spec,
                }
            )
            continue

        chosen = None
        for source, versions in available:
            if any(str(version) == str(target) for version in versions):
                chosen = source
                break

        if chosen is None:
            errors.append(
                {
                    "name": name,
                    "reason": "version %s is not available from an allowed source" % target,
                }
            )
            continue

        packages[name] = {
            "version": str(target),
            "source": str(chosen.get("url")),
            "sources": [str(source.get("url")) for source in ordered],
        }

    return {"packages": packages, "errors": errors, "ok": not errors}


def detect_shadowing(requirements, public_index):
    """Report requirements whose package name also exists on the public index."""
    findings = []
    index = dict(public_index or {})
    for requirement in requirements or []:
        parsed = (
            parse_requirement(requirement)
            if isinstance(requirement, str)
            else dict(requirement)
        )
        name = parsed.get("name") or ""
        spec = parsed.get("spec") or "*"
        pinned = None
        if isinstance(spec, str) and spec.startswith("=="):
            pinned = spec[2:].strip()

        for public_name, public_version in index.items():
            if name != public_name:
                continue
            if pinned != str(public_version):
                continue
            findings.append(
                {
                    "name": public_name,
                    "version": str(public_version),
                    "requirement": name,
                    "reason": "same package name is published on the public index",
                }
            )
    return findings


def validate_policy(policy):
    """Return a list of problems found in a dependency policy."""
    policy = policy or {}
    problems = []
    if not policy.get("internal_prefixes"):
        problems.append("no internal namespace prefixes are configured")
    if not policy.get("lockfile"):
        problems.append("no lockfile is configured")
    return problems


def record_provenance(resolved):
    """Return the final source and the full source trail for each package."""
    packages = (resolved or {}).get("packages") or {}
    provenance = {}
    for name, entry in packages.items():
        history = [str(item) for item in entry.get("sources") or []]
        if not history and entry.get("source"):
            history = [str(entry["source"])]
        provenance[name] = {
            "final": entry.get("source"),
            "sources": history[-1:],
        }
    return provenance


def resolve_batch(sets, policy):
    """Resolve several requirement sets and return one result per set."""
    results = {}
    shared = None
    for index, item in enumerate(sets or []):
        key = item.get("name") or "set-%d" % index
        if shared is None:
            lockfile = item.get("lockfile")
            if lockfile is None:
                lockfile = (policy or {}).get("lockfile") or {}
            shared = resolve(
                item.get("requirements") or [],
                item.get("sources") or [],
                lockfile,
            )
        results[key] = shared
    return results