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
    # Match on dot-separated segments: the package name must equal the
    # prefix or extend it with further segments.  A plain string prefix
    # test would wrongly accept e.g. "corp.payments" for prefix "corp.pay".
    prefixes = (policy or {}).get("internal_prefixes") or []
    return any(_name_in_prefix(name, prefix) for prefix in prefixes)


def _source_url(source):
    """Return the URL for a source given as a string or a source mapping."""
    if isinstance(source, dict):
        return str(source.get("url") or "").strip()
    return str(source or "").strip()


def _is_internal_source(source, policy):
    # Exact address match only.  Hostname suffix matching would accept
    # look-alikes such as "https://evilcorp.example/simple" for the allowed
    # "https://corp.example/simple", and would ignore scheme/path entirely.
    allowed = (policy or {}).get("internal_sources") or []
    candidate = _source_url(source)
    if not candidate:
        return False
    for entry in allowed:
        if candidate == str(entry).strip():
            return True
    return False


def source_allowed(name, source, policy):
    """Return True when the source may serve the named package."""
    if not source:
        return False
    if not _has_internal_namespace(name, policy):
        return True
    return _is_internal_source(source, policy)


_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _version_key(version):
    """Build a total-order key that compares numeric runs as integers.

    Plain lexicographic comparison would order ``1.10.0`` below ``1.9.0``.
    Each token is tagged with its type so int and str values are never
    compared against each other, keeping the key total for arbitrary input.
    """
    tokens = _VERSION_TOKEN_RE.findall(str(version))
    key = []
    for token in tokens:
        if token.isdigit():
            key.append((1, int(token)))
        else:
            key.append((0, token.lower()))
    if not key:
        key.append((1, 0))
    return tuple(key)


def _compare_versions(left, right):
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key == right_key:
        return 0
    return -1 if left_key < right_key else 1


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
    # Internal sources first, then a stable URL order.  The final repr
    # tie-break makes the ordering total even for equal-URL entries, so the
    # conclusion never depends on the caller's source-list order.
    return sorted(
        list(sources or []),
        key=lambda item: (
            0 if item.get("internal") else 1,
            str(item.get("url") or ""),
            repr(item),
        ),
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


def _source_matches_policy(source, policy):
    """Whether an internal-flagged source is also allowed by ``policy``.

    When the policy pins an explicit ``internal_sources`` address list it
    must match exactly; otherwise the source's own ``internal`` marker is
    authoritative.
    """
    if not source.get("internal"):
        return False
    allowed = (policy or {}).get("internal_sources")
    if allowed:
        return _is_internal_source(source.get("url"), policy)
    return True


def resolve(requirements, sources, lockfile, policy=None):
    """Resolve requirements, preferring locked versions and internal sources."""
    ordered = _ordered_sources(sources)
    prefixes = _internal_prefixes(ordered)
    for prefix in (policy or {}).get("internal_prefixes") or []:
        if prefix not in prefixes:
            prefixes.append(prefix)

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

        # A lockfile is an exact pin and takes precedence over a floating
        # version range.
        locked = locks.get(_normalize_name(name))
        target = str(locked) if locked is not None else None

        # Internal names may only be served by internal sources.  There is
        # deliberately no fallback to public sources, even when the internal
        # index does not carry the requested version.
        if internal:
            candidate_sources = [
                source
                for source in ordered
                if _source_matches_policy(source, policy)
            ]
        else:
            candidate_sources = list(ordered)

        available = []
        for source in candidate_sources:
            versions = _source_versions(source, name)
            if versions:
                available.append((source, versions))

        # Same-named packages on disallowed/public sources are dependency
        # confusion shadows.  They are never selected, but recorded so the
        # failure can be reported with the offending addresses.
        allowed_ids = {id(source) for source in candidate_sources}
        shadow_sources = [
            source
            for source in ordered
            if id(source) not in allowed_ids and _source_versions(source, name)
        ]
        shadow_urls = [str(source.get("url")) for source in shadow_sources]

        if target is None:
            all_versions = []
            for _, versions in available:
                all_versions.extend(versions)
            target = _best_version(all_versions, spec)

        if target is None:
            reason = "no available version satisfies %s" % spec
            if internal and shadow_urls:
                reason += (
                    "; internal package must be resolved from an internal "
                    "source; same-name package on public source(s) was "
                    "rejected as a dependency-confusion shadow: %s"
                    % ", ".join(shadow_urls)
                )
            errors.append({"name": name, "reason": reason})
            continue

        chosen = None
        for source, versions in available:
            if any(str(version) == str(target) for version in versions):
                chosen = source
                break

        if chosen is None:
            reason = "version %s is not available from an allowed source" % target
            if internal and shadow_urls:
                reason += (
                    "; same-name package on public source(s) was rejected as "
                    "a dependency-confusion shadow: %s" % ", ".join(shadow_urls)
                )
            errors.append({"name": name, "reason": reason})
            continue

        packages[name] = {
            "version": str(target),
            "source": str(chosen.get("url")),
            "sources": [str(source.get("url")) for source in ordered],
        }

    return {"packages": packages, "errors": errors, "ok": not errors}


def detect_shadowing(requirements, public_index):
    """Report requirements whose package name also exists on the public index.

    Name comparison follows normalized package-name identity
    (case-/separator-insensitive).  A finding is emitted for every public
    version published under a matching name, regardless of whether the
    requirement's pin happens to equal that version: a higher or lower
    public version is still a squatter occupying the same namespace.
    """
    findings = []

    entries = []
    for public_name, public_value in (public_index or {}).items():
        if isinstance(public_value, (list, tuple, set, frozenset)):
            public_versions = [str(version) for version in public_value]
            public_versions.sort(key=lambda value: (_version_key(value), value))
        else:
            public_versions = [str(public_value)]
        entries.append(
            (_normalize_name(public_name), str(public_name), public_versions)
        )
    entries.sort(key=lambda entry: (entry[0], entry[1]))

    for requirement in requirements or []:
        parsed = (
            parse_requirement(requirement)
            if isinstance(requirement, str)
            else dict(requirement)
        )
        name = parsed.get("name") or ""
        target_name = _normalize_name(name)

        for _normalized, public_name, public_versions in entries:
            if target_name != _normalized:
                continue
            for public_version in public_versions:
                findings.append(
                    {
                        "name": public_name,
                        "version": public_version,
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
    if policy.get("allow_public_fallback"):
        problems.append(
            "public fallback is enabled; internal packages must resolve only "
            "from internal sources (allow_public_fallback must be false)"
        )
    return problems


def record_provenance(resolved):
    """Return the final source and the full source trail for each package."""
    packages = (resolved or {}).get("packages") or {}
    provenance = {}
    for name, entry in packages.items():
        entry = entry or {}
        final = entry.get("source")
        history = [str(item) for item in entry.get("sources") or []]
        if not history and final:
            history = [str(final)]
        provenance[name] = {
            "final": final,
            "sources": history,
        }
    return provenance


def resolve_batch(sets, policy):
    """Resolve several requirement sets and return one result per set.

    Every set is resolved independently with its own requirements, sources
    and lockfile; results are never shared or cached across sets.
    """
    results = {}
    for index, item in enumerate(sets or []):
        key = item.get("name") or "set-%d" % index
        lockfile = item.get("lockfile")
        if lockfile is None:
            lockfile = (policy or {}).get("lockfile") or {}
        results[key] = resolve(
            item.get("requirements") or [],
            item.get("sources") or [],
            lockfile,
            policy,
        )
    return results