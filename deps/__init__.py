"""Dependency confusion checks and resolution."""

from .api import (
    detect_shadowing,
    namespace_of,
    parse_requirement,
    record_provenance,
    resolve,
    resolve_batch,
    source_allowed,
    validate_policy,
)

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