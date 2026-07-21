"""Exact schema compatibility predicates for sealed D1a artifacts."""

from __future__ import annotations

from . import SchemaIdentity


def is_compatible(required: SchemaIdentity, observed: SchemaIdentity) -> bool:
    """Compatibility is exact: no implicit kind, version, or hash widening."""

    if type(required) is not SchemaIdentity or type(observed) is not SchemaIdentity:
        raise TypeError("schema identities are required")
    return required == observed
