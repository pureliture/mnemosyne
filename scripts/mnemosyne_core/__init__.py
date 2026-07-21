"""Verified source-only package boundary for the Mnemosyne CLI core."""

from __future__ import annotations


__all__ = ["execute_request_bytes"]


def __getattr__(name: str):
    """Expose the CLI entry point without eagerly composing its catalog.

    The verified bootstrap imports individual core modules before it installs
    ``_verified_source_manifest`` on this package.  Importing execution here
    would compose the catalog too early, so defer it until a caller actually
    asks for the public entry point.
    """

    if name != "execute_request_bytes":
        raise AttributeError(name)
    from .operation_control.execution import execute_request_bytes

    return execute_request_bytes
