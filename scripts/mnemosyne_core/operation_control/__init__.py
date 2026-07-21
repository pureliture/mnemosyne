"""Private operation-control namespace."""

from __future__ import annotations


__all__ = [
    "OperationAvailability",
    "OperationSpec",
    "OperationCatalog",
    "execute_request_bytes",
]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(name)
    if name == "execute_request_bytes":
        from .execution import execute_request_bytes

        return execute_request_bytes
    from . import catalog

    return getattr(catalog, name)
