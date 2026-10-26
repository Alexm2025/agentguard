from __future__ import annotations

from typing import Any


class Proxy:
    """Attribute proxy that overrides selected attributes of a wrapped object."""

    def __init__(self, target: Any, **overrides: Any) -> None:
        object.__setattr__(self, "_ag_target", target)
        object.__setattr__(self, "_ag_overrides", overrides)

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_ag_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_ag_target"), name)

    def __repr__(self) -> str:
        return f"<AgentGuard {object.__getattribute__(self, '_ag_target')!r}>"


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True, mode="json")
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_dict(v) for v in obj]
    return obj


def rebuild(obj: Any, data: dict[str, Any]) -> Any:
    cls = type(obj)
    if hasattr(cls, "model_validate"):
        return cls.model_validate(data)
    return data
