from __future__ import annotations

from collections.abc import Iterable

from .contracts import ResourceProfile


class ResourceCatalog:
    """Immutable, server-constructed snapshot of known execution resources."""

    def __init__(self, profiles: Iterable[ResourceProfile]) -> None:
        supplied = tuple(profiles)
        for profile in supplied:
            ResourceProfile.model_validate(profile.model_dump(mode="python"))
        ordered = tuple(sorted(supplied, key=lambda item: item.runner_profile_id))
        identifiers = tuple(item.runner_profile_id for item in ordered)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("resource catalog profile ids must be unique")
        self._profiles = ordered
        self._by_id = {item.runner_profile_id: item for item in ordered}

    def snapshot(self) -> tuple[ResourceProfile, ...]:
        return self._profiles

    def enabled_profiles(self) -> tuple[ResourceProfile, ...]:
        return tuple(item for item in self._profiles if item.enabled)

    def get(self, runner_profile_id: str) -> ResourceProfile:
        return self._by_id[runner_profile_id]
