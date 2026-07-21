from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class LoadProfile:
    name: str
    duration_sec: int
    events_per_sec: int
    flows: int
    websocket_clients: int
    expected_target: str

    def with_overrides(
        self,
        *,
        duration_sec: float | None = None,
        events_per_sec: int | None = None,
        flows: int | None = None,
        websocket_clients: int | None = None,
        ci_safe: bool = False,
    ) -> "LoadProfile":
        profile = replace(
            self,
            duration_sec=(
                int(duration_sec)
                if duration_sec is not None
                else int(self.duration_sec)
            ),
            events_per_sec=(
                int(events_per_sec)
                if events_per_sec is not None
                else int(self.events_per_sec)
            ),
            flows=int(flows) if flows is not None else int(self.flows),
            websocket_clients=(
                int(websocket_clients)
                if websocket_clients is not None
                else int(self.websocket_clients)
            ),
        )
        if not ci_safe:
            return profile
        return replace(
            profile,
            duration_sec=max(1, min(profile.duration_sec, 10)),
            events_per_sec=max(1, min(profile.events_per_sec, 200)),
            flows=max(1, min(profile.flows, 25)),
            websocket_clients=max(1, min(profile.websocket_clients, 2)),
        )


LOAD_PROFILES: dict[str, LoadProfile] = {
    "light_desktop": LoadProfile(
        name="light_desktop",
        duration_sec=5 * 60,
        events_per_sec=100,
        flows=20,
        websocket_clients=1,
        expected_target="very low pressure",
    ),
    "normal_desktop": LoadProfile(
        name="normal_desktop",
        duration_sec=15 * 60,
        events_per_sec=250,
        flows=75,
        websocket_clients=2,
        expected_target="stable CPU/RAM with no unbounded growth",
    ),
    "heavy_desktop": LoadProfile(
        name="heavy_desktop",
        duration_sec=30 * 60,
        events_per_sec=500,
        flows=150,
        websocket_clients=3,
        expected_target="bounded pressure allowed, no crash or unbounded memory",
    ),
    "server_medium": LoadProfile(
        name="server_medium",
        duration_sec=60 * 60,
        events_per_sec=1000,
        flows=300,
        websocket_clients=5,
        expected_target="stable under server-like pressure",
    ),
    "stress_short": LoadProfile(
        name="stress_short",
        duration_sec=5 * 60,
        events_per_sec=2500,
        flows=600,
        websocket_clients=6,
        expected_target="visible bounded pressure; explained drops are acceptable",
    ),
}


def profile_names() -> tuple[str, ...]:
    return tuple(LOAD_PROFILES)


def get_profile(name: str) -> LoadProfile:
    try:
        return LOAD_PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown load profile: {name}") from exc


__all__ = ["LOAD_PROFILES", "LoadProfile", "get_profile", "profile_names"]
