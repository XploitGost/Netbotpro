from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


REQUIRED_TEXT_CHECKS = (
    ("systemd_service_user", "deploy/systemd/netbotpro.service", "User=netbotpro"),
    (
        "systemd_environment_file",
        "deploy/systemd/netbotpro.service",
        "EnvironmentFile=/etc/netbotpro/netbotpro.env",
    ),
    (
        "server_profile_env",
        "deploy/systemd/netbotpro.env.example",
        "NETBOT_PROFILE=server",
    ),
    (
        "live_capture_disabled_by_default",
        "deploy/systemd/netbotpro.env.example",
        "NETBOT_ENABLE_LIVE_CAPTURE=false",
    ),
    ("docker_non_root_user", "Dockerfile", "USER netbotpro"),
    ("docker_healthcheck", "Dockerfile", "HEALTHCHECK"),
    ("compose_localhost_bind", "docker-compose.yml", '"127.0.0.1:8000:8000"'),
    (
        "linux_docs_safe_boundary",
        "docs/LINUX_SERVER_DEPLOYMENT.md",
        "not command/control",
    ),
)


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def run_checks() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for name, relative_path, expected in REQUIRED_TEXT_CHECKS:
        content = _read(relative_path)
        results.append({"name": name, "file": relative_path, "ok": expected in content})

    systemd = _read("deploy/systemd/netbotpro.service")
    results.append(
        {
            "name": "systemd_not_root",
            "file": "deploy/systemd/netbotpro.service",
            "ok": "User=root" not in systemd,
        }
    )

    compose = _read("docker-compose.yml").lower()
    results.append(
        {
            "name": "compose_not_privileged",
            "file": "docker-compose.yml",
            "ok": "privileged: true" not in compose,
        }
    )

    dockerignore = _read(".dockerignore")
    for ignored in (".runtime", "node_modules", "*.pcap", "*.pcapng", ".env"):
        results.append(
            {
                "name": f"dockerignore_{ignored}",
                "file": ".dockerignore",
                "ok": ignored in dockerignore,
            }
        )

    failed = [item for item in results if not item["ok"]]
    return {
        "ok": not failed,
        "checks_total": len(results),
        "checks_failed": len(failed),
        "failed": failed,
    }


def main() -> int:
    result = run_checks()
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
