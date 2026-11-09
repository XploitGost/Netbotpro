"""Check tracked source artifacts without printing potential secret values."""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess


MAX_SOURCE_BYTES = 5 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
)
GENERATED_PARTS = {
    ".runtime", "node_modules", "__pycache__", ".pytest_cache",
    ".baseline", "dist", ".venv", "venv",
}
GENERATED_SUFFIXES = {
    ".pcap", ".pcapng", ".db", ".sqlite", ".sqlite3", ".log", ".dmp",
    ".exe", ".pyd", ".pyc", ".pyo", ".zip",
}


def check_file(name: str, data: bytes) -> list[str]:
    path = PurePosixPath(name)
    issues = []
    if any(part in GENERATED_PARTS for part in path.parts):
        issues.append("generated/runtime directory")
    if path.suffix.lower() in GENERATED_SUFFIXES or path.name == "native-redaction-build.json":
        issues.append("generated/runtime artifact")
    if path.name.startswith(".env") and path.name != ".env.example" and not path.name.endswith(".example"):
        issues.append("local environment file")
    if len(data) > MAX_SOURCE_BYTES:
        issues.append("source file exceeds 5 MiB; review artifact ownership")
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        issues.append("possible credential or private key; value omitted")
    return issues


def check_repository(root: Path, *, staged: bool = False) -> list[tuple[str, str]]:
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode("utf-8").split("\0")
    issues = []
    for name in filter(None, names):
        if staged:
            data = subprocess.check_output(["git", "show", f":{name}"], cwd=root)
        else:
            try:
                data = (root / name).read_bytes()
            except OSError:
                issues.append((name, "tracked file cannot be read"))
                continue
        issues.extend((name, reason) for reason in check_file(name, data))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="inspect Git index contents before commit")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    issues = check_repository(root, staged=args.staged)
    for name, reason in issues:
        print(f"{name}: {reason}")
    if issues:
        return 1
    print("Repository hygiene passed (tracked files only; not a comprehensive secret audit).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
