#!/usr/bin/env python3
"""Build, install, or statically check Mnemosyne raw-memory-sync projections."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPOSITORY_ROOT / "raw_memory_sync"
REGISTRATION_BEGIN = "# BEGIN Mnemosyne raw-memory-sync managed registration\n"
REGISTRATION_END = "# END Mnemosyne raw-memory-sync managed registration\n"
LEGACY_HEADER = re.compile(
    r'^\[agents\."raw_memory_sync"\][ \t]*(?:#.*)?(?:\n|$)', re.MULTILINE
)
LEGACY_MENTION_HEADER = re.compile(
    r'^\s*\[[^\n]*agents\."raw_memory_sync"[^\n]*$', re.MULTILINE
)
TOML_TABLE_HEADER = re.compile(
    r'^\s*\[\[?[^\n]*\]\]?[ \t]*(?:#.*)?(?:\n|$)', re.MULTILINE
)


def read_source(name: str) -> str:
    return (PACKAGE_ROOT / name).read_text(encoding="utf-8")


def rendered_outputs(home_root: Path) -> dict[Path, str]:
    skill = read_source("SKILL.md")
    agent = read_source("agent.md")
    codex_template = read_source("adapters/codex-agent.toml.template")
    claude_template = read_source("adapters/claude-agent.md.template")
    return {
        home_root / ".codex" / "skills" / "raw-memory-sync" / "SKILL.md": skill,
        home_root / ".codex" / "agents" / "raw_memory_sync.toml": codex_template.replace(
            "{{AGENT_INSTRUCTIONS}}", agent
        ),
        home_root / ".claude" / "skills" / "raw-memory-sync" / "SKILL.md": skill,
        home_root / ".claude" / "agents" / "raw-memory-sync.md": claude_template.replace(
            "{{AGENT_INSTRUCTIONS}}", agent
        ),
    }


def registration_block() -> str:
    return (
        REGISTRATION_BEGIN
        + '[agents."raw_memory_sync"]\n'
        + 'description = "Mnemosyne-owned approval-gated raw-memory sync worker."\n'
        + 'config_file = "agents/raw_memory_sync.toml"\n'
        + 'nickname_candidates = ["raw_memory_sync"]\n'
        + REGISTRATION_END
    )


def rendered_config(existing: str) -> str:
    begin_count = existing.count(REGISTRATION_BEGIN)
    end_count = existing.count(REGISTRATION_END)
    if begin_count != end_count or begin_count > 1:
        raise ValueError("raw-memory-sync managed registration markers are malformed")
    if begin_count:
        start = existing.index(REGISTRATION_BEGIN)
        end = existing.index(REGISTRATION_END, start) + len(REGISTRATION_END)
        unmanaged_legacy = LEGACY_HEADER.findall(existing[:start] + existing[end:])
        if unmanaged_legacy:
            raise ValueError("unmanaged legacy raw-memory-sync registration remains")
        return existing[:start] + registration_block() + existing[end:]

    legacy_headers = list(LEGACY_HEADER.finditer(existing))
    legacy_mention_headers = list(LEGACY_MENTION_HEADER.finditer(existing))
    if len(legacy_mention_headers) != len(legacy_headers):
        raise ValueError("legacy raw-memory-sync table header is malformed")
    if len(legacy_headers) > 1:
        raise ValueError("legacy raw-memory-sync registration is ambiguous")
    if legacy_headers:
        header = legacy_headers[0]
        next_header = TOML_TABLE_HEADER.search(existing, header.end())
        table_end = next_header.start() if next_header else len(existing)
        return existing[:header.start()] + registration_block() + existing[table_end:]

    prefix = existing if not existing or existing.endswith("\n") else existing + "\n"
    if prefix and not prefix.endswith("\n\n"):
        prefix += "\n"
    return prefix + registration_block()


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(0o644)
    os.replace(temporary_path, path)


def desired_launcher(home_root: Path) -> tuple[Path, Path]:
    return (
        home_root / ".local" / "bin" / "mnemosyne-control",
        (REPOSITORY_ROOT / "scripts" / "mnemosyne-control").resolve(),
    )


def launcher_matches(path: Path, source: Path) -> bool:
    return path.is_symlink() and path.resolve() == source


def install_launcher(home_root: Path) -> None:
    path, source = desired_launcher(home_root)
    if not source.is_file():
        raise ValueError(f"launcher source is missing: {source}")
    if os.path.lexists(path):
        if launcher_matches(path, source):
            return
        raise ValueError(f"refusing to replace launcher destination: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(source)


def check(home_root: Path, *, include_launcher: bool) -> list[str]:
    problems: list[str] = []
    for path, expected in rendered_outputs(home_root).items():
        if not path.is_file():
            problems.append(f"missing projection: {path}")
        elif path.read_text(encoding="utf-8") != expected:
            problems.append(f"stale projection: {path}")
    config_path = home_root / ".codex" / "config.toml"
    if not config_path.is_file():
        problems.append(f"missing projection: {config_path}")
    else:
        actual = config_path.read_text(encoding="utf-8")
        try:
            if rendered_config(actual) != actual:
                problems.append(f"stale managed registration: {config_path}")
        except ValueError as exc:
            problems.append(str(exc))
    if include_launcher:
        launcher, source = desired_launcher(home_root)
        if not launcher_matches(launcher, source):
            problems.append(f"missing or unsafe launcher: {launcher}")
    return problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--home-root",
        type=Path,
        default=Path.home(),
        help="home-root projection destination (use a temporary directory in tests)",
    )
    parser.add_argument("--check", action="store_true", help="validate only; do not write")
    parser.add_argument(
        "--install-launcher",
        action="store_true",
        help="safely link .local/bin/mnemosyne-control to this repository",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home_root = args.home_root.expanduser().resolve()
    if args.check:
        problems = check(home_root, include_launcher=args.install_launcher)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0

    config_path = home_root / ".codex" / "config.toml"
    current_config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    try:
        next_config = rendered_config(current_config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    outputs = rendered_outputs(home_root)
    for path, content in outputs.items():
        write_atomic(path, content)
    write_atomic(config_path, next_config)
    if args.install_launcher:
        install_launcher(home_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
