#!/usr/bin/env python3
"""Build, install, or statically check Mnemosyne raw-memory-sync projections."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPOSITORY_ROOT / "raw_memory_sync"
SCRIPTS_ROOT = REPOSITORY_ROOT / "scripts"
if str(SCRIPTS_ROOT) in sys.path:
    sys.path.remove(str(SCRIPTS_ROOT))
sys.path.insert(0, str(SCRIPTS_ROOT))

import mnemosyne  # noqa: E402

if Path(mnemosyne.__file__ or "").resolve() != (SCRIPTS_ROOT / "mnemosyne.py").resolve():
    raise RuntimeError("raw-memory-sync installer did not load the canonical Mnemosyne writer")


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


def write_private_atomic(path: Path, content: str) -> None:
    encoded = content.encode("utf-8")
    try:
        directory_fd = mnemosyne.open_or_create_verified_directory(
            path.parent, mode=0o700
        )
    except mnemosyne.MnemosyneError as exc:
        raise ValueError(f"unsafe entrypoint manifest parent: {path.parent}") from exc
    staging_name = f".{path.name}.incomplete-{secrets.token_hex(12)}"
    staging_created = False
    fd: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(staging_name, flags, 0o600, dir_fd=directory_fd)
        staging_created = True
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written <= 0:
                raise ValueError(f"entrypoint manifest write made no progress: {path}")
            offset += written
        os.fsync(fd)
        opened = os.fstat(fd)
        lexical = os.stat(staging_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise ValueError(f"entrypoint manifest staging identity is unsafe: {path}")
        mnemosyne.require_same_directory_identity(
            path.parent, directory_fd, "entrypoint manifest"
        )
        os.replace(
            staging_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        staging_created = False
        os.fsync(directory_fd)
        final = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError(f"entrypoint manifest final identity changed: {path}")
        mnemosyne.require_same_directory_identity(
            path.parent, directory_fd, "entrypoint manifest"
        )
    except OSError as exc:
        raise ValueError(f"cannot write entrypoint manifest: {path}") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if staging_created:
            try:
                os.unlink(staging_name, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def desired_launcher(home_root: Path) -> tuple[Path, Path]:
    return (
        home_root / ".local" / "bin" / "mnemosyne-control",
        (REPOSITORY_ROOT / "scripts" / "mnemosyne-control").resolve(),
    )


def launcher_matches_at(path: Path, source: Path, parent_fd: int) -> bool:
    try:
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        link_value = os.readlink(path.name, dir_fd=parent_fd)
        after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    if (
        not stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.getuid()
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        return False
    raw_target = Path(link_value)
    target = raw_target if raw_target.is_absolute() else path.parent / raw_target
    return Path(os.path.abspath(target)) == source


def launcher_matches(path: Path, source: Path) -> bool:
    try:
        parent_fd = mnemosyne.open_verified_directory(
            path.parent, require_owner_only=True
        )
    except mnemosyne.MnemosyneError:
        return False
    try:
        return launcher_matches_at(path, source, parent_fd)
    finally:
        os.close(parent_fd)


def install_launcher(home_root: Path) -> None:
    path, source = desired_launcher(home_root)
    if not source.is_file():
        raise ValueError(f"launcher source is missing: {source}")
    try:
        parent_fd = mnemosyne.open_or_create_verified_directory(
            path.parent, mode=0o700
        )
    except mnemosyne.MnemosyneError as exc:
        raise ValueError(f"unsafe launcher parent: {path.parent}") from exc
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                mnemosyne.require_same_directory_identity(
                    path.parent, parent_fd, "launcher"
                )
                os.symlink(str(source), path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                raise ValueError(f"cannot create launcher destination: {path}") from exc
            if not launcher_matches_at(path, source, parent_fd):
                raise ValueError(f"launcher destination is unsafe: {path}")
        except OSError as exc:
            raise ValueError(f"cannot inspect launcher destination: {path}") from exc
        else:
            if not launcher_matches_at(path, source, parent_fd):
                raise ValueError(f"refusing to replace launcher destination: {path}")
        try:
            mnemosyne.require_same_directory_identity(path.parent, parent_fd, "launcher")
        except mnemosyne.MnemosyneError as exc:
            raise ValueError(f"launcher parent changed during installation: {path.parent}") from exc
    finally:
        os.close(parent_fd)


def entrypoint_manifest_path(home_root: Path) -> Path:
    return home_root / ".local" / "share" / "mnemosyne" / "installed-entrypoints.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_discovery_roots(home_root: Path) -> list[Path]:
    roots = mnemosyne.authoritative_entrypoint_discovery_roots(home_root)
    for root in roots:
        try:
            directory_fd = mnemosyne.open_verified_directory(
                root, require_owner_only=True
            )
        except mnemosyne.MnemosyneError as exc:
            raise ValueError(f"unsafe entrypoint discovery root: {root}") from exc
        else:
            os.close(directory_fd)
    return roots


def verified_instruction_surface_contracts(
    home_root: Path, canonical_writer: Path
) -> list[dict[str, str]]:
    contracts: list[dict[str, str]] = []
    for surface_path in mnemosyne.authoritative_entrypoint_instruction_surfaces(home_root):
        try:
            info, raw = mnemosyne.read_verified_regular_file(
                surface_path,
                label="instruction surface",
                expected_mode=None,
            )
        except mnemosyne.MnemosyneError as exc:
            raise ValueError(f"unsafe instruction surface: {surface_path}") from exc
        if info.st_nlink != 1:
            raise ValueError(f"unsafe instruction surface: {surface_path}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"instruction surface is not UTF-8: {surface_path}") from exc
        references = sorted(
            set(re.findall(r"/[A-Za-z0-9_./-]*/mnemosyne\.py", text))
        )
        if references != [str(canonical_writer)]:
            raise ValueError(
                f"instruction surface does not bind the canonical writer: {surface_path}"
            )
        contracts.append(
            {
                "path": str(surface_path),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "required_writer_path": str(canonical_writer),
            }
        )
    return contracts


def rendered_entrypoint_manifest(home_root: Path) -> str:
    launcher_alias, source_launcher = desired_launcher(home_root)
    if not launcher_matches(launcher_alias, source_launcher):
        raise ValueError(f"missing or unsafe launcher: {launcher_alias}")
    canonical_writer = (SCRIPTS_ROOT / "mnemosyne.py").resolve()
    discovery_roots = verified_discovery_roots(home_root)
    instruction_surfaces = verified_instruction_surface_contracts(
        home_root, canonical_writer
    )
    runtime_modules = sorted(
        (path.resolve() for path in mnemosyne.authoritative_runtime_module_paths()),
        key=str,
    )
    manifest = {
        "schema_version": 3,
        "kind": "MNEMOSYNE_INSTALLED_ENTRYPOINTS",
        "compatibility_version": mnemosyne.MNEMOSYNE_COMPATIBILITY_VERSION,
        "declared_by": "raw-memory-sync-install-v1",
        "coverage_complete": True,
        "canonical_writer": {
            "path": str(canonical_writer),
            "sha256": sha256_file(canonical_writer),
        },
        "writer_aliases": [],
        "instruction_surfaces": instruction_surfaces,
        "launchers": [
            {
                "kind": mnemosyne.MNEMOSYNE_CONTROL_LAUNCHER_KIND,
                "path": str(source_launcher),
                "sha256": sha256_file(source_launcher),
                "delegates_to": str(canonical_writer),
            }
        ],
        "launcher_aliases": [
            {
                "path": str(launcher_alias),
                "must_resolve_to": str(source_launcher),
            }
        ],
        "discovery_roots": sorted({str(path) for path in discovery_roots}),
        "retired_paths": [],
        "runtime_modules": [
            {"path": str(path), "sha256": sha256_file(path)} for path in runtime_modules
        ],
    }
    return json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


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
        else:
            manifest_path = entrypoint_manifest_path(home_root)
            expected_manifest = rendered_entrypoint_manifest(home_root)
            try:
                actual_manifest, _manifest, _info = mnemosyne.read_owner_only_manifest(
                    manifest_path
                )
            except mnemosyne.MnemosyneError:
                problems.append(f"unsafe entrypoint manifest: {manifest_path}")
            else:
                if actual_manifest != expected_manifest.encode("utf-8"):
                    problems.append(f"stale entrypoint manifest: {manifest_path}")
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
        help="safely link .local/bin/mnemosyne-control and register it in an owner-only manifest",
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
        write_private_atomic(
            entrypoint_manifest_path(home_root),
            rendered_entrypoint_manifest(home_root),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
