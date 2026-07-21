#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


class OkfValidationError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str


@dataclass(frozen=True)
class UrlPrefix:
    host: str
    port: int | None
    path: str


@dataclass(frozen=True)
class BundleConfig:
    bundle_id: str
    path: str
    allow_source_roots: tuple[str, ...]
    allow_url_prefixes: tuple[str, ...]


MARKDOWN_AUTOLINK_RE = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^<>\s]+)>")
HTML_URL_ATTRIBUTE_RE = re.compile(
    r'''(?is)\b(href|src|srcset|imagesrcset|action|formaction|poster|data|cite|background|longdesc|manifest|ping|archive|codebase|classid|profile|usemap)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))'''
)
COMMONMARK_ESCAPABLE = frozenset(r'''!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~''')
FORBIDDEN_SOURCE_PARTS = {
    "private",
    "memory",
    ".tmp",
    ".git",
    "worktrees",
    "graphify-out",
    ".agents",
    ".claude",
    ".codex",
    ".gemini",
    ".harnesskit",
}


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value in {"true", "false"}:
        return value == "true"
    if value in {"null", "~"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [] if not inner else [parse_scalar(item) for item in inner.split(",")]
    if value.startswith("{") and value.endswith("}"):
        return {}
    if value.isdigit():
        return int(value)
    if value.startswith(("\"", "'")) and value.endswith(value[0]):
        return value[1:-1]
    return value


def split_frontmatter(text: str) -> tuple[dict[str, Any] | None, str, str | None]:
    if not text.startswith("---\n"):
        return None, text, None
    if text.startswith("---\n---\n"):
        marker = 3
    else:
        marker = text.find("\n---\n", 4)
        if marker == -1:
            raise OkfValidationError("frontmatter-not-closed")
    data: dict[str, Any] = {}
    current_list: str | None = None
    raw_frontmatter = text[4:marker]
    for raw_line in raw_frontmatter.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.startswith("  - ") and current_list:
            data[current_list].append(parse_scalar(raw_line[4:]))
            continue
        if raw_line.startswith((" ", "\t")) or ":" not in raw_line:
            raise OkfValidationError("frontmatter-unsupported-syntax")
        key, value = raw_line.split(":", 1)
        key = key.strip()
        if not key:
            raise OkfValidationError("frontmatter-empty-key")
        if key in data:
            raise OkfValidationError("frontmatter-duplicate-key")
        if value.strip() == "":
            data[key] = []
            current_list = key
        else:
            data[key] = parse_scalar(value)
            current_list = None
    return data, text[marker + 5 :], raw_frontmatter


def resolve_under_root(value: str | Path, root: Path, *, must_exist: bool = False) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=must_exist)
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise OkfValidationError("path-outside-root")
    return resolved_path


def require_no_symlink_components(value: str | Path, root: Path, rule: str) -> None:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    lexical_path = Path(os.path.abspath(path))
    resolved_root = root.resolve()
    resolved_path = lexical_path.resolve(strict=False)
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise OkfValidationError("path-outside-root")

    anchor: Path | None = None
    for candidate in [lexical_path, *lexical_path.parents]:
        if candidate.resolve(strict=False) == resolved_root:
            anchor = candidate
    if anchor is None:
        raise OkfValidationError("path-outside-root")
    if anchor.is_symlink():
        raise OkfValidationError(rule)

    current = anchor
    for part in lexical_path.relative_to(anchor).parts:
        current = current / part
        if current.is_symlink():
            raise OkfValidationError(rule)
        if not current.exists():
            break


def display_path(path: Path, root: Path) -> str:
    absolute = path if path.is_absolute() else root / path
    try:
        return absolute.relative_to(root.resolve()).as_posix()
    except ValueError:
        return "[outside-root]"


def is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def is_forbidden_source(path: Path, root: Path) -> bool:
    rel = path.relative_to(root.resolve())
    parts = set(rel.parts)
    if parts & FORBIDDEN_SOURCE_PARTS:
        return True
    if len(rel.parts) >= 2 and rel.parts[:2] in {("_registry", "pending"), ("_registry", "decisions")}:
        return True
    return any("cleanup-audit" in part or part.endswith("-cleanup") for part in rel.parts)


def normalize_url_path(value: str, error_rule: str) -> str:
    decoded = value
    for _ in range(8):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    else:
        raise OkfValidationError(error_rule)

    if "\x00" in decoded or "\\" in decoded:
        raise OkfValidationError(error_rule)
    parts: list[str] = []
    for part in decoded.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise OkfValidationError(error_rule)
        parts.append(part)
    normalized = "/" + "/".join(parts)
    if decoded.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def is_markdown_escaped(text: str, offset: int) -> bool:
    backslashes = 0
    offset -= 1
    while offset >= 0 and text[offset] == "\\":
        backslashes += 1
        offset -= 1
    return backslashes % 2 == 1


def decode_markdown_target(value: str) -> str:
    decoded = html.unescape(value)
    result: list[str] = []
    offset = 0
    while offset < len(decoded):
        if (
            decoded[offset] == "\\"
            and offset + 1 < len(decoded)
            and decoded[offset + 1] in COMMONMARK_ESCAPABLE
        ):
            result.append(decoded[offset + 1])
            offset += 2
            continue
        result.append(decoded[offset])
        offset += 1
    return "".join(result)


def parse_markdown_destination(text: str, offset: int, *, allow_eol: bool = False) -> str | None:
    while offset < len(text) and text[offset] in {" ", "\t"}:
        offset += 1
    if offset < len(text) and text[offset] == "\n":
        offset += 1
        while True:
            while offset < len(text) and text[offset] in {" ", "\t"}:
                offset += 1
            if offset >= len(text) or text[offset] != ">":
                break
            offset += 1
    if offset >= len(text) or text[offset] == "\n":
        return None
    if text[offset] == "<":
        start = offset + 1
        offset = start
        while offset < len(text) and text[offset] != "\n":
            if text[offset] == ">" and not is_markdown_escaped(text, offset):
                return text[start:offset]
            offset += 1
        return None

    start = offset
    depth = 0
    while offset < len(text) and text[offset] != "\n":
        char = text[offset]
        if char == "\\" and offset + 1 < len(text):
            offset += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return text[start:offset]
            depth -= 1
        elif char in {" ", "\t"} and depth == 0:
            return text[start:offset]
        offset += 1
    if allow_eol and depth == 0:
        return text[start:offset]
    return None


def extract_link_targets(body: str) -> list[str]:
    targets: set[str] = set()

    for offset in range(len(body) - 1):
        if (
            body[offset] == "]"
            and body[offset + 1] == "("
            and not is_markdown_escaped(body, offset)
        ):
            target = parse_markdown_destination(body, offset + 2)
            if target:
                targets.add(decode_markdown_target(target))
        elif (
            body[offset] == "]"
            and body[offset + 1] == ":"
            and not is_markdown_escaped(body, offset)
        ):
            target = parse_markdown_destination(body, offset + 2, allow_eol=True)
            if target:
                targets.add(decode_markdown_target(target))

    targets.update(decode_markdown_target(value) for value in MARKDOWN_AUTOLINK_RE.findall(body))
    for match in HTML_URL_ATTRIBUTE_RE.finditer(body):
        attribute = match.group(1).lower()
        raw_target = next((group for group in match.groups()[1:] if group is not None), "")
        decoded_target = decode_markdown_target(raw_target)
        if attribute in {"srcset", "imagesrcset"}:
            for candidate in decoded_target.split(","):
                target = candidate.strip().split(maxsplit=1)[0] if candidate.strip() else ""
                if target:
                    targets.add(target)
        elif attribute in {"ping", "archive"}:
            targets.update(value for value in decoded_target.split() if value)
        elif decoded_target:
            targets.add(decoded_target)
    return sorted(targets)


def parse_url_prefix(value: str) -> UrlPrefix:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise OkfValidationError("invalid-url-prefix") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise OkfValidationError("invalid-url-prefix")
    normalized_path = normalize_url_path(parsed.path, "invalid-url-prefix")
    if not normalized_path.endswith("/"):
        raise OkfValidationError("invalid-url-prefix")
    return UrlPrefix(parsed.hostname.lower(), port, normalized_path)


def load_registry_bundle(path: Path, bundle_id: str) -> BundleConfig:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", bundle_id):
        raise OkfValidationError("invalid-bundle-id")

    in_knowledge_formats = False
    in_okf = False
    in_bundles = False
    okf_fields: dict[str, Any] = {}
    bundles: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_list: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        if indent == 0:
            in_knowledge_formats = line == "knowledge_formats:"
            in_okf = False
            in_bundles = False
            current = None
            current_list = None
            continue
        if not in_knowledge_formats:
            continue
        if indent == 2:
            in_okf = line == "okf:"
            in_bundles = False
            current = None
            current_list = None
            continue
        if not in_okf:
            continue
        if indent == 4:
            current = None
            current_list = None
            if line == "bundles:":
                in_bundles = True
            elif ":" in line:
                key, value = line.split(":", 1)
                okf_fields[key.strip()] = parse_scalar(value)
                in_bundles = False
            continue
        if not in_bundles:
            continue
        if indent == 6 and line.startswith("- "):
            current = {}
            bundles.append(current)
            current_list = None
            rest = line[2:].strip()
            if ":" in rest:
                key, value = rest.split(":", 1)
                current[key.strip()] = parse_scalar(value)
            continue
        if current is None:
            continue
        if indent == 8:
            if line.endswith(":"):
                current_list = line[:-1].strip()
                current[current_list] = []
            elif ":" in line:
                key, value = line.split(":", 1)
                current[key.strip()] = parse_scalar(value)
                current_list = None
            continue
        if indent == 10 and current_list and line.startswith("- "):
            current[current_list].append(parse_scalar(line[2:]))

    if (
        str(okf_fields.get("spec_version", "")) != "0.1"
        or okf_fields.get("adoption_status") != "adopted"
        or okf_fields.get("profile_version") != 1
        or okf_fields.get("authority") != "derived"
        or okf_fields.get("enforcement") != "registry-driven-validator"
    ):
        raise OkfValidationError("registry-okf-profile-not-adopted")
    if okf_fields.get("validator") != str(Path(__file__).resolve()):
        raise OkfValidationError("registry-validator-mismatch")

    matches = [item for item in bundles if item.get("id") == bundle_id]
    if len(matches) != 1:
        raise OkfValidationError("registry-bundle-not-found")
    item = matches[0]
    bundle_path = item.get("path")
    output_root_value = okf_fields.get("output_root")
    source_roots = item.get("allow_source_roots", [])
    url_prefixes = item.get("allow_url_prefixes", [])
    if (
        not isinstance(bundle_path, str)
        or not isinstance(output_root_value, str)
        or not isinstance(source_roots, list)
        or not all(isinstance(value, str) for value in source_roots)
        or not isinstance(url_prefixes, list)
        or not all(isinstance(value, str) for value in url_prefixes)
    ):
        raise OkfValidationError("registry-bundle-invalid")

    workspace_root = path.parent.parent.resolve()
    configured_output_root = Path(output_root_value).expanduser()
    configured_bundle = Path(bundle_path).expanduser()
    if not configured_output_root.is_absolute() or not configured_bundle.is_absolute():
        raise OkfValidationError("registry-bundle-invalid")
    try:
        output_root = resolve_under_root(configured_output_root, workspace_root)
        resolved_bundle = resolve_under_root(configured_bundle, workspace_root)
    except OkfValidationError as exc:
        raise OkfValidationError("registry-bundle-outside-output-root") from exc
    if output_root == workspace_root or is_forbidden_source(output_root, workspace_root):
        raise OkfValidationError("registry-output-root-invalid")
    if not is_within(resolved_bundle, output_root):
        raise OkfValidationError("registry-bundle-outside-output-root")
    return BundleConfig(bundle_id, bundle_path, tuple(source_roots), tuple(url_prefixes))


def validate_log_body(body: str, path: Path, root: Path) -> list[Finding]:
    display = display_path(path, root)
    headings = re.findall(r"(?m)^##\s+(.+?)\s*$", body)
    if not headings:
        return [Finding("log-date-heading-missing", display)]
    dates: list[date] = []
    for heading in headings:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", heading):
            return [Finding("log-date-invalid", display)]
        try:
            dates.append(date.fromisoformat(heading))
        except ValueError:
            return [Finding("log-date-invalid", display)]
    if dates != sorted(dates, reverse=True):
        return [Finding("log-dates-not-newest-first", display)]
    return []


def local_link_finding(
    raw_target: str,
    source: Path,
    bundle: Path,
    root: Path,
    allowed_source_roots: tuple[Path, ...],
    allowed_url_prefixes: tuple[UrlPrefix, ...],
) -> Finding | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith("#"):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        try:
            port = parsed.port
        except ValueError:
            return Finding("external-url-invalid", display_path(source, root))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return Finding("external-url-invalid", display_path(source, root))
        try:
            normalized_path = normalize_url_path(parsed.path, "external-url-traversal")
        except OkfValidationError as exc:
            return Finding(str(exc), display_path(source, root))
        if not any(
            parsed.hostname.lower() == prefix.host
            and port == prefix.port
            and normalized_path.startswith(prefix.path)
            for prefix in allowed_url_prefixes
        ):
            return Finding("external-url-not-allowed", display_path(source, root))
        return None
    decoded_path = parsed.path
    for _ in range(3):
        next_value = unquote(decoded_path)
        if next_value == decoded_path:
            break
        decoded_path = next_value
    if "\x00" in decoded_path or "\\" in decoded_path:
        return Finding("link-traversal", display_path(source, root))
    if re.search(r"%(?:25)*2e", parsed.path, re.IGNORECASE) and ".." in Path(decoded_path).parts:
        return Finding("link-traversal", display_path(source, root))
    if not decoded_path:
        return None
    if decoded_path.startswith("/"):
        if ".." in Path(decoded_path).parts:
            return Finding("link-traversal", display_path(source, root))
        resolved = (bundle / decoded_path.lstrip("/")).resolve(strict=False)
    else:
        resolved = (source.parent / decoded_path).resolve(strict=False)
    resolved_root = root.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        return Finding("link-escapes-root", display_path(source, root))
    if not resolved.exists():
        return Finding("link-target-missing", display_path(source, root))
    built_in_sources = {
        (root / "_registry" / "placement-map.yml").resolve(strict=False),
        (root / "_projects.md").resolve(strict=False),
    }
    if not is_within(resolved, bundle.resolve()) and is_forbidden_source(resolved, root):
        return Finding("source-forbidden", display_path(source, root))
    if not is_within(resolved, bundle.resolve()) and resolved not in built_in_sources:
        if not any(is_within(resolved, allowed_root) for allowed_root in allowed_source_roots):
            return Finding("source-root-not-allowed", display_path(source, root))
    return None


def validate_bundle(
    bundle: Path,
    root: Path,
    allowed_source_roots: tuple[Path, ...] = (),
    allowed_url_prefixes: tuple[UrlPrefix, ...] = (),
) -> list[Finding]:
    findings: list[Finding] = []
    markdown_files: list[Path] = []

    def handle_walk_error(error: OSError) -> None:
        failed_path = Path(error.filename) if isinstance(error.filename, str) else bundle
        findings.append(Finding("directory-scan-failed", display_path(failed_path, root)))

    for current_dir, dir_names, file_names in os.walk(
        bundle,
        topdown=True,
        onerror=handle_walk_error,
        followlinks=False,
    ):
        current = Path(current_dir)
        retained_dirs: list[str] = []
        for name in sorted(dir_names):
            path = current / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                findings.append(Finding("file-inspection-failed", display_path(path, root)))
                continue
            if stat.S_ISLNK(mode):
                findings.append(Finding("symlink-forbidden", display_path(path, root)))
            elif stat.S_ISDIR(mode):
                retained_dirs.append(name)
            else:
                findings.append(Finding("non-regular-file", display_path(path, root)))
        dir_names[:] = retained_dirs

        for name in sorted(file_names):
            path = current / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                findings.append(Finding("file-inspection-failed", display_path(path, root)))
                continue
            if stat.S_ISLNK(mode):
                findings.append(Finding("symlink-forbidden", display_path(path, root)))
            elif not stat.S_ISREG(mode):
                findings.append(Finding("non-regular-file", display_path(path, root)))
            elif path.suffix.lower() != ".md":
                findings.append(Finding("unexpected-file", display_path(path, root)))
            else:
                markdown_files.append(path)

    root_index = bundle / "index.md"
    if root_index not in markdown_files:
        findings.append(Finding("root-index-missing", display_path(root_index, root)))
        return sorted(set(findings), key=lambda item: (item.path, item.rule))

    for path in sorted(markdown_files):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding("markdown-not-utf8", display_path(path, root)))
            continue
        except OSError:
            findings.append(Finding("file-read-failed", display_path(path, root)))
            continue
        try:
            frontmatter, body, raw_frontmatter = split_frontmatter(text)
        except OkfValidationError as exc:
            findings.append(Finding(str(exc), display_path(path, root)))
            continue

        if path == root_index:
            quoted_version = re.search(
                r"(?m)^okf_version:\s*([\"'])0\.1\1\s*$",
                raw_frontmatter or "",
            )
            if (
                not frontmatter
                or str(frontmatter.get("okf_version", "")) != "0.1"
                or quoted_version is None
            ):
                findings.append(Finding("root-version-invalid", display_path(path, root)))
        elif path.name not in {"index.md", "log.md"}:
            if frontmatter is None or "type" not in frontmatter:
                findings.append(Finding("type-missing", display_path(path, root)))
            elif not isinstance(frontmatter["type"], str) or not frontmatter["type"].strip():
                findings.append(Finding("type-invalid", display_path(path, root)))
        elif frontmatter is not None:
            findings.append(Finding("reserved-frontmatter-present", display_path(path, root)))

        if path.name == "log.md" and frontmatter is None:
            findings.extend(validate_log_body(body, path, root))

        for raw_target in extract_link_targets(body):
            finding = local_link_finding(
                raw_target,
                path,
                bundle,
                root,
                allowed_source_roots,
                allowed_url_prefixes,
            )
            if finding:
                findings.append(finding)

        if frontmatter is not None and "lifecycle_source" in frontmatter:
            lifecycle_source = frontmatter["lifecycle_source"]
            if not isinstance(lifecycle_source, str) or not lifecycle_source.strip():
                findings.append(Finding("lifecycle-source-invalid", display_path(path, root)))
            else:
                finding = local_link_finding(
                    lifecycle_source,
                    path,
                    bundle,
                    root,
                    allowed_source_roots,
                    allowed_url_prefixes,
                )
                if finding:
                    findings.append(finding)

    return sorted(set(findings), key=lambda item: (item.path, item.rule))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the adopted local OKF v0.1 profile")
    parser.add_argument("--root", required=True)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--bundle")
    selector.add_argument("--bundle-id")
    parser.add_argument("--allow-source-root", action="append", default=[])
    parser.add_argument("--allow-url-prefix", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve(strict=True)
        bundle_value = args.bundle
        source_root_values = tuple(args.allow_source_root)
        url_prefix_values = tuple(args.allow_url_prefix)
        if args.bundle_id:
            if source_root_values or url_prefix_values:
                raise OkfValidationError("bundle-id-explicit-allowlist-forbidden")
            config = load_registry_bundle(root / "_registry" / "placement-map.yml", args.bundle_id)
            bundle_value = config.path
            source_root_values = config.allow_source_roots
            url_prefix_values = config.allow_url_prefixes
        if bundle_value is None:
            raise OkfValidationError("bundle-required")

        require_no_symlink_components(bundle_value, root, "bundle-symlink-forbidden")
        bundle = resolve_under_root(bundle_value, root, must_exist=True)
        if not bundle.is_dir():
            raise OkfValidationError("bundle-not-directory")
        if bundle == root or is_forbidden_source(bundle, root):
            raise OkfValidationError("bundle-forbidden")
        for value in source_root_values:
            require_no_symlink_components(value, root, "allowed-source-root-symlink-forbidden")
        allowed_source_roots = tuple(resolve_under_root(value, root, must_exist=True) for value in source_root_values)
        if any(not path.is_dir() for path in allowed_source_roots):
            raise OkfValidationError("allowed-source-root-not-directory")
        if any(path == root or is_forbidden_source(path, root) for path in allowed_source_roots):
            raise OkfValidationError("forbidden-source-root")
        allowed_url_prefixes = tuple(parse_url_prefix(value) for value in url_prefix_values)
        findings = validate_bundle(bundle, root, allowed_source_roots, allowed_url_prefixes)
    except FileNotFoundError:
        print("error: path-not-found", file=sys.stderr)
        return 2
    except OkfValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = {
        "mode": "okf-validate",
        "profile": "okf-v0.1-adopted-local-v1",
        "spec_version": "0.1",
        "bundle": display_path(bundle, root),
        "errors": len(findings),
        "findings": [{"rule": item.rule, "path": item.path} for item in findings],
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("mode: okf-validate")
        print("profile: okf-v0.1-adopted-local-v1")
        print("spec_version: 0.1")
        print(f"bundle: {result['bundle']}")
        print(f"errors: {len(findings)}")
        for finding in findings:
            print(f"  - {finding.rule}: {finding.path}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
