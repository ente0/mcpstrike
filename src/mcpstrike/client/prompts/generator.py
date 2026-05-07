"""Prompt template manager and generator.

Discovers ``.txt`` / ``.md`` templates from a templates directory, resolves
``{{PLACEHOLDER}}`` variables, and writes ready-to-use prompt files.

Used by the TUI's ``/prompt`` command and available as a standalone CLI via
``mcpstrike-prompt``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# ── Default templates directory (shipped with the package) ─────────────────
_PACKAGE_TEMPLATES = Path(__file__).parent / "templates"

# Extensions recognized as template files
_EXTENSIONS = (".txt", ".md", ".template")

# Standard placeholders with descriptions
PLACEHOLDERS: dict[str, str] = {
    "{{TARGET}}": "Target IP or hostname",
    "{{DOMAIN}}": "Domain name (N/A if not applicable)",
    "{{SESSION_ID}}": "Auto-generated session identifier",
    "{{DATE}}": "Current date (YYYY-MM-DD)",
    "{{DATETIME}}": "Full ISO datetime",
    "{{TIMESTAMP}}": "Unix timestamp",
    "{{TEST_TYPE}}": "Test type (black_box / gray_box / web_app / network / full)",
    "{{USER_AGENT_SUFFIX}}": "Custom User-Agent suffix for authorized testing",
    "{{OUT_OF_SCOPE_DOMAINS}}": "Excluded domains",
    "{{OUT_OF_SCOPE_IPS}}": "Excluded IPs/ranges",
    "{{OUT_OF_SCOPE_PATHS}}": "Excluded paths/endpoints",
    "{{OUT_OF_SCOPE_VULNS}}": "Excluded vulnerability types",
    "{{OUT_OF_SCOPE_NOTES}}": "Additional out-of-scope notes",
    "{{USER_AGENT}}":        "Full User-Agent string (alias or raw)",   # <-- aggiunta
    "{{USER_AGENT_SUFFIX}}": "Custom User-Agent suffix for authorized testing",
}

# ── User-Agent aliases ─────────────────────────────────────────────────────

USER_AGENT_ALIASES: dict[str, str] = {
    "burp":      "BurpSuite-Authorized-Test",
    "mobile":    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (bounty-authorized)",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl":      "curl/8.5.0 (authorized-pentest)",
    "firefox":   "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0 (bounty-authorized)",
}

TEST_TYPE_DESCRIPTIONS: dict[str, str] = {
    "full":      "All phases: recon → enum → exploitation → report. Uses every tool.",
    "web_app":   "Web-only: skips port scan, focuses dalfox/sqlmap/nuclei/feroxbuster.",
    "network":   "Network-first: heavy nmap/masscan, SMB/LDAP. Web only if port found.",
    "black_box": "No creds assumed. LLM brute-forces and tests default credentials.",
    "gray_box":  "Creds/roles provided. LLM focuses post-auth: IDOR, privesc, etc.",
}

_TEST_TYPE_HELP = (
    "Test type — shapes LLM behavior and tool prioritization:\n\n"
    + "\n".join(f"  {k:<12}{v}" for k, v in TEST_TYPE_DESCRIPTIONS.items())
    + "\n\nDefault: full"
)


def resolve_user_agent(ua: str) -> str:
    """Resolve a known alias to its full UA string, or return the raw value."""
    return USER_AGENT_ALIASES.get(ua.lower(), ua)


def parse_scope_file(path: Path) -> dict[str, str]:
    """Parse a scope exclusion file into per-category inline strings.

    File format::

        # comment
        [domains]
        admin.example.com
        staging.example.com

        [ips]
        10.0.0.1/24

        [paths]
        /api/internal
        /admin

        [vulns]
        dos

        [notes]
        Do not test during business hours

    Lines before the first header land in ``notes``.
    Each category is rendered as a comma-separated inline string.
    """
    categories: dict[str, list[str]] = {
        "domains": [], "ips": [], "paths": [], "vulns": [], "notes": [],
    }
    current = "notes"
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^\[(\w+)\]$", line)
            if m:
                key = m.group(1).lower()
                if key in categories:
                    current = key
                continue
            categories[current].append(line)
    except OSError as exc:
        raise SystemExit(f"[scope-file] Cannot read {path}: {exc}") from exc
    return {k: ", ".join(v) if v else "N/A" for k, v in categories.items()}
# ── Template discovery ─────────────────────────────────────────────────────


@dataclass
class TemplateInfo:
    """Metadata about a discovered template."""

    name: str
    path: Path
    description: str = ""
    size: int = 0


class TemplateManager:
    """Discover and load templates from one or more directories."""

    def __init__(self, *dirs: Path | str) -> None:
        self._dirs: list[Path] = []
        for d in dirs:
            p = Path(d).expanduser()
            if p.exists() and p.is_dir():
                self._dirs.append(p)
        # Always include the shipped templates as fallback
        if _PACKAGE_TEMPLATES.exists() and _PACKAGE_TEMPLATES not in self._dirs:
            self._dirs.append(_PACKAGE_TEMPLATES)
        self._cache: dict[str, TemplateInfo] | None = None

    def discover(self) -> dict[str, TemplateInfo]:
        """Scan directories for template files. Results are cached."""
        if self._cache is not None:
            return self._cache

        templates: dict[str, TemplateInfo] = {}
        for d in self._dirs:
            for ext in _EXTENSIONS:
                for path in sorted(d.glob(f"*{ext}")):
                    if not path.is_file():
                        continue
                    name = path.stem
                    if name in templates:
                        continue  # first directory wins
                    first_line = ""
                    try:
                        first_line = path.read_text(encoding="utf-8").split("\n", 1)[0].strip()
                    except OSError:
                        pass
                    templates[name] = TemplateInfo(
                        name=name,
                        path=path,
                        description=first_line[:80],
                        size=path.stat().st_size,
                    )
        self._cache = templates
        return templates

    def list_templates(self) -> list[TemplateInfo]:
        """Return templates as a sorted list (for numbered selection)."""
        return sorted(self.discover().values(), key=lambda t: t.name)

    def get(self, name: str) -> TemplateInfo | None:
        """Find a template by exact name or partial match."""
        templates = self.discover()
        # Exact
        if name in templates:
            return templates[name]
        # Case-insensitive
        for k, v in templates.items():
            if k.lower() == name.lower():
                return v
        # Partial
        for k, v in templates.items():
            if name.lower() in k.lower():
                return v
        return None

    def get_by_index(self, index: int) -> TemplateInfo | None:
        """Get a template by its 1-based position in the sorted list."""
        items = self.list_templates()
        if 1 <= index <= len(items):
            return items[index - 1]
        return None


# ── Prompt generation ──────────────────────────────────────────────────────


@dataclass
class PromptContext:
    """All the values needed to fill a template."""

    target: str
    domain: str = "N/A"
    test_type: str = "full"
    user_agent: str = ""          # full UA string — popola {{USER_AGENT}}
    user_agent_suffix: str = ""   # backward compat — popola {{USER_AGENT_SUFFIX}}    out_of_scope_domains: str = "N/A"
    out_of_scope_ips: str = "N/A"
    out_of_scope_paths: str = "N/A"
    out_of_scope_vulns: str = "N/A"
    out_of_scope_notes: str = "N/A"
    extra: dict[str, str] = field(default_factory=dict)

    def session_id(self) -> str:
        """Generate a filesystem-safe session identifier."""
        safe = self.target
        for ch in ".:/\\@#":
            safe = safe.replace(ch, "_")
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", safe)
        safe = re.sub(r"_+", "_", safe).strip("_")
        return safe

    def as_replacements(self) -> dict[str, str]:
        now = datetime.now()
        reps = {
            "{{TARGET}}": self.target,
            "{{DOMAIN}}": self.domain,
            "{{SESSION_ID}}": self.session_id(),
            "{{DATE}}": now.strftime("%Y-%m-%d"),
            "{{DATETIME}}": now.isoformat(),
            "{{TIMESTAMP}}": str(int(now.timestamp())),
            "{{TEST_TYPE}}": self.test_type,
            "{{USER_AGENT_SUFFIX}}": self.user_agent_suffix,
            "{{OUT_OF_SCOPE_DOMAINS}}": self.out_of_scope_domains,
            "{{OUT_OF_SCOPE_IPS}}": self.out_of_scope_ips,
            "{{OUT_OF_SCOPE_PATHS}}": self.out_of_scope_paths,
            "{{OUT_OF_SCOPE_VULNS}}": self.out_of_scope_vulns,
            "{{OUT_OF_SCOPE_NOTES}}": self.out_of_scope_notes,
            "{{USER_AGENT}}":        self.user_agent,        # <-- aggiunta
            "{{USER_AGENT_SUFFIX}}": self.user_agent_suffix,
        }
        for k, v in self.extra.items():
            key = k if k.startswith("{{") else "{{" + k.upper() + "}}"
            reps[key] = v
        return reps


def generate_prompt(
    template: TemplateInfo,
    ctx: PromptContext,
    output_dir: Path | None = None,
) -> tuple[str, Path | None]:
    """Fill a template with context values.

    Returns ``(filled_text, output_path)``. If *output_dir* is given the
    filled prompt is also written to disk; otherwise *output_path* is None.
    """
    content = template.path.read_text(encoding="utf-8")
    for placeholder, value in ctx.as_replacements().items():
        content = content.replace(placeholder, value)

    output_path: Path | None = None
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        fname = f"pentest_{ctx.session_id()}_{template.name}.txt"
        output_path = output_dir / fname
        output_path.write_text(content, encoding="utf-8")

    return content, output_path


# ── Standalone CLI ─────────────────────────────────────────────────────────


def main() -> None:
    """Minimal CLI: ``mcpstrike-prompt --target IP [--template NAME] [--list]``."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="mcpstrike-prompt",
        description=(
            "Generate pentest prompts from templates.\n\n"
            "Quick examples:\n"
            "  mcpstrike-prompt -t 10.0.0.5 --test-type web_app\n"
            "  mcpstrike-prompt -t 10.0.0.5 -d site.com --ua burp --out-of-scope-file scope.txt\n"
            "  mcpstrike-prompt --list-test-types\n"
            "  mcpstrike-prompt --list\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", metavar="IP/HOST",
                        help="Target IP or hostname (required unless --list / --list-test-types)")
    parser.add_argument("--domain", "-d", default="N/A", metavar="DOMAIN",
                        help="Domain name (default: N/A)")
    parser.add_argument("--template", default="autonomous", metavar="NAME",
                        help="Template name or partial match (default: autonomous). Use --list to browse.")
    parser.add_argument("--test-type", default="full", metavar="TYPE",
                        help=_TEST_TYPE_HELP)
    parser.add_argument("--list-test-types", action="store_true",
                        help="Show test types with descriptions and exit")
    parser.add_argument("--user-agent", "--ua", dest="user_agent", metavar="UA",
                        help=(
                            "User-Agent suffix injected into the prompt for all HTTP tools.\n"
                            f"Aliases: {', '.join(USER_AGENT_ALIASES)}.\n"
                            "Or pass a raw string. Example: --ua burp"
                        ))
    parser.add_argument("--out-of-scope-file", metavar="FILE",
                        help=(
                            "Path to a scope exclusion file. Supports sections:\n"
                            "  [domains]  [ips]  [paths]  [vulns]  [notes]\n"
                            "Lines without a header go to [notes]. Comments start with #."
                        ))
    parser.add_argument("--output-dir", "-o", metavar="DIR",
                        help="Directory to write the generated prompt file")
    parser.add_argument("--templates-dir", metavar="DIR",
                        help="Extra templates directory to scan")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available templates and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the first 3000 chars to stdout without writing to disk")
    args = parser.parse_args()

    if args.list_test_types:
        print("\nTest types and LLM behavior:\n")
        for name, desc in TEST_TYPE_DESCRIPTIONS.items():
            print(f"  {name:<12} {desc}")
        print()
        sys.exit(0)

    extra_dirs: list[Path] = []
    if args.templates_dir:
        extra_dirs.append(Path(args.templates_dir))

    mgr = TemplateManager(*extra_dirs)

    if args.list:
        templates = mgr.list_templates()
        if not templates:
            print("No templates found.")
            sys.exit(1)
        print(f"\nAvailable templates ({len(templates)}):\n")
        for i, t in enumerate(templates, 1):
            print(f"  [{i}] {t.name:<25} {t.description[:50]}")
        print(f"\nSupported placeholders:")
        for ph, desc in PLACEHOLDERS.items():
            print(f"  {ph:<35} {desc}")
        print(f"\nUser-Agent aliases: {', '.join(USER_AGENT_ALIASES)}")
        print(f"Run --list-test-types for test type details.")
        sys.exit(0)

    if not args.target:
        parser.error("--target is required (use --list to see templates)")

    tpl = mgr.get(args.template)
    if tpl is None:
        print(f"Template not found: {args.template}")
        print("Use --list to see available templates")
        sys.exit(1)

    # ── Out-of-scope ───────────────────────────────────────────────────────
    scope: dict[str, str] = {}
    if args.out_of_scope_file:
        scope = parse_scope_file(Path(args.out_of_scope_file))

    # ── User-Agent ─────────────────────────────────────────────────────────
    ua_full = resolve_user_agent(args.user_agent) if args.user_agent else ""

    ctx = PromptContext(
        target=args.target,
        domain=args.domain,
        test_type=args.test_type,
        user_agent=ua_full,
        user_agent_suffix=ua_full,
        out_of_scope_domains=scope.get("domains", "N/A"),
        out_of_scope_ips=scope.get("ips", "N/A"),
        out_of_scope_paths=scope.get("paths", "N/A"),
        out_of_scope_vulns=scope.get("vulns", "N/A"),
        out_of_scope_notes=scope.get("notes", "N/A"),
    )

    out_dir = Path(args.output_dir) if args.output_dir and not args.dry_run else None
    text, path = generate_prompt(tpl, ctx, output_dir=out_dir)

    if args.dry_run:
        print(text[:3000])
        if len(text) > 3000:
            print("\n... [truncated]")
    elif path:
        print(f"Prompt generated: {path}")
    else:
        print(text)


if __name__ == "__main__":
    main()
