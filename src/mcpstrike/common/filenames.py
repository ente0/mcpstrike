"""Filename generation for pentest command output.

Single source of truth for output filename generation, used by the
mcpstrike client and (optionally) the server.
"""

from __future__ import annotations

import re

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# Phase prefix by tool — drives ordered, grep-friendly filenames.
_PHASE_MAP: dict[str, str] = {
    "nmap": "01", "masscan": "01", "ping": "01",
    "whatweb": "02", "wappalyzer": "02",
    "nikto": "03", "feroxbuster": "03", "gobuster": "03", "ffuf": "03", "dirsearch": "03",
    "nuclei": "04", "wpscan": "04",
    "smbclient": "05", "enum4linux": "05", "crackmapexec": "05",
    "katana": "06", "gospider": "06",
    "arjun": "07", "paramspider": "07",
    "xsser": "08", "dalfox": "08",
    "sqlmap": "09",
    "metasploit": "10", "msfconsole": "10",
    "linpeas": "11", "winpeas": "11",
}


def extract_target(args: list[str]) -> str:
    """Pull the first IP or domain out of a command's argv."""
    for arg in args:
        ip = _IP_RE.search(arg)
        if ip:
            return ip.group(0)
        if not arg.startswith("-"):
            dom = _DOMAIN_RE.search(arg)
            if dom:
                return dom.group(0)
    return "unknown_target"


def phase_prefix(command: str) -> str:
    """Return the 2-digit phase prefix for ``command`` (99 if unknown)."""
    return _PHASE_MAP.get(command.lower(), "99")


def scan_descriptor(command: str, args: list[str]) -> str:
    """Best-effort human-readable descriptor for a scan invocation."""
    if command == "nmap":
        if "-sV" in args and "-sC" in args:
            return "service_detection"
        if "-sV" in args:
            return "version_scan"
        if "-sC" in args:
            return "script_scan"
        if "-sS" in args:
            return "syn_scan"
        if "-sU" in args:
            return "udp_scan"
        if "-sn" in args or "-sP" in args:
            return "ping_sweep"
        if "-p-" in args:
            return "all_ports"
        if "-A" in args:
            return "aggressive_scan"
        if "-O" in args:
            return "os_detection"
        return "quick_scan"

    if command == "nikto":
        if "-Tuning" in args:
            return "tuned_scan"
        if "-ssl" in args:
            return "ssl_scan"
        return "web_scan"

    if command == "nuclei":
        if "-s" in args:
            try:
                sev = args[args.index("-s") + 1]
                return f"severity_{sev}"
            except IndexError:
                return "severity_all"
        return "template_scan" if "-t" in args else "full_scan"

    if command == "sqlmap":
        if "--dbs" in args:
            return "enumerate_dbs"
        if "--tables" in args:
            return "enumerate_tables"
        if "--dump" in args:
            return "dump_data"
        if "--batch" in args:
            return "auto_scan"
        return "injection_test"

    if command == "gobuster":
        if "dir" in args:
            return "directory_enum"
        if "dns" in args:
            return "subdomain_enum"
        if "vhost" in args:
            return "vhost_enum"
        return "fuzzing"

    if command == "feroxbuster":
        if "-x" in args:
            return "extension_scan"
        if "-d" in args:
            try:
                depth = args[args.index("-d") + 1]
                return f"depth_{depth}"
            except IndexError:
                pass
        return "directory_scan"

    if command == "katana":
        if "-d" in args:
            try:
                depth = args[args.index("-d") + 1]
                return f"crawl_depth_{depth}"
            except IndexError:
                pass
        return "web_crawl"

    if command == "curl":
        if "-I" in args or "--head" in args:
            return "headers_check"
        if "-X" in args:
            try:
                method = args[args.index("-X") + 1]
                return f"{method.lower()}_request"
            except IndexError:
                pass
        return "http_request"

    fallback = {
        "xsser": "xss_scan",
        "arjun": "param_discovery",
        "whatweb": "tech_fingerprint",
        "smbclient": "smb_enum",
        "enum4linux": "smb_full_enum",
        "wget": "download",
        "masscan": "port_scan",
    }
    if command in fallback:
        return fallback[command]

    # Otherwise, try to build something from the first few short flags.
    parts = [a.lstrip("-") for a in args[:3] if a.startswith("-") and len(a) <= 4]
    if parts:
        return "_".join(parts)

    target = extract_target(args)
    if target != "unknown_target":
        return target.replace(".", "_").replace(":", "_")[:20]

    return "scan"


class FilenameAllocator:
    """Stateful counter that produces unique, grep-friendly filenames.

    Usage::

        alloc = FilenameAllocator()
        alloc.next("nmap", ["-sV", "10.0.0.1"])   # "01_nmap_version_scan.txt"
        alloc.next("nmap", ["-sV", "10.0.0.2"])   # "01_nmap_version_scan_2.txt"
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def reset(self) -> None:
        self._counters.clear()

    def next(self, command: str, args: list[str]) -> str:
        prefix = phase_prefix(command)
        key = f"{prefix}_{command}"
        self._counters[key] = self._counters.get(key, 0) + 1
        count = self._counters[key]
        descriptor = scan_descriptor(command, args)
        if count > 1:
            return f"{prefix}_{command}_{descriptor}_{count}.txt"
        return f"{prefix}_{command}_{descriptor}.txt"
