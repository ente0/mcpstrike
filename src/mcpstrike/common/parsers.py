"""Security-tool output parsers.

These were dead code in the legacy ``mcp_server.py`` — defined but never
registered as MCP tools. Here they're public functions and get exposed by
``server.app`` via ``@mcp.tool()`` so an autonomous LLM can request structured
findings right after running a scan.
"""

from __future__ import annotations

import re
from typing import Any


# ── nmap ────────────────────────────────────────────────────────────────────


def parse_nmap(content: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ports": [],
        "os_info": "Unknown",
        "hostname": "N/A",
        "mac_address": "N/A",
        "services": [],
        "vulnerabilities": [],
    }

    port_pattern = r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?"
    for match in re.finditer(port_pattern, content):
        port_info = {
            "port": match.group(1),
            "protocol": match.group(2).upper(),
            "state": match.group(3),
            "service": match.group(4),
            "version": match.group(5).strip() if match.group(5) else "N/A",
        }
        if port_info["state"] == "open":
            result["ports"].append(port_info)
            result["services"].append(port_info["service"])

    for pattern in (
        r"OS details?:\s*(.+)",
        r"Running:\s*(.+)",
        r"OS CPE:\s*(.+)",
        r"Service Info: OS:\s*([^;]+)",
    ):
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            result["os_info"] = m.group(1).strip()
            break

    hostname_match = re.search(r"Nmap scan report for\s+(\S+)", content)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)", content)
    if mac_match:
        result["mac_address"] = mac_match.group(1)

    vuln_patterns = [
        (r"VULNERABLE", "critical"),
        (r"CVE-\d{4}-\d+", "high"),
        (r"httponly flag not set", "medium"),
        (r"directory listing", "medium"),
    ]
    for pattern, severity in vuln_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            for line in content.splitlines():
                if re.search(pattern, line, re.IGNORECASE):
                    result["vulnerabilities"].append(
                        {
                            "type": pattern.replace(r"\.", ".").replace(".*", " "),
                            "severity": severity,
                            "evidence": line.strip()[:200],
                            "source": "nmap",
                        }
                    )
    return result


# ── whatweb ─────────────────────────────────────────────────────────────────


def parse_whatweb(content: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "technologies": [],
        "server": "Unknown",
        "cookies": [],
        "headers": {},
        "frameworks": [],
    }

    server_match = re.search(r"HTTPServer\[([^\]]+)\]", content)
    if server_match:
        result["server"] = server_match.group(1)

    apache_match = re.search(r"Apache\[([^\]]+)\]", content)
    if apache_match:
        result["technologies"].append(
            {"name": "Apache", "version": apache_match.group(1), "category": "Web Server"}
        )

    cookie_match = re.search(r"Cookies\[([^\]]+)\]", content)
    if cookie_match:
        result["cookies"] = cookie_match.group(1).split(",")

    if "PHP" in content:
        php_match = re.search(r"PHP\[([^\]]*)\]", content)
        result["technologies"].append(
            {
                "name": "PHP",
                "version": php_match.group(1) if php_match else "Unknown",
                "category": "Programming Language",
            }
        )

    framework_patterns = [
        (r"DVWA", "DVWA", "Vulnerable Application"),
        (r"WordPress", "WordPress", "CMS"),
        (r"Drupal", "Drupal", "CMS"),
        (r"Joomla", "Joomla", "CMS"),
        (r"Laravel", "Laravel", "Framework"),
        (r"Django", "Django", "Framework"),
        (r"React", "React", "Frontend Framework"),
        (r"Angular", "Angular", "Frontend Framework"),
        (r"Vue", "Vue.js", "Frontend Framework"),
        (r"jQuery", "jQuery", "JavaScript Library"),
        (r"Bootstrap", "Bootstrap", "CSS Framework"),
        (r"nginx", "Nginx", "Web Server"),
        (r"Node\.js|Express", "Node.js", "Runtime"),
        (r"Juice Shop", "OWASP Juice Shop", "Vulnerable Application"),
    ]
    for pattern, name, category in framework_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            result["technologies"].append(
                {"name": name, "version": "Detected", "category": category}
            )
            result["frameworks"].append(name)
    return result


# ── nuclei ──────────────────────────────────────────────────────────────────


def parse_nuclei(content: str) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    nuclei_pattern = r"\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(?:\s*\[([^\]]+)\])?"

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info",
    }

    for match in re.finditer(nuclei_pattern, content):
        severity = match.group(1).lower()
        template = match.group(2)
        protocol = match.group(3)
        url = match.group(4)
        info = match.group(5) or ""
        vulnerabilities.append(
            {
                "type": template.replace("-", " ").title(),
                "severity": severity_map.get(severity, "info"),
                "protocol": protocol,
                "url": url,
                "info": info,
                "source": "nuclei",
                "template_id": template,
            }
        )

    simple_patterns = [
        (r"sql.?injection", "SQL Injection", "critical"),
        (r"xss|cross.?site.?scripting", "Cross-Site Scripting (XSS)", "high"),
        (r"csrf|cross.?site.?request", "Cross-Site Request Forgery", "medium"),
        (r"open.?redirect", "Open Redirect", "medium"),
        (r"ssrf|server.?side.?request", "Server-Side Request Forgery", "high"),
        (r"rce|remote.?code.?exec", "Remote Code Execution", "critical"),
        (r"lfi|local.?file.?inc", "Local File Inclusion", "high"),
        (r"rfi|remote.?file.?inc", "Remote File Inclusion", "critical"),
        (r"xxe|xml.?external", "XML External Entity", "high"),
        (r"idor|insecure.?direct", "Insecure Direct Object Reference", "medium"),
        (r"broken.?auth", "Broken Authentication", "high"),
        (r"sensitive.?data.?exposure", "Sensitive Data Exposure", "high"),
        (r"security.?misconfiguration", "Security Misconfiguration", "medium"),
        (r"default.?credential", "Default Credentials", "critical"),
    ]
    for pattern, name, severity in simple_patterns:
        if re.search(pattern, content, re.IGNORECASE) and not any(
            v["type"] == name for v in vulnerabilities
        ):
            vulnerabilities.append(
                {
                    "type": name,
                    "severity": severity,
                    "source": "nuclei",
                    "evidence": "Pattern matched in scan output",
                }
            )
    return vulnerabilities


# ── nikto ───────────────────────────────────────────────────────────────────


def parse_nikto(content: str) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    nikto_patterns = [
        (r"OSVDB-\d+", "OSVDB Reference", "medium"),
        (r"X-Frame-Options header is not present", "Missing X-Frame-Options", "medium"),
        (r"X-XSS-Protection header is not defined", "Missing XSS Protection Header", "low"),
        (r"X-Content-Type-Options header is not set", "Missing Content-Type-Options", "low"),
        (r"Server leaks inodes via ETags", "Information Disclosure via ETags", "low"),
        (r"Apache/.+ appears to be outdated", "Outdated Apache Version", "high"),
        (
            r"The anti-clickjacking X-Frame-Options header is not present",
            "Clickjacking Vulnerability",
            "medium",
        ),
        (r"Cookie .+ created without the httponly flag", "Cookie Missing HttpOnly", "medium"),
        (r"Cookie .+ created without the secure flag", "Cookie Missing Secure Flag", "medium"),
        (r"Directory indexing found", "Directory Listing Enabled", "medium"),
        (r"/config/", "Exposed Configuration Directory", "critical"),
        (r"\.git/", "Exposed Git Repository", "critical"),
        (r"\.env", "Exposed Environment File", "critical"),
        (r"phpinfo\(\)", "PHPInfo Exposure", "medium"),
        (r"backup|\.bak|\.old", "Backup Files Found", "medium"),
    ]
    for pattern, name, severity in nikto_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 100)
            context = content[start:end].replace("\n", " ").strip()
            vulnerabilities.append(
                {
                    "type": name,
                    "severity": severity,
                    "evidence": context[:200],
                    "source": "nikto",
                }
            )

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for v in vulnerabilities:
        key = (v["type"], v.get("evidence", "")[:50])
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


# ── dirb / gobuster / feroxbuster ───────────────────────────────────────────


def parse_dirb(content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    interesting = [
        (r"/admin", "Admin Panel Found", "medium"),
        (r"/backup", "Backup Directory", "high"),
        (r"/config", "Configuration Directory", "critical"),
        (r"/\.git", "Git Repository Exposed", "critical"),
        (r"/\.svn", "SVN Repository Exposed", "critical"),
        (r"/\.env", "Environment File Exposed", "critical"),
        (r"/phpinfo", "PHPInfo Page", "medium"),
        (r"/phpmyadmin", "PHPMyAdmin Found", "high"),
        (r"/wp-admin", "WordPress Admin", "medium"),
        (r"/wp-config", "WordPress Config", "critical"),
        (r"/robots\.txt", "Robots.txt Found", "info"),
        (r"/sitemap", "Sitemap Found", "info"),
        (r"/api", "API Endpoint", "info"),
        (r"/swagger|/api-docs", "API Documentation", "medium"),
        (r"/debug", "Debug Endpoint", "high"),
        (r"/test", "Test Endpoint", "low"),
        (r"/upload", "Upload Directory", "medium"),
        (r"/files", "Files Directory", "medium"),
        (r"/private", "Private Directory", "high"),
        (r"/secret", "Secret Directory", "high"),
        (r"/\.htaccess", "HTAccess Exposed", "high"),
        (r"/\.htpasswd", "HTPasswd Exposed", "critical"),
        (r"/server-status", "Server Status Page", "medium"),
        (r"/server-info", "Server Info Page", "medium"),
    ]
    for pattern, name, severity in interesting:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(
                {
                    "type": name,
                    "severity": severity,
                    "source": "directory_enumeration",
                    "path": pattern.replace("\\", ""),
                }
            )
    return findings


# ── auto-dispatch ───────────────────────────────────────────────────────────


def auto_parse(command: str, content: str) -> dict[str, Any]:
    """Route a command's raw output to the right parser.

    Returns ``{"parser": name, "findings": ...}`` so the caller can merge it
    into ``session_metadata.json`` without having to know which parser ran.
    """
    cmd = command.lower()
    if cmd == "nmap":
        return {"parser": "nmap", "findings": parse_nmap(content)}
    if cmd == "whatweb":
        return {"parser": "whatweb", "findings": parse_whatweb(content)}
    if cmd == "nuclei":
        return {"parser": "nuclei", "findings": parse_nuclei(content)}
    if cmd == "nikto":
        return {"parser": "nikto", "findings": parse_nikto(content)}
    if cmd in {"dirb", "gobuster", "feroxbuster", "ffuf", "dirsearch"}:
        return {"parser": "dirb", "findings": parse_dirb(content)}
    return {"parser": None, "findings": None}
