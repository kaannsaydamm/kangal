"""Vulnerability patterns: port -> vuln, header -> vuln, path -> vuln, tech -> vuln.

Each pattern declares:
- id: short stable identifier
- severity: critical|high|medium|low|info
- vuln_class: category for grouping in the UI
- title: human-readable summary
- check: callable returning evidence dict (or None if not applicable)

VulnCorrelator iterates these and emits Finding rows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ---------- helpers ----------

def _http_evidence(asset_meta: dict, key: str) -> Optional[dict]:
    """Pull a key from the asset's meta (which holds the HTTP probe result)."""
    val = asset_meta.get(key)
    if not val:
        return None
    return {"key": key, "value": str(val)[:500]}


# ---------- pattern definitions ----------

@dataclass
class PortPattern:
    port: int
    severity: str
    vuln_class: str
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class HeaderPattern:
    header: Optional[str]  # "Server", "X-Powered-By", etc., or None for "missing X"
    severity: str
    vuln_class: str
    title: str
    should_be_missing: bool = False
    version_disclosure: bool = False  # emit only if header value matches version regex


@dataclass
class PathPattern:
    path: str
    severity: str
    vuln_class: str
    title: str


@dataclass
class TechPattern:
    name_regex: str  # matched against Server/X-Powered-By/Generator headers (case-insensitive)
    severity: str
    vuln_class: str
    title: str


PORT_PATTERNS: list[PortPattern] = [
    PortPattern(21, "high", "exposed-service", "FTP exposed to the internet"),
    PortPattern(23, "critical", "exposed-service", "Telnet exposed (cleartext credentials)"),
    PortPattern(135, "high", "exposed-service", "Windows RPC exposed"),
    PortPattern(139, "high", "exposed-service", "NetBIOS exposed"),
    PortPattern(445, "high", "exposed-service", "SMB exposed (EternalBlue class)"),
    PortPattern(1433, "critical", "exposed-service", "MSSQL exposed to the internet"),
    PortPattern(3306, "critical", "exposed-service", "MySQL exposed to the internet"),
    PortPattern(3389, "high", "exposed-service", "RDP exposed (brute-force surface)"),
    PortPattern(5432, "critical", "exposed-service", "PostgreSQL exposed to the internet"),
    PortPattern(5900, "high", "exposed-service", "VNC exposed"),
    PortPattern(6379, "critical", "exposed-service", "Redis exposed (often no auth)"),
    PortPattern(8089, "medium", "exposed-service", "Kibana/dev port exposed"),
    PortPattern(9200, "high", "exposed-service", "Elasticsearch exposed"),
    PortPattern(11211, "high", "exposed-service", "Memcached exposed (UDP amp risk)"),
    PortPattern(27017, "critical", "exposed-service", "MongoDB exposed (often no auth)"),
]

# Headers that should be present for security
REQUIRED_SECURITY_HEADERS: list[HeaderPattern] = [
    HeaderPattern("Content-Security-Policy", "medium", "missing-security-header", "Missing CSP header"),
    HeaderPattern("Strict-Transport-Security", "low", "missing-security-header", "Missing HSTS header"),
    HeaderPattern("X-Frame-Options", "low", "missing-security-header", "Missing X-Frame-Options (clickjacking)"),
    HeaderPattern("X-Content-Type-Options", "low", "missing-security-header", "Missing X-Content-Type-Options"),
    HeaderPattern("Referrer-Policy", "low", "missing-security-header", "Missing Referrer-Policy"),
]

# Headers whose version disclosure is informative
VERSION_DISCLOSURE: list[HeaderPattern] = [
    HeaderPattern("Server", "info", "info-disclosure", "Server version disclosed", version_disclosure=True),
    HeaderPattern("X-Powered-By", "low", "info-disclosure", "X-Powered-By discloses tech stack", version_disclosure=True),
    HeaderPattern("X-AspNet-Version", "low", "info-disclosure", "ASP.NET version disclosed", version_disclosure=True),
    HeaderPattern("X-AspNetMvc-Version", "low", "info-disclosure", "ASP.NET MVC version disclosed", version_disclosure=True),
]

# Sensitive paths that should not be reachable on a production host
PATH_PATTERNS: list[PathPattern] = [
    PathPattern("/.git/HEAD", "high", "exposed-path", "Git repository exposed via .git/HEAD"),
    PathPattern("/.env", "critical", "exposed-path", ".env file exposed (credentials leak)"),
    PathPattern("/.svn/entries", "high", "exposed-path", "Subversion metadata exposed"),
    PathPattern("/.hg/store", "high", "exposed-path", "Mercurial metadata exposed"),
    PathPattern("/phpinfo.php", "medium", "exposed-path", "phpinfo() exposed"),
    PathPattern("/info.php", "medium", "exposed-path", "phpinfo/info exposed"),
    PathPattern("/server-status", "medium", "exposed-path", "Apache server-status exposed"),
    PathPattern("/server-info", "medium", "exposed-path", "Apache server-info exposed"),
    PathPattern("/.DS_Store", "low", "exposed-path", ".DS_Store file exposed"),
    PathPattern("/backup.zip", "high", "exposed-path", "Backup archive exposed"),
    PathPattern("/backup.tar.gz", "high", "exposed-path", "Backup archive exposed"),
    PathPattern("/backup.sql", "critical", "exposed-path", "Database backup exposed"),
    PathPattern("/dump.sql", "critical", "exposed-path", "Database dump exposed"),
    PathPattern("/wp-config.php.bak", "critical", "exposed-path", "WordPress config backup exposed"),
    PathPattern("/config.php.bak", "high", "exposed-path", "Config backup exposed"),
    PathPattern("/swagger.json", "low", "exposed-path", "Swagger/OpenAPI spec exposed"),
    PathPattern("/api/swagger.json", "low", "exposed-path", "Swagger/OpenAPI spec exposed"),
    PathPattern("/openapi.json", "low", "exposed-path", "OpenAPI spec exposed"),
    PathPattern("/actuator", "medium", "exposed-path", "Spring Boot actuator exposed"),
    PathPattern("/actuator/env", "high", "exposed-path", "Spring Boot env actuator exposed"),
    PathPattern("/api/v1", "info", "exposed-path", "API root exposed"),
    PathPattern("/robots.txt", "info", "info-disclosure", "robots.txt exposed (low signal)"),
    PathPattern("/sitemap.xml", "info", "info-disclosure", "sitemap.xml exposed"),
    PathPattern("/.well-known/security.txt", "info", "info-disclosure", "security.txt exposed"),
]

# Tech signatures: regex against server / x-powered-by / generator header
TECH_PATTERNS: list[TechPattern] = [
    TechPattern(r"WordPress\s*[\d.]+", "info", "fingerprint", "WordPress detected"),
    TechPattern(r"Drupal\s*[\d.]+", "info", "fingerprint", "Drupal detected"),
    TechPattern(r"Joomla!?\s*[\d.]+", "info", "fingerprint", "Joomla detected"),
    TechPattern(r"Magento/?\s*[\d.]+", "info", "fingerprint", "Magento detected"),
    TechPattern(r"Shopify", "info", "fingerprint", "Shopify storefront"),
    TechPattern(r"Cloudflare", "info", "fingerprint", "Cloudflare in front"),
    TechPattern(r"nginx/([\d.]+)", "info", "fingerprint", "nginx version"),
    TechPattern(r"Apache/([\d.]+)", "info", "fingerprint", "Apache version"),
    TechPattern(r"Microsoft-IIS/([\d.]+)", "info", "fingerprint", "IIS version"),
    TechPattern(r"PHP/([\d.]+)", "info", "fingerprint", "PHP version"),
    TechPattern(r"Express", "info", "fingerprint", "Node.js Express detected"),
    TechPattern(r"ASP\.NET", "info", "fingerprint", "ASP.NET detected"),
    TechPattern(r"Tomcat", "info", "fingerprint", "Apache Tomcat detected"),
    TechPattern(r"Envoy", "info", "fingerprint", "Envoy proxy detected"),
    TechPattern(r"GitHub\.com", "info", "fingerprint", "GitHub Pages"),
    TechPattern(r"Vercel", "info", "fingerprint", "Vercel hosting"),
    TechPattern(r"Netlify", "info", "fingerprint", "Netlify hosting"),
    TechPattern(r"AmazonS3", "info", "fingerprint", "Amazon S3 hosting"),
]

VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def find_version(value: str) -> Optional[str]:
    if not value:
        return None
    m = VERSION_RE.search(value)
    return m.group(0) if m else None
