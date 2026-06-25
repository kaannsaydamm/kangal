"""Tool output adapters: turn ToolExecutor.parsed into Kangal assets + findings.

Each adapter maps one tool name -> a parse function:

    parse(parsed: list[dict[str, Any]],
          raw: str,
          target: str) -> AdapterResult

AdapterResult contains:
- assets: list of dicts ready for Asset ORM (type/value/parent_value/meta/discovered_by)
- findings: list of dicts ready for Finding ORM (severity/vuln_class/title/evidence)
- agent_name: string written to discovered_by + events.stage

Adapters never raise — they return empty lists on parse failure. Tool
executor already returned ToolResult.ok=False in that case, so the caller
decides what to do.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable


# ---------- result type ----------

@dataclass
class AdapterResult:
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    agent_name: str = ""


ParseFn = Callable[[list[dict[str, Any]], str, str], AdapterResult]


# ---------- tiny severity helpers ----------

def _sev(s: str | None) -> str:
    s = (s or "info").lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    return "info"


# ---------- shared subdetection helpers ----------

def _nuclei_severity(rec: dict[str, Any]) -> str:
    info = rec.get("info") or {}
    sev = (info.get("severity") or rec.get("severity") or "info").lower()
    return _sev(sev)


# ---------- per-tool adapters ----------

def adapt_nuclei(parsed, raw, target):
    out = AdapterResult(agent_name="nuclei")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        info = rec.get("info") or {}
        name = info.get("name") or rec.get("template") or "nuclei-finding"
        sev = _nuclei_severity(rec)
        matcher_name = rec.get("matcher-name") or rec.get("matcher_name")
        out.findings.append({
            "severity": sev,
            "vuln_class": (info.get("classification") or {}).get("cve-id") or info.get("category") or "nuclei-finding",
            "title": f"[nuclei] {name}"[:512],
            "evidence": {
                "matched-at": rec.get("matched-at"),
                "matcher-name": matcher_name,
                "template-id": rec.get("template-id") or info.get("templateID"),
                "type": rec.get("type"),
                "host": rec.get("host"),
            },
        })
        host = rec.get("host") or rec.get("matched-at")
        if host:
            out.assets.append({
                "type": "endpoint",
                "value": host,
                "meta": {"via": "nuclei", "template-id": rec.get("template-id")},
                "discovered_by": "nuclei",
            })
    return out


def adapt_subfinder(parsed, raw, target):
    out = AdapterResult(agent_name="subfinder")
    # subfinder JSON: {"host":"...","input":"..."}
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        host = rec.get("host") or rec.get("domain") or rec.get("value")
        if not host:
            continue
        out.assets.append({
            "type": "subdomain",
            "value": host,
            "parent_value": target,
            "meta": {"source": rec.get("source") or "subfinder"},
            "discovered_by": "subfinder",
        })
    return out


def adapt_amass(parsed, raw, target):
    out = AdapterResult(agent_name="amass")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        host = rec.get("name") or rec.get("domain")
        if not host:
            continue
        out.assets.append({
            "type": "subdomain",
            "value": host,
            "parent_value": target,
            "meta": {
                "source": rec.get("source") or "amass",
                "tag": rec.get("tag"),
                "addresses": rec.get("addresses"),
            },
            "discovered_by": "amass",
        })
    return out


def adapt_httpx(parsed, raw, target):
    out = AdapterResult(agent_name="httpx")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        url = rec.get("url") or ""
        host = rec.get("host") or rec.get("input")
        if not host:
            continue
        out.assets.append({
            "type": "url",
            "value": url or f"https://{host}",
            "parent_value": host,
            "meta": {
                "status_code": rec.get("status-code") or rec.get("status_code"),
                "title": rec.get("title"),
                "tech": rec.get("tech") or [],
                "content_length": rec.get("content-length") or rec.get("content_length"),
                "scheme": rec.get("scheme"),
                "cn": rec.get("cn") or rec.get("tls", {}).get("cn") if isinstance(rec.get("tls"), dict) else None,
            },
            "discovered_by": "httpx",
        })
        # tls / cert exposures → low/info finding
        tls = rec.get("tls") if isinstance(rec.get("tls"), dict) else None
        if tls and tls.get("not_after"):
            out.findings.append({
                "severity": "info",
                "vuln_class": "tls-meta",
                "title": f"tls cert for {host}",
                "evidence": {
                    "issuer": tls.get("issuer_org") or tls.get("issuer_dn"),
                    "not_after": tls.get("not_after"),
                    "cn": tls.get("cn"),
                },
            })
    return out


def adapt_dnsx(parsed, raw, target):
    out = AdapterResult(agent_name="dnsx")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        host = rec.get("host") or rec.get("name")
        if not host:
            continue
        out.assets.append({
            "type": "dns-record",
            "value": host,
            "parent_value": target,
            "meta": {
                "a": rec.get("a") or [],
                "aaaa": rec.get("aaaa") or [],
                "cname": rec.get("cname") or [],
                "mx": rec.get("mx") or [],
                "ns": rec.get("ns") or [],
                "txt": rec.get("txt") or [],
            },
            "discovered_by": "dnsx",
        })
    return out


def adapt_naabu(parsed, raw, target):
    out = AdapterResult(agent_name="naabu")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        host = rec.get("host") or rec.get("ip")
        port = rec.get("port")
        if not host or not port:
            continue
        out.assets.append({
            "type": "port",
            "value": f"{host}:{port}",
            "parent_value": host,
            "meta": {"port": port, "protocol": rec.get("protocol") or "tcp"},
            "discovered_by": "naabu",
        })
    return out


def adapt_nmap(parsed, raw, target):
    out = AdapterResult(agent_name="nmap")
    # nmap xml is parsed coarsely by executor; but if user runs -oX it's xml.
    # Best-effort regex over raw when parsed is empty.
    if parsed:
        for rec in parsed:
            if not isinstance(rec, dict):
                continue
            host = rec.get("ip") or rec.get("host") or rec.get("address")
            ports = rec.get("ports") or []
            for p in ports:
                out.assets.append({
                    "type": "service",
                    "value": f"{host}:{p.get('port')}/{p.get('protocol','tcp')}",
                    "parent_value": host,
                    "meta": {
                        "port": p.get("port"),
                        "name": p.get("name"),
                        "product": p.get("product"),
                        "version": p.get("version"),
                        "banner": p.get("banner"),
                    },
                    "discovered_by": "nmap",
                })
    else:
        # regex fallback over raw XML
        host_re = re.compile(r'address addr="(?P<ip>[^"]+)"')
        port_re = re.compile(r'<port port="(?P<port>\d+)" protocol="(?P<proto>[^"]+)">.*?<service name="(?P<name>[^"]*)"(?: product="(?P<product>[^"]*)")?(?: version="(?P<version>[^"]*)")?',
                             re.S)
        for host_match in host_re.finditer(raw or ""):
            ip = host_match.group("ip")
            # find all ports in roughly the same <host> block — keep simple:
            for p_match in port_re.finditer(raw or ""):
                out.assets.append({
                    "type": "service",
                    "value": f"{ip}:{p_match.group('port')}/{p_match.group('proto')}",
                    "parent_value": ip,
                    "meta": {
                        "port": int(p_match.group("port")),
                        "protocol": p_match.group("proto"),
                        "name": p_match.group("name") or None,
                        "product": p_match.group("product") or None,
                        "version": p_match.group("version") or None,
                    },
                    "discovered_by": "nmap",
                })
    return out


def adapt_nikto(parsed, raw, target):
    out = AdapterResult(agent_name="nikto")
    # nikto json: {"vulnerability": "...", "id":"...", "method":"...", "url":"...", "msg":""}
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        url = rec.get("url") or rec.get("hostname")
        msg = rec.get("msg") or rec.get("vulnerability") or "nikto finding"
        out.findings.append({
            "severity": "medium",
            "vuln_class": rec.get("id") or "nikto-finding",
            "title": f"[nikto] {msg}"[:512],
            "evidence": {
                "url": url,
                "method": rec.get("method"),
                "references": rec.get("references"),
            },
        })
        if url:
            out.assets.append({
                "type": "endpoint",
                "value": url,
                "parent_value": target,
                "meta": {"via": "nikto", "id": rec.get("id")},
                "discovered_by": "nikto",
            })
    return out


def adapt_sqlmap(parsed, raw, target):
    out = AdapterResult(agent_name="sqlmap")
    if not parsed and raw:
        # sqlmap doesn't always emit json — fall back to text scan
        m = re.search(r"Parameter: '?(?P<param>[^'\s]+)'?\s+.*?Type: (?P<type>\w[\w\s-]*?)\s+payload:", raw, re.S | re.I)
        if m:
            parsed = [{
                "parameter": m.group("param"),
                "type": m.group("type").strip(),
                "raw": True,
            }]
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        param = rec.get("parameter") or rec.get("param")
        sqli_type = rec.get("type") or "sql injection"
        out.findings.append({
            "severity": "critical",
            "vuln_class": "sqli",
            "title": f"[sqlmap] {sqli_type} via parameter '{param}'",
            "evidence": {
                "parameter": param,
                "type": sqli_type,
                "dbms": rec.get("dbms"),
                "payload": rec.get("payload"),
                "url": rec.get("url") or target,
            },
        })
    return out


def adapt_dalfox(parsed, raw, target):
    out = AdapterResult(agent_name="dalfox")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        out.findings.append({
            "severity": "high",
            "vuln_class": rec.get("type") or "xss",
            "title": f"[dalfox] {rec.get('type','xss')} on {rec.get('data','?')}"[:512],
            "evidence": {
                "data": rec.get("data"),
                "param": rec.get("param"),
                "payload": rec.get("payload"),
                "evidence": rec.get("evidence"),
            },
        })
    return out


def adapt_hydra(parsed, raw, target):
    out = AdapterResult(agent_name="hydra")
    # hydra text: "[22][ssh] host: 10.0.0.1   login: admin   password: hunter2"
    if not parsed:
        for m in re.finditer(r"\[(?P<port>\d+)\]\[(?P<svc>[^\]]+)\][^\\n]*?login:\s*(?P<user>\S+)\s+password:\s*(?P<pass>\S+)", raw or ""):
            out.findings.append({
                "severity": "critical",
                "vuln_class": "credential-leak",
                "title": f"[hydra] {m.group('svc')} creds {m.group('user')}:***@{target}",
                "evidence": {
                    "service": m.group("svc"),
                    "username": m.group("user"),
                    # NEVER store plaintext — adapter hashes it via ruflo at call site
                    "password_hash_required": True,
                },
            })
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        out.findings.append({
            "severity": "critical",
            "vuln_class": "credential-leak",
            "title": f"[hydra] {rec.get('service','?')} creds {rec.get('username','?')}:***@{target}",
            "evidence": {
                "service": rec.get("service"),
                "username": rec.get("username"),
                "password_hash_required": True,
            },
        })
    return out


def adapt_nxc(parsed, raw, target):
    out = AdapterResult(agent_name="nxc")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        host = rec.get("host")
        if host:
            out.assets.append({
                "type": "ad-host",
                "value": host,
                "parent_value": target,
                "meta": {
                    "domain": rec.get("domain"),
                    "os": rec.get("os"),
                    "signing": rec.get("signing"),
                    "smbv1": rec.get("smbv1"),
                    "shares": rec.get("shares"),
                },
                "discovered_by": "nxc",
            })
        if rec.get("admin") or rec.get("pwned"):
            out.findings.append({
                "severity": "critical" if rec.get("admin") else "high",
                "vuln_class": "credential-reuse",
                "title": f"[nxc] {rec.get('username','?')}@{host} {'admin' if rec.get('admin') else 'pwned'}",
                "evidence": {
                    "host": host,
                    "service": rec.get("service") or "smb",
                    "username": rec.get("username"),
                },
            })
    return out


def adapt_bloodhound(parsed, raw, target):
    out = AdapterResult(agent_name="bloodhound")
    # bloodhound-python json has users, groups, computers, sessions.
    if isinstance(parsed, list) and parsed:
        # parsed is a list of dicts OR a single dict; be lenient
        for rec in parsed:
            if not isinstance(rec, dict):
                continue
            kind = rec.get("type") or "ad-object"
            value = rec.get("name") or rec.get("id")
            if value:
                out.assets.append({
                    "type": kind,
                    "value": value,
                    "parent_value": target,
                    "meta": {"domain": rec.get("domain"), "properties": rec.get("properties") or {}},
                    "discovered_by": "bloodhound",
                })
    return out


def adapt_trufflehog(parsed, raw, target):
    out = AdapterResult(agent_name="trufflehog")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        out.findings.append({
            "severity": "high",
            "vuln_class": "secret-leak",
            "title": f"[trufflehog] {rec.get('DetectorName','secret')} in {rec.get('SourceMetadata',{}).get('Data','?')}",
            "evidence": {
                "detector": rec.get("DetectorName"),
                "source": rec.get("SourceMetadata"),
                "verified": rec.get("Verified"),
                # Raw NEVER returned — hash if you need to retain
                "secret_hash_required": True,
            },
        })
    return out


def adapt_gitleaks(parsed, raw, target):
    out = AdapterResult(agent_name="gitleaks")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        out.findings.append({
            "severity": "high",
            "vuln_class": "secret-leak",
            "title": f"[gitleaks] {rec.get('RuleID','secret')} @ {rec.get('File','?')}:{rec.get('StartLine','?')}",
            "evidence": {
                "rule": rec.get("RuleID"),
                "file": rec.get("File"),
                "line": rec.get("StartLine"),
                "commit": rec.get("Commit"),
                "author": rec.get("Author"),
                "secret_hash_required": True,
            },
        })
    return out


def adapt_prowler(parsed, raw, target):
    out = AdapterResult(agent_name="prowler")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        sev = (rec.get("Severity") or rec.get("severity") or "medium").lower()
        out.findings.append({
            "severity": _sev(sev),
            "vuln_class": rec.get("CheckID") or "cloud-misconfig",
            "title": f"[prowler] {rec.get('CheckTitle', rec.get('CheckID','cloud-finding'))}"[:512],
            "evidence": {
                "service": rec.get("ServiceName"),
                "region": rec.get("Region"),
                "resource": rec.get("ResourceId"),
                "status": rec.get("Status"),
                "compliance": rec.get("Compliance"),
            },
        })
    return out


def adapt_kubehunter(parsed, raw, target):
    out = AdapterResult(agent_name="kube-hunter")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        sev = (rec.get("severity") or "medium").lower()
        out.findings.append({
            "severity": _sev(sev),
            "vuln_class": "k8s-finding",
            "title": f"[kube-hunter] {rec.get('vulnerability','k8s-finding')}"[:512],
            "evidence": {
                "category": rec.get("category"),
                "target": rec.get("target") or rec.get("host") or target,
                "description": rec.get("description"),
            },
        })
    return out


def adapt_wafw00f(parsed, raw, target):
    out = AdapterResult(agent_name="wafw00f")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        waf = rec.get("firewall") or rec.get("waf")
        if waf and waf.lower() != "none":
            out.findings.append({
                "severity": "info",
                "vuln_class": "waf-detected",
                "title": f"[wafw00f] WAF detected: {waf}",
                "evidence": {"url": target, "manufacturer": waf},
            })
    return out


def adapt_semgrep(parsed, raw, target):
    out = AdapterResult(agent_name="semgrep")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        results = rec.get("results") or []
        for r in results:
            sev = (r.get("extra", {}).get("severity") or "warning").lower()
            sev = "high" if sev == "error" else ("medium" if sev == "warning" else "low")
            out.findings.append({
                "severity": sev,
                "vuln_class": r.get("check_id") or "sast",
                "title": f"[semgrep] {r.get('check_id','sast-finding')} @ {r.get('path','?')}:{r.get('start',{}).get('line','?')}"[:512],
                "evidence": {
                    "path": r.get("path"),
                    "line": r.get("start", {}).get("line"),
                    "message": r.get("extra", {}).get("message"),
                    "cwe": r.get("extra", {}).get("metadata", {}).get("cwe"),
                },
            })
    return out


def adapt_trivy(parsed, raw, target):
    out = AdapterResult(agent_name="trivy")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        vulns = rec.get("Vulnerabilities") or []
        for v in vulns:
            sev = (v.get("Severity") or "UNKNOWN").lower()
            sev = _sev(sev) if sev in ("critical", "high", "medium", "low") else "info"
            out.findings.append({
                "severity": sev,
                "vuln_class": v.get("VulnerabilityID") or "cve",
                "title": f"[trivy] {v.get('VulnerabilityID','?')} in {v.get('PkgName','?')}",
                "evidence": {
                    "target": rec.get("Target"),
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "title": v.get("Title"),
                },
            })
    return out


def adapt_theharvester(parsed, raw, target):
    out = AdapterResult(agent_name="theHarvester")
    # harvester JSON: {"emails":[...], "hosts":[...], "domains":[...], "interesting_urls":[...]}
    if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
        parsed = [parsed[0]]
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        for h in rec.get("hosts") or []:
            out.assets.append({
                "type": "subdomain",
                "value": h,
                "parent_value": target,
                "meta": {"source": "theHarvester"},
                "discovered_by": "theHarvester",
            })
        for e in rec.get("emails") or []:
            out.assets.append({
                "type": "email",
                "value": e,
                "parent_value": target,
                "meta": {"source": "theHarvester"},
                "discovered_by": "theHarvester",
            })
        for u in rec.get("interesting_urls") or []:
            out.assets.append({
                "type": "url",
                "value": u,
                "parent_value": target,
                "meta": {"source": "theHarvester", "interesting": True},
                "discovered_by": "theHarvester",
            })
    return out


def adapt_responder(parsed, raw, target):
    out = AdapterResult(agent_name="responder")
    for rec in parsed or []:
        if not isinstance(rec, dict):
            continue
        out.findings.append({
            "severity": "high",
            "vuln_class": "llmnr-nbns-poison",
            "title": f"[responder] hash captured for {rec.get('client','?')}",
            "evidence": {
                "client": rec.get("client"),
                "user": rec.get("user"),
                "hash": rec.get("hash"),
                "protocol": rec.get("protocol"),
            },
        })
    return out


# ---------- registry ----------

ADAPTERS: dict[str, ParseFn] = {
    "nuclei": adapt_nuclei,
    "subfinder": adapt_subfinder,
    "amass": adapt_amass,
    "httpx": adapt_httpx,
    "dnsx": adapt_dnsx,
    "naabu": adapt_naabu,
    "nmap": adapt_nmap,
    "nikto": adapt_nikto,
    "sqlmap": adapt_sqlmap,
    "dalfox": adapt_dalfox,
    "hydra": adapt_hydra,
    "nxc": adapt_nxc,
    "bloodhound-python": adapt_bloodhound,
    "trufflehog": adapt_trufflehog,
    "gitleaks": adapt_gitleaks,
    "prowler": adapt_prowler,
    "kube-hunter": adapt_kubehunter,
    "wafw00f": adapt_wafw00f,
    "semgrep": adapt_semgrep,
    "trivy": adapt_trivy,
    "theHarvester": adapt_theharvester,
    "responder": adapt_responder,
}


def adapt(tool_name: str, parsed: list[dict[str, Any]], raw: str, target: str) -> AdapterResult:
    fn = ADAPTERS.get(tool_name)
    if fn is None:
        return AdapterResult(agent_name=tool_name)
    try:
        return fn(parsed, raw, target)
    except Exception:
        return AdapterResult(agent_name=tool_name)


def known_adapters() -> list[str]:
    return sorted(ADAPTERS.keys())
