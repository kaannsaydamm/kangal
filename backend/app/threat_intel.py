"""Threat intelligence: live CVE (NVD) + MITRE ATT&CK feed with disk+memory caching.

Routes (registered in main.py):
    GET /api/threat-intel/cve/{cve_id}            single CVE from NVD
    GET /api/threat-intel/recent-cves             recent CVEs filtered by severity
    GET /api/threat-intel/mitre/{technique_id}    single MITRE technique
    GET /api/threat-intel/mitre/search?q=...      text search across techniques
    GET /api/threat-intel/feed?refresh=true       combined: recent CVEs + curated MITRE list

Cache TTLs:
    - per-CVE NVD           24h
    - recent CVEs list       1h
    - MITRE STIX bundle     24h
    - combined feed          1h

Offline behaviour:
    - If outbound HTTP fails AND a cached copy exists -> return cached copy with stale=True.
    - If outbound HTTP fails AND no cache exists     -> callers raise 503 with a clear message.

No third-party deps beyond httpx (already in requirements).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

# ---------- config ----------

CACHE_DIR = Path(os.environ.get("KANGAL_THREAT_CACHE", Path(__file__).resolve().parent.parent / ".cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

HTTP_TIMEOUT_S = 20.0
NVD_RATE_SLEEP_S = 0.25  # be polite — no key = ~5 req/30s

# ---------- ttl constants (seconds) ----------
TTL_CVE_DETAIL = 24 * 3600
TTL_RECENT_LIST = 1 * 3600
TTL_MITRE_BUNDLE = 24 * 3600
TTL_FEED = 1 * 3600

# MITRE kill-chain order (tactic precedence, enterprise ATT&CK)
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# ---------- in-process memory cache ----------
# Keyed by cache filename; values are dicts with the loaded data + the
# timestamp the disk file was last refreshed, so we can detect stale without
# hitting disk on every request.
_MEM: dict[str, dict[str, Any]] = {}


def _now() -> float:
    return time.time()


def _safe_filename(s: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in s)


def cache_path(key: str) -> Path:
    """Return the on-disk cache file path for a given logical key."""
    return CACHE_DIR / _safe_filename(key)


def cache_load(key: str, max_age_s: int) -> dict[str, Any] | None:
    """Return cached payload for *key* if it exists and is younger than *max_age_s*.

    Returns the raw cached payload (a dict). Returns None when the file is
    missing, malformed, or older than the TTL. Callers should treat None as
    "go refetch; if refetch fails, fall back to stale data via cache_load_stale".
    """
    cached, ts, _stale = cache_load_with_meta(key)
    if cached is None:
        return None
    if (_now() - ts) > max_age_s:
        return None
    return cached


def cache_load_with_meta(key: str) -> tuple[dict[str, Any] | None, float, bool]:
    """Like cache_load but always returns (data | None, mtime, stale_vs_ttl).

    stale_vs_ttl is True when the cached file exists but is older than its
    intended TTL — useful for serving a "stale=true" payload when the live
    fetch fails.
    """
    p = cache_path(key)
    # in-memory short-circuit
    mem = _MEM.get(key)
    if mem is not None:
        return mem["data"], mem["ts"], False
    if not p.exists():
        return None, 0.0, False
    try:
        ts = p.stat().st_mtime
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None, 0.0, False
    return data, ts, False


def cache_save(key: str, data: dict[str, Any]) -> None:
    """Persist *data* under *key* and update the in-memory copy."""
    p = cache_path(key)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
    _MEM[key] = {"data": data, "ts": _now()}


def cache_clear() -> None:
    """Wipe both the in-memory and on-disk cache (test helper)."""
    _MEM.clear()
    for f in CACHE_DIR.glob("*.json"):
        try:
            f.unlink()
        except Exception:
            pass


# ---------- NVD ----------

def _nvd_params(extra: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = dict(extra)
    if NVD_API_KEY:
        params["apiKey"] = NVD_API_KEY
    return params


async def fetch_nvd_cve(cve_id: str) -> dict[str, Any] | None:
    """Fetch a single CVE from NVD. Returns the raw vulnerabilities[0] item, or None on error."""
    cve_id = cve_id.strip().upper()
    cache_key = f"nvd-{cve_id}.json"
    cached = cache_load(cache_key, TTL_CVE_DETAIL)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
            r = await client.get(NVD_BASE, params=_nvd_params({"cveId": cve_id}))
            if r.status_code != 200:
                return _stale_or_none(cache_key)
            payload = r.json()
    except Exception:
        return _stale_or_none(cache_key)

    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return _stale_or_none(cache_key)
    item = vulns[0]
    cache_save(cache_key, item)
    return item


_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


async def fetch_nvd_recent(days: int, severity: str) -> list[dict[str, Any]]:
    """Fetch recent CVEs from NVD within the last *days* days, filtered to *severity*+.

    NVD's date-window endpoint is rate-limited and sometimes rejected for
    unauthenticated callers depending on the window; we try `lastMod*` first
    (most recent), then fall back to `pubStartDate/pubEndDate` (publication
    date) before giving up to the cached copy.
    """
    days = max(1, min(int(days), 30))
    sev = (severity or "high").strip().upper()
    if sev not in _SEVERITY_RANK:
        sev = "HIGH"

    cache_key = f"nvd-recent-{days}d-{sev}.json"
    cached = cache_load(cache_key, TTL_RECENT_LIST)
    if cached is not None:
        return cached

    from datetime import datetime, timedelta, timezone

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    window_strategies = (
        ("lastModStartDate", "lastModEndDate"),
        ("pubStartDate", "pubEndDate"),
    )

    payload: dict[str, Any] | None = None
    last_status: int | None = None
    last_err: str | None = None
    for start_key, end_key in window_strategies:
        params = _nvd_params(
            {
                start_key: start.strftime(fmt),
                end_key: end.strftime(fmt),
                "resultsPerPage": 50,
            }
        )
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
                r = await client.get(NVD_BASE, params=params)
                last_status = r.status_code
                if r.status_code == 200:
                    payload = r.json()
                    break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    if not payload:
        stale = _stale_or_none(cache_key)
        if isinstance(stale, list) and stale:
            return stale
        # Surface the failure reason to the route so it can put it in the 503 body.
        raise ThreatIntelFetchError(
            f"NVD recent feed failed (status={last_status}, err={last_err})"
        )

    vulns = payload.get("vulnerabilities") or []
    threshold = _SEVERITY_RANK[sev]
    out: list[dict[str, Any]] = []
    for v in vulns:
        sev_v3 = _extract_severity(v)
        if sev_v3 and _SEVERITY_RANK.get(sev_v3, 0) >= threshold:
            out.append(v)
    cache_save(cache_key, out)
    return out


class ThreatIntelFetchError(RuntimeError):
    """Raised when a live threat-intel fetch fails AND no usable cache exists."""


def _extract_severity(cve_item: dict[str, Any]) -> str | None:
    """Pull the CVSSv3 baseSeverity from an NVD vulnerabilities[] entry."""
    metrics = (cve_item.get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = (arr[0] or {}).get("cvssData") or {}
            sev = data.get("baseSeverity")
            if sev:
                return str(sev).upper()
    return None


def _stale_or_none(cache_key: str) -> Any:
    """Best-effort fallback: return whatever is on disk for *cache_key*, ignoring TTL.

    Used so a flapping live feed can still serve data when the upstream is down.
    """
    try:
        p = cache_path(cache_key)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def cve_to_threat(cve_item: dict[str, Any], stale: bool = False) -> dict[str, Any] | None:
    """Normalize a single NVD vulnerabilities[] entry to a flat dict."""
    if not cve_item:
        return None
    cve = cve_item.get("cve") or {}
    cve_id = cve.get("id") or ""
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = ""
    for d in descriptions:
        if (d.get("lang") or "").lower() == "en":
            description = d.get("value") or ""
            break
    if not description and descriptions:
        description = descriptions[0].get("value") or ""

    metrics = cve.get("metrics") or {}
    cvss_v3: dict[str, Any] | None = None
    cvss_v2: dict[str, Any] | None = None
    for key, bucket in (("cvssMetricV31", "v3"), ("cvssMetricV30", "v3"), ("cvssMetricV2", "v2")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        data = (arr[0] or {}).get("cvssData") or {}
        out = {
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
        if bucket == "v3" and cvss_v3 is None:
            cvss_v3 = {k: v for k, v in out.items() if v is not None}
        elif bucket == "v2" and cvss_v2 is None:
            cvss_v2 = {k: v for k, v in out.items() if v is not None}

    references = []
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if url:
            references.append(url)

    return {
        "id": cve_id,
        "description": description,
        "cvss_v3": cvss_v3,
        "cvss_v2": cvss_v2,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "references": references,
        "source": "NVD",
        "stale": bool(stale),
    }


# ---------- MITRE ATT&CK ----------

async def fetch_mitre_bundle() -> dict[str, Any]:
    """Return the parsed MITRE enterprise ATT&CK STIX bundle (cached 24h)."""
    cache_key = "mitre-enterprise.json"
    cached = cache_load(cache_key, TTL_MITRE_BUNDLE)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S, follow_redirects=True) as client:
            r = await client.get(MITRE_BUNDLE_URL)
            if r.status_code != 200:
                stale = _stale_or_none(cache_key)
                if isinstance(stale, dict) and stale:
                    return stale
                return {}
            data = r.json()
    except Exception:
        stale = _stale_or_none(cache_key)
        if isinstance(stale, dict) and stale:
            return stale
        return {}

    if not data:
        return {}

    cache_save(cache_key, data)
    return data


def _iter_objects(bundle: dict[str, Any], obj_type: str) -> list[dict[str, Any]]:
    """Yield STIX objects of a given type from a bundle."""
    out: list[dict[str, Any]] = []
    for o in bundle.get("objects") or []:
        if o.get("type") == obj_type:
            out.append(o)
    return out


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        eid = ref.get("external_id")
        if eid:
            return eid
    return None


def _is_revoked_or_deprecated(obj: dict[str, Any]) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def find_mitre_technique(bundle: dict[str, Any], technique_id: str) -> dict[str, Any] | None:
    """Find a technique by its MITRE external id (e.g. T1190)."""
    if not bundle or not technique_id:
        return None
    target = technique_id.strip().upper()
    for o in _iter_objects(bundle, "attack-pattern"):
        if _is_revoked_or_deprecated(o):
            continue
        eid = _external_id(o)
        if eid and eid.upper() == target:
            return o
    return None


def search_mitre(bundle: dict[str, Any], query: str, limit: int = 25) -> list[dict[str, Any]]:
    """Substring search across technique name + description (case-insensitive)."""
    if not bundle or not query:
        return []
    needle = query.strip().lower()
    if len(needle) < 2:
        return []
    out: list[dict[str, Any]] = []
    for o in _iter_objects(bundle, "attack-pattern"):
        if _is_revoked_or_deprecated(o):
            continue
        name = (o.get("name") or "").lower()
        desc = (o.get("description") or "").lower()
        if needle in name or needle in desc:
            out.append(o)
        if len(out) >= limit:
            break
    return out


def _mitre_mitigation_ids(bundle: dict[str, Any], technique: dict[str, Any]) -> list[str]:
    """Return external_ids of course-of-action objects that mitigate *technique*."""
    if not bundle or not technique:
        return []
    tech_id = _external_id(technique)
    if not tech_id:
        return []
    mitigations: list[str] = []
    for coa in _iter_objects(bundle, "course-of-action"):
        if _is_revoked_or_deprecated(coa):
            continue
        # The relationship lives in `relationship` objects; we iterate them.
        # To avoid double iteration, the loop below does it.
        pass

    for rel in _iter_objects(bundle, "relationship"):
        if _is_revoked_or_deprecated(rel):
            continue
        if rel.get("relationship_type") != "mitigates":
            continue
        src = rel.get("source_ref") or ""
        tgt = rel.get("target_ref") or ""
        if not (src.startswith("course-of-action--") and tgt.startswith("attack-pattern--")):
            continue
        # Resolve target attack-pattern -> external id
        target_obj = next(
            (o for o in bundle.get("objects") or [] if o.get("id") == tgt),
            None,
        )
        if not target_obj or _external_id(target_obj) != tech_id:
            continue
        coa_obj = next(
            (o for o in bundle.get("objects") or [] if o.get("id") == src),
            None,
        )
        if coa_obj:
            eid = _external_id(coa_obj)
            if eid and eid not in mitigations:
                mitigations.append(eid)
    return mitigations


def mitre_to_threat(technique: dict[str, Any], bundle: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Normalize a MITRE attack-pattern object to a flat dict."""
    if not technique:
        return None
    ext_id = _external_id(technique)
    if not ext_id:
        return None

    tactics: list[str] = []
    for kc in technique.get("kill_chain_phases") or []:
        name = kc.get("phase_name")
        if name and name not in tactics:
            tactics.append(name)

    platforms = technique.get("x_mitre_platforms") or []
    if not isinstance(platforms, list):
        platforms = []

    data_sources = technique.get("x_mitre_data_sources") or []
    if not isinstance(data_sources, list):
        data_sources = []

    mitigations: list[str] = []
    if bundle:
        mitigations = _mitre_mitigation_ids(bundle, technique)

    url = f"https://attack.mitre.org/techniques/{ext_id}/"
    for ref in technique.get("external_references") or []:
        if (ref.get("source_name") or "").lower() == "mitre-attack" and ref.get("url"):
            url = ref["url"]
            break

    return {
        "id": ext_id,
        "name": technique.get("name") or ext_id,
        "tactics": tactics,
        "description": technique.get("description") or "",
        "url": url,
        "mitigations": mitigations,
        "platforms": platforms,
        "data_sources": data_sources,
        "source": "MITRE",
        "stale": False,
    }


def curated_mitre(bundle: dict[str, Any], limit: int = 30) -> list[dict[str, Any]]:
    """Return *limit* MITRE techniques ordered by kill-chain precedence.

    Within the same tactic the order is alphabetical by external id, so the
    output is stable across runs.
    """
    if not bundle:
        return []
    techs = [o for o in _iter_objects(bundle, "attack-pattern") if not _is_revoked_or_deprecated(o)]
    by_id = {(_external_id(o) or "").upper(): o for o in techs}

    def _key(o: dict[str, Any]) -> tuple[int, str]:
        phases = o.get("kill_chain_phases") or []
        if phases:
            phase = phases[0].get("phase_name") or ""
            idx = TACTIC_ORDER.index(phase) if phase in TACTIC_ORDER else len(TACTIC_ORDER)
        else:
            idx = len(TACTIC_ORDER)
        return (idx, _external_id(o) or "")

    techs.sort(key=_key)
    out: list[dict[str, Any]] = []
    for o in techs[:limit]:
        norm = mitre_to_threat(o, bundle)
        if norm:
            out.append(norm)
    return out


# ---------- combined feed ----------

async def threat_intel_feed(refresh: bool = False, days: int = 7, severity: str = "HIGH") -> dict[str, Any]:
    """Build the combined feed: recent CVEs + curated MITRE list."""
    feed_cache = "threat-intel-feed.json"
    if not refresh:
        cached = cache_load(feed_cache, TTL_FEED)
        if cached is not None:
            return cached

    recent_task = fetch_nvd_recent(days=days, severity=severity)
    bundle_task = fetch_mitre_bundle()
    recent_raw: list[dict[str, Any]] = []
    bundle: dict[str, Any] = {}
    nvd_err: str | None = None
    try:
        recent_raw = await recent_task
    except ThreatIntelFetchError as e:
        nvd_err = str(e)
        # try stale disk copy
        stale = _stale_or_none(f"nvd-recent-{days}d-{severity}.json")
        if isinstance(stale, list):
            recent_raw = stale
    try:
        bundle = await bundle_task
    except Exception:
        bundle = {}

    recent_cves = [cve_to_threat(v) for v in (recent_raw or [])]
    recent_cves = [c for c in recent_cves if c]
    if nvd_err:
        for c in recent_cves:
            c["stale"] = True

    mitre_techniques = curated_mitre(bundle, limit=30)

    from datetime import datetime, timezone

    feed = {
        "recent_cves": recent_cves,
        "mitre_techniques": mitre_techniques,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stale": bool(nvd_err) or not bundle,
        "meta": {
            "nvd_api_key_configured": bool(NVD_API_KEY),
            "cache_dir": str(CACHE_DIR),
            "window_days": days,
            "severity": severity,
            "errors": {"nvd": nvd_err} if nvd_err else {},
        },
    }
    cache_save(feed_cache, feed)
    return feed


# ---------- module smoke test ----------

if __name__ == "__main__":  # pragma: no cover
    print("[threat_intel] module ok; cache dir:", CACHE_DIR)