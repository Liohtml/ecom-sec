#!/usr/bin/env python3
"""Find new vulnerability candidates for the shop platforms ecomsec supports.

Sources
  * NVD CVE API 2.0 – keyword and CPE searches (JTL-Shop, Shopware, Shopify apps)
  * OSV.dev        – all advisories for the Shopware Composer packages

Compares the hits with the curated files in advisories/*.toml and
advisories/ignored.toml and writes

  advisories/candidates.json   machine readable list for the review agent
  advisories/drafts/<platform>-<date>.toml   best-effort draft entries
                               (draft = true, therefore NOT evaluated by scans)

Usage: scripts/advisory_sync.py [--days 30] [--out advisories/candidates.json]
Environment: NVD_API_KEY (optional, raises the NVD rate limit)
Exit code 0; prints a Markdown summary; sets GITHUB_OUTPUT `count` when run in Actions.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADV_DIR = ROOT / "advisories"

PLATFORMS = {
    "jtl5": {
        "nvd_keywords": ["JTL-Shop", "JTL Shop", "jtl-software"],
        "nvd_cpe": ["cpe:2.3:a:jtl-software:jtl-shop", "cpe:2.3:a:jtl-software:jtl_shop"],
        "must_match": re.compile(r"jtl", re.I),
        "osv_packages": [],
    },
    "shopware6": {
        "nvd_keywords": ["Shopware"],
        "nvd_cpe": ["cpe:2.3:a:shopware:shopware"],
        "must_match": re.compile(r"shopware", re.I),
        "osv_packages": ["shopware/core", "shopware/platform", "shopware/administration", "shopware/storefront"],
        "min_fixed_major": 6,
    },
    "shopify": {
        "nvd_keywords": ["Shopify app", "Shopify theme"],
        "nvd_cpe": [],
        "must_match": re.compile(r"shopify", re.I),
        "osv_packages": [],
    },
}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"
UA = "ecomsec-advisory-sync/1.0 (+https://github.com/liohtml/ecom-sec)"


def http_json(url: str, data: dict | None = None, headers: dict | None = None, retries: int = 4) -> dict:
    body = json.dumps(data).encode() if data is not None else None
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs)
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < retries - 1:
                time.sleep(6 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            raise
    return {}


def load_known() -> tuple[set[str], set[str]]:
    """Return (known ids incl. aliases, ignored ids)."""
    known: set[str] = set()
    for f in ADV_DIR.glob("*.toml"):
        if f.name == "ignored.toml":
            continue
        for a in tomllib.loads(f.read_text()).get("advisory", []):
            known.add(a["id"].upper())
            for alias in a.get("aliases", []):
                known.add(alias.upper())
    for f in (ADV_DIR / "drafts").glob("*.toml") if (ADV_DIR / "drafts").is_dir() else []:
        for a in tomllib.loads(f.read_text()).get("advisory", []):
            known.add(a["id"].upper())
    ignored: set[str] = set()
    ig = ADV_DIR / "ignored.toml"
    if ig.exists():
        ignored = {e["id"].upper() for e in tomllib.loads(ig.read_text()).get("ignore", [])}
    return known, ignored


def nvd_search(params: dict, api_key: str | None) -> list[dict]:
    out: list[dict] = []
    start = 0
    headers = {"apiKey": api_key} if api_key else {}
    while True:
        q = dict(params, resultsPerPage=200, startIndex=start)
        url = f"{NVD_URL}?{urllib.parse.urlencode(q)}"
        data = http_json(url, headers=headers)
        out.extend(v["cve"] for v in data.get("vulnerabilities", []))
        total = data.get("totalResults", 0)
        start += 200
        if start >= total:
            break
        time.sleep(1.0 if api_key else 6.5)
    time.sleep(1.0 if api_key else 6.5)
    return out


def cvss(cve: dict) -> tuple[float | None, str | None]:
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            d = m[key][0].get("cvssData", {})
            return d.get("baseScore"), d.get("vectorString")
    return None, None


def severity_for(score: float | None) -> str:
    if score is None:
        return "warning"
    if score >= 7.0:
        return "critical"
    if score >= 4.0:
        return "warning"
    return "info"


def ranges_from_cpe(cve: dict, cpe_prefixes: list[str]) -> tuple[list[str], list[str]]:
    affected: list[str] = []
    fixed: list[str] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria", "")
                if cpe_prefixes and not any(crit.startswith(p) for p in cpe_prefixes):
                    continue
                if not m.get("vulnerable", True):
                    continue
                lo = m.get("versionStartIncluding")
                hi = m.get("versionEndExcluding")
                hi_inc = m.get("versionEndIncluding")
                parts = []
                if lo:
                    parts.append(f">={lo}")
                if hi:
                    parts.append(f"<{hi}")
                    fixed.append(hi)
                elif hi_inc:
                    parts.append(f"<={hi_inc}")  # lint will flag; agent must resolve
                if not parts:
                    # exact version in the CPE string
                    ver = crit.split(":")[5] if crit.count(":") >= 5 else "*"
                    if ver not in ("*", "-", ""):
                        parts.append(ver)
                if parts:
                    r = " ".join(parts)
                    if r not in affected:
                        affected.append(r)
    return affected, sorted(set(fixed))


def nvd_candidates(platform: str, cfg: dict, since: dt.datetime, api_key: str | None) -> list[dict]:
    seen: dict[str, dict] = {}
    base = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    for kw in cfg["nvd_keywords"]:
        try:
            for cve in nvd_search(dict(base, keywordSearch=kw), api_key):
                seen[cve["id"]] = cve
        except Exception as e:  # noqa: BLE001
            print(f"WARN NVD keyword {kw!r}: {e}", file=sys.stderr)
    for cpe in cfg["nvd_cpe"]:
        try:
            for cve in nvd_search(dict(base, virtualMatchString=cpe), api_key):
                seen[cve["id"]] = cve
        except Exception as e:  # noqa: BLE001
            print(f"WARN NVD cpe {cpe!r}: {e}", file=sys.stderr)
    out = []
    for cve in seen.values():
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        if not cfg["must_match"].search(desc + " " + json.dumps(cve.get("configurations", []))):
            continue
        score, vector = cvss(cve)
        affected, fixed = ranges_from_cpe(cve, cfg["nvd_cpe"])
        out.append({
            "id": cve["id"],
            "platform": platform,
            "source": "nvd",
            "title": desc[:160],
            "description": desc,
            "score": score,
            "vector": vector,
            "severity": severity_for(score),
            "published": cve.get("published", "")[:10],
            "modified": cve.get("lastModified", "")[:10],
            "affected": affected,
            "fixed_in": fixed,
            "references": [r["url"] for r in cve.get("references", [])][:8],
            "aliases": [],
        })
    return out


def osv_candidates(platform: str, cfg: dict, since: dt.datetime) -> list[dict]:
    out: dict[str, dict] = {}
    for pkg in cfg["osv_packages"]:
        try:
            data = http_json(OSV_URL, {"package": {"name": pkg, "ecosystem": "Packagist"}})
        except Exception as e:  # noqa: BLE001
            print(f"WARN OSV {pkg}: {e}", file=sys.stderr)
            continue
        for v in data.get("vulns", []):
            modified = v.get("modified", "")[:19]
            try:
                if dt.datetime.fromisoformat(modified) < since:
                    continue
            except ValueError:
                pass
            vid = v["id"]
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            key = cve or vid
            affected, fixed = [], []
            for a in v.get("affected", []):
                if a.get("package", {}).get("name") not in cfg["osv_packages"]:
                    continue
                for r in a.get("ranges", []):
                    intro, fix = None, None
                    for ev in r.get("events", []):
                        intro = ev.get("introduced", intro)
                        if "fixed" in ev:
                            fix = ev["fixed"]
                            parts = []
                            if intro and intro != "0":
                                parts.append(f">={intro}")
                            parts.append(f"<{fix}")
                            rng = " ".join(parts)
                            if rng not in affected:
                                affected.append(rng)
                            if fix not in fixed:
                                fixed.append(fix)
            sev = (v.get("database_specific", {}) or {}).get("severity", "").lower()
            severity = {"critical": "critical", "high": "critical", "moderate": "warning", "medium": "warning", "low": "info"}.get(sev, "warning")
            entry = out.setdefault(key, {
                "id": key,
                "platform": platform,
                "source": "osv",
                "title": v.get("summary", "")[:160],
                "description": (v.get("details") or "")[:1200],
                "score": None,
                "vector": next((s.get("score") for s in v.get("severity", []) if s.get("type", "").startswith("CVSS")), None),
                "severity": severity,
                "published": v.get("published", "")[:10],
                "modified": v.get("modified", "")[:10],
                "affected": [],
                "fixed_in": [],
                "references": [r["url"] for r in v.get("references", [])][:8],
                "aliases": sorted({vid, *aliases} - {key}),
            })
            for rng in affected:
                if rng not in entry["affected"]:
                    entry["affected"].append(rng)
            for f in fixed:
                if f not in entry["fixed_in"]:
                    entry["fixed_in"].append(f)
    entries = list(out.values())
    for e in entries:
        # Collapse ranges with the same lower bound to the highest fix
        # (OSV lists one range per fixed release of a branch).
        best: dict[str, str] = {}
        for rng in e["affected"]:
            lo, _, hi = rng.rpartition("<")
            lo = lo.strip()
            if not hi:
                best.setdefault(rng, "")
                continue
            if lo not in best or version_key(hi) > version_key(best[lo]):
                best[lo] = hi
        e["affected"] = [f"{lo} <{hi}".strip() if hi else lo for lo, hi in best.items()]
        e["fixed_in"] = sorted({hi for hi in best.values() if hi}, key=version_key)
    if cfg.get("min_fixed_major"):
        # Drop advisories that only concern older major versions (e.g. Shopware 5).
        def relevant(e: dict) -> bool:
            majors = [int(f.split(".")[0]) for f in e["fixed_in"] if f.split(".")[0].isdigit()]
            return not majors or max(majors) >= cfg["min_fixed_major"]
        entries = [e for e in entries if relevant(e)]
    return entries


def version_key(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.-]", v))


def toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def write_drafts(cands: list[dict], today: str) -> list[Path]:
    written = []
    by_platform: dict[str, list[dict]] = {}
    for c in cands:
        by_platform.setdefault(c["platform"], []).append(c)
    (ADV_DIR / "drafts").mkdir(exist_ok=True)
    for platform, items in by_platform.items():
        path = ADV_DIR / "drafts" / f"{platform}-{today}.toml"
        lines = [
            f"# Automatisch erzeugte Entwürfe vom {today} – NICHT aktiv (draft = true).",
            "# Versionsbereiche und Titel prüfen, dann nach advisories/<platform>.toml übernehmen",
            "# und `draft` entfernen. Siehe docs/ADVISORIES.md.",
            "",
        ]
        for c in items:
            lines += [
                "[[advisory]]",
                f"id = {toml_str(c['id'])}",
                f"platform = {toml_str(platform)}",
                f"title = {toml_str(c['title'] or c['id'])}",
                f"severity = {toml_str(c['severity'])}",
            ]
            if c.get("score") is not None:
                lines.append(f"score = {c['score']}")
            lines.append("affected = [" + ", ".join(toml_str(a) for a in c["affected"]) + "]")
            lines.append("fixed_in = [" + ", ".join(toml_str(f) for f in c["fixed_in"]) + "]")
            if c["references"]:
                lines.append(f"reference = {toml_str(c['references'][0])}")
            lines.append(f"published = {c['published'] or today}")
            lines.append(f"source = {toml_str(c['source'])}")
            if c.get("aliases"):
                lines.append("aliases = [" + ", ".join(toml_str(a) for a in c["aliases"]) + "]")
            lines.append("draft = true")
            lines.append("")
        path.write_text("\n".join(lines))
        written.append(path)
    return written


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30, help="look back this many days (modified date, max 120)")
    ap.add_argument("--out", default=str(ADV_DIR / "candidates.json"))
    ap.add_argument("--no-drafts", action="store_true")
    args = ap.parse_args()

    # The NVD API rejects date windows above 120 days (HTTP 404).
    since = dt.datetime.utcnow() - dt.timedelta(days=min(args.days, 120))
    api_key = os.environ.get("NVD_API_KEY")
    known, ignored = load_known()
    today = dt.date.today().isoformat()

    cands: list[dict] = []
    for platform, cfg in PLATFORMS.items():
        for c in nvd_candidates(platform, cfg, since, api_key) + osv_candidates(platform, cfg, since):
            ids = {c["id"].upper(), *(a.upper() for a in c.get("aliases", []))}
            if ids & known or ids & ignored:
                continue
            cands.append(c)
    # de-duplicate by id
    uniq: dict[str, dict] = {}
    for c in cands:
        uniq.setdefault(c["id"].upper(), c)
    cands = sorted(uniq.values(), key=lambda c: (c["platform"], c["published"]), reverse=False)

    Path(args.out).write_text(json.dumps({"generated": today, "since": since.isoformat(), "candidates": cands}, indent=2, ensure_ascii=False))
    drafts = [] if args.no_drafts or not cands else write_drafts(cands, today)

    print(f"## Advisory-Sync {today}\n")
    print(f"Zeitraum: letzte {args.days} Tage · bekannte IDs: {len(known)} · ignoriert: {len(ignored)}\n")
    if not cands:
        print("Keine neuen Kandidaten.")
    else:
        print("| ID | Plattform | Schwere | Veröffentlicht | Betroffen | Behoben | Titel |")
        print("|---|---|---|---|---|---|---|")
        for c in cands:
            print(f"| {c['id']} | {c['platform']} | {c['severity']} | {c['published']} | {', '.join(c['affected']) or '?'} | {', '.join(c['fixed_in']) or '?'} | {c['title'][:80]} |")
        if drafts:
            print("\nEntwürfe: " + ", ".join(str(p.relative_to(ROOT)) for p in drafts))
    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as fh:
            fh.write(f"count={len(cands)}\n")
            fh.write(f"drafts={' '.join(str(p.relative_to(ROOT)) for p in drafts)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
