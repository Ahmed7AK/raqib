"""
Raqib Hunter: find new domains that use UAE brand names, before anyone clicks them.

Sources:
  1. Certificate Transparency (crt.sh): certificates issued in the last N days whose names contain a brand keyword
  2. dnstwist (optional, if installed): registered look-alikes of each official domain
Each candidate is scored (engine.score_domain), saved to hunter_candidates.csv, and the top ones are
sent to the engine for a full scan (source="hunter"), so they appear on the dashboard with evidence.

Run:  python hunter.py --days 30 --max-scans 60
Note: crt.sh is slow and sometimes times out. Re-run, or lower the keyword list with --brands.
"""
import argparse
import csv
import json
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import engine


def crtsh(keyword: str, days: int) -> set:
    url = "https://crt.sh/?q=" + urllib.parse.quote(f"%{keyword}%") + "&output=json&exclude=expired"
    since = datetime.now(timezone.utc) - timedelta(days=days)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                rows = json.loads(r.read() or b"[]")
            out = set()
            for row in rows:
                nb = datetime.fromisoformat(row["not_before"]).replace(tzinfo=timezone.utc)
                if nb < since:
                    continue
                for name in row.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name:
                        out.add(name)
            return out
        except Exception as e:
            print(f"  crt.sh {keyword}: attempt {attempt + 1} failed ({type(e).__name__})")
            time.sleep(3)
    return set()


def dnstwist(domain: str) -> set:
    if not shutil.which("dnstwist"):
        return set()
    try:
        out = subprocess.run(["dnstwist", "--registered", "--format", "json", domain],
                             capture_output=True, text=True, timeout=240).stdout
        return {r["domain"].lower() for r in json.loads(out or "[]") if r.get("domain") != domain}
    except Exception:
        return set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--max-scans", type=int, default=60)
    ap.add_argument("--min-score", type=float, default=0.3)
    ap.add_argument("--brands", default="", help="comma-separated brand names to limit the run")
    ap.add_argument("--engine", default="http://127.0.0.1:8000")
    ap.add_argument("--no-scan", action="store_true")
    a = ap.parse_args()

    brands = [b for b in engine.KB if not a.brands or b["name"] in a.brands.split(",")]
    found: dict = {}
    for b in brands:
        for kw in [k for k in b.get("keywords", []) if len(k) >= 4]:
            names = crtsh(kw, a.days)
            print(f"[CT] {b['name']:<24} '{kw}': {len(names)} names")
            for n in names:
                found.setdefault(n, set()).add(f"ct:{kw}")
        for d in b.get("official_domains", []):
            if d.endswith(".gov.ae"):
                continue  # .gov.ae registrations are restricted; look-alikes live on other TLDs (caught by CT)
            for n in dnstwist(d):
                found.setdefault(n, set()).add(f"dnstwist:{d}")

    rows = []
    for host, src in found.items():
        if engine.official_brand_of(host):
            continue
        s = engine.score_domain(host)
        if s["score"] >= a.min_score:
            rows.append({"host": host, "score": s["score"], "brand": s["brand"], "sources": ";".join(sorted(src)),
                         "reasons": " | ".join(s["reasons"])})
    rows.sort(key=lambda r: -r["score"])
    with open("hunter_candidates.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["host", "score", "brand", "sources", "reasons"])
        w.writeheader()
        w.writerows(rows)

    by_brand: dict = {}
    for r in rows:
        by_brand[r["brand"]] = by_brand.get(r["brand"], 0) + 1
    print(f"\n{len(found)} names seen, {len(rows)} suspicious candidates (score >= {a.min_score}) in the last {a.days} days")
    for k, v in sorted(by_brand.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    if a.no_scan:
        return
    for r in rows[: a.max_scans]:
        body = json.dumps({"url": f"https://{r['host']}/", "source": "hunter"}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(a.engine + "/api/scan?background=true", data=body,
                                   headers={"Content-Type": "application/json"}), timeout=10).read()
            print(f"  queued {r['host']} ({r['score']})")
        except Exception as e:
            print(f"  could not queue {r['host']}: {e}")
        time.sleep(2)  # engine runs 3 scans at a time; don't flood it


if __name__ == "__main__":
    main()
