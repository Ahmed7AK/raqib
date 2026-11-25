"""
Site intelligence: when a domain was created, by whom, where it is hosted, and what other
security services say about it. Every source is optional: a missing API key or a timeout
gives "not_configured" / "error", never a crash.

Keys (all free tiers):
  GSB_API_KEY        Google Safe Browsing v4 (free, non-commercial)
  VT_API_KEY         VirusTotal public API (free: 4 requests/min, 500/day)
  URLHAUS_AUTH_KEY   abuse.ch URLhaus (free Auth-Key from auth.abuse.ch)
  URLSCAN_API_KEY    urlscan.io (optional; search works without it, slower limits)
No key needed: RDAP/WHOIS, DNS, ipinfo.io, Wayback Machine, crt.sh, OpenPhish feed.
"""
import asyncio
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

GSB_KEY = os.getenv("GSB_API_KEY", "")
VT_KEY = os.getenv("VT_API_KEY", "")
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
UA = "Raqib/1.0 (UAE scam-site analysis; hackathon prototype)"

_cache: dict = {}
_vt_calls: list = []
_openphish = {"ts": 0.0, "hosts": set()}


def _cached(key, ttl=3600):
    v = _cache.get(key)
    return v[1] if v and time.time() - v[0] < ttl else None


def _store(key, val):
    _cache[key] = (time.time(), val)
    return val


def _days_since(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _vcard(entity: dict, field: str) -> Optional[str]:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            v = item[3]
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v if x)
            return str(v) if v else None
    return None


# ---------------------------------------------------------------- who and when
async def rdap_domain(c: httpx.AsyncClient, domain: str) -> dict:
    r = await c.get(f"https://rdap.org/domain/{domain}", timeout=6)
    if r.status_code != 200:
        raise RuntimeError(f"RDAP {r.status_code}")
    j = r.json()
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    out = {"created": ev.get("registration"), "updated": ev.get("last changed"),
           "expires": ev.get("expiration"), "status": j.get("status", []),
           "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])], "source": "RDAP"}
    for ent in j.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            out["registrar"] = _vcard(ent, "fn")
            out["registrar_abuse"] = next((_vcard(s, "email") for s in ent.get("entities", [])
                                           if "abuse" in s.get("roles", [])), None)
        if "registrant" in roles:
            out["registrant"] = {"name": _vcard(ent, "fn"), "org": _vcard(ent, "org"),
                                 "country": (_vcard(ent, "adr") or "").split(",")[-1].strip() or None}
    return out


async def whois43(domain: str) -> dict:
    """Plain WHOIS fallback (port 43), e.g. for ccTLDs without RDAP."""
    async def ask(server, q):
        rd, wr = await asyncio.wait_for(asyncio.open_connection(server, 43), 5)
        wr.write((q + "\r\n").encode())
        await wr.drain()
        data = await asyncio.wait_for(rd.read(65536), 6)
        wr.close()
        return data.decode("utf-8", "ignore")

    tld = domain.rsplit(".", 1)[-1]
    refer = re.search(r"^(?:refer|whois):\s*(\S+)", await ask("whois.iana.org", tld), re.M)
    if not refer:
        raise RuntimeError("no WHOIS server")
    txt = await ask(refer.group(1), domain)

    def grab(*keys):
        for k in keys:
            m = re.search(rf"^\s*{k}\s*:\s*(.+)$", txt, re.I | re.M)
            if m:
                return m.group(1).strip()
        return None
    return {"created": grab("Creation Date", "Created", "Registered on", "Registration Time", "created"),
            "expires": grab("Registry Expiry Date", "Expiry Date", "Expiration Date"),
            "registrar": grab("Registrar", "Registrar Name", "Sponsoring Registrar"),
            "registrant": {"name": grab("Registrant Name"), "org": grab("Registrant Organization", "Registrant"),
                           "country": grab("Registrant Country")},
            "source": f"WHOIS {refer.group(1)}"}


async def dns_records(domain: str) -> dict:
    import dns.asyncresolver
    import dns.resolver
    res = dns.asyncresolver.Resolver()
    res.lifetime = 3
    out = {}
    for t in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            ans = await res.resolve(domain, t)
            out[t] = [a.to_text().strip('"') for a in ans][:8]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            out[t] = []
        except Exception:
            out[t] = None  # unknown (timeout etc.), not "empty"
    out["spf"] = any("v=spf1" in x for x in (out.get("TXT") or []))
    return out


async def wayback_first(c: httpx.AsyncClient, domain: str) -> dict:
    r = await c.get("https://web.archive.org/cdx/search/cdx",
                    params={"url": domain, "output": "json", "limit": "1", "fl": "timestamp"}, timeout=8)
    rows = r.json() if r.text.strip() else []
    if len(rows) < 2:
        return {"first": None, "captures": False}
    ts = rows[1][0]
    return {"first": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T00:00:00+00:00", "captures": True}


async def crtsh_first(c: httpx.AsyncClient, domain: str) -> dict:
    r = await c.get("https://crt.sh/", params={"q": domain, "output": "json"}, timeout=10)
    rows = r.json() if r.text.strip().startswith("[") else []
    dates = sorted(x["not_before"] for x in rows if x.get("not_before"))
    return {"first": dates[0] + "+00:00" if dates else None, "certs": len(rows)}


# ---------------------------------------------------------------- where
async def ip_info(c: httpx.AsyncClient, ip: str) -> dict:
    r = await c.get(f"https://ipinfo.io/{ip}/json", timeout=5)
    j = r.json()
    org = j.get("org", "")
    asn, _, name = org.partition(" ")
    return {"ip": ip, "asn": asn or None, "org": name or org or None, "country": j.get("country"),
            "city": j.get("city"), "region": j.get("region"), "reverse_dns": j.get("hostname")}


async def ip_rdap(c: httpx.AsyncClient, ip: str) -> dict:
    r = await c.get(f"https://rdap.org/ip/{ip}", timeout=6)
    j = r.json()
    abuse = None
    for ent in j.get("entities", []):
        if "abuse" in ent.get("roles", []):
            abuse = _vcard(ent, "email")
        for sub in ent.get("entities", []):
            if "abuse" in sub.get("roles", []):
                abuse = abuse or _vcard(sub, "email")
    return {"network": j.get("name"), "country": j.get("country"), "abuse_email": abuse}


async def favicon_hash(c: httpx.AsyncClient, url: str) -> Optional[str]:
    if not url or not url.startswith("http"):
        return None
    r = await c.get(url, timeout=5)
    return hashlib.sha1(r.content).hexdigest() if r.status_code == 200 and r.content else None


async def bot_fetch(c: httpx.AsyncClient, url: str) -> dict:
    """Fetch like a plain bot (no JS, no phone profile). Used to spot cloaking."""
    r = await c.get(url, timeout=8, headers={"User-Agent": "python-httpx/0.27"})
    return {"final_url": str(r.url), "status": r.status_code}


# ---------------------------------------------------------------- what other sites say
async def safe_browsing(c: httpx.AsyncClient, url: str) -> dict:
    link = f"https://transparencyreport.google.com/safe-browsing/search?url={url}"
    if not GSB_KEY:
        return {"source": "Google Safe Browsing", "status": "not_configured", "link": link}
    body = {"client": {"clientId": "raqib", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                           "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    r = await c.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}", json=body, timeout=5)
    m = r.json().get("matches", [])
    return {"source": "Google Safe Browsing", "status": "listed" if m else "clean",
            "detail": ", ".join(sorted({x["threatType"] for x in m})) or "no match (suspected-risk list)", "link": link}


async def virustotal(c: httpx.AsyncClient, domain: str) -> dict:
    link = f"https://www.virustotal.com/gui/domain/{domain}"
    if not VT_KEY:
        return {"source": "VirusTotal", "status": "not_configured", "link": link}
    now = time.time()
    _vt_calls[:] = [t for t in _vt_calls if now - t < 60]
    if len(_vt_calls) >= 4:
        return {"source": "VirusTotal", "status": "skipped", "detail": "free quota: 4 lookups/min", "link": link}
    _vt_calls.append(now)
    r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": VT_KEY}, timeout=8)
    if r.status_code == 404:
        return {"source": "VirusTotal", "status": "unknown", "detail": "never seen by VirusTotal", "link": link}
    a = r.json().get("data", {}).get("attributes", {})
    s = a.get("last_analysis_stats", {})
    mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
    status = "listed" if mal >= 2 else "mixed" if (mal == 1 or sus >= 1) else "clean"
    return {"source": "VirusTotal", "status": status, "malicious": mal, "suspicious": sus,
            "detail": f"{mal} engines malicious, {sus} suspicious, of {sum(s.values()) or '?'}", "link": link}


async def urlhaus(c: httpx.AsyncClient, host: str) -> dict:
    link = f"https://urlhaus.abuse.ch/browse.php?search={host}"
    if not URLHAUS_KEY:
        return {"source": "URLhaus (abuse.ch)", "status": "not_configured", "link": link}
    r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host},
                     headers={"Auth-Key": URLHAUS_KEY}, timeout=6)
    j = r.json()
    if j.get("query_status") == "ok":
        return {"source": "URLhaus (abuse.ch)", "status": "listed",
                "detail": f"{j.get('url_count', '?')} malicious URLs recorded", "link": link}
    return {"source": "URLhaus (abuse.ch)", "status": "clean", "detail": "not listed", "link": link}


async def openphish(c: httpx.AsyncClient, host: str, reg: str) -> dict:
    if time.time() - _openphish["ts"] > 3600:
        r = await c.get("https://openphish.com/feed.txt", timeout=8)
        hosts = set()
        for line in r.text.splitlines():
            m = re.match(r"https?://([^/:?#]+)", line.strip())
            if m:
                hosts.add(m.group(1).lower())
        _openphish.update(ts=time.time(), hosts=hosts)
    hit = host in _openphish["hosts"] or any(h == reg or h.endswith("." + reg) for h in _openphish["hosts"])
    return {"source": "OpenPhish", "status": "listed" if hit else "clean",
            "detail": "in the live phishing feed" if hit else f"not in feed ({len(_openphish['hosts'])} hosts)",
            "link": "https://openphish.com/"}


async def urlscan(c: httpx.AsyncClient, domain: str) -> dict:
    link = f"https://urlscan.io/search/#domain:{domain}"
    headers = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    r = await c.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 20},
                    headers=headers, timeout=6)
    res = r.json().get("results", [])
    mal = [x for x in res if (x.get("verdicts") or {}).get("malicious")
           or "malicious" in " ".join(map(str, (x.get("task") or {}).get("tags", []))).lower()]
    first = min((x.get("task", {}).get("time", "") for x in res), default=None) or None
    return {"source": "urlscan.io", "status": "mixed" if mal else ("clean" if res else "unknown"),
            "detail": f"{len(res)} earlier scans, {len(mal)} marked malicious" + (f", first {first[:10]}" if first else ""),
            "link": link}


def manual_links(domain: str) -> list:
    return [{"name": "ScamAdviser", "link": f"https://www.scamadviser.com/check-website/{domain}"},
            {"name": "Trustpilot", "link": f"https://www.trustpilot.com/review/{domain}"},
            {"name": "ICANN Lookup", "link": f"https://lookup.icann.org/en/lookup?name={domain}"},
            {"name": "Wayback Machine", "link": f"https://web.archive.org/web/*/{domain}"}]


# ---------------------------------------------------------------- all together
async def _safe(name, coro):
    try:
        return name, await coro
    except Exception as e:
        return name, {"error": f"{type(e).__name__}: {str(e)[:120]}"}


SIMULATED = set(h for kv in os.getenv("HOST_MAP", "").split(",") if "=" in kv for h in [kv.split("=", 1)[0]])


def simulated_intel(host: str, reg: str, ip: Optional[str]) -> dict:
    """Demo domains exist only inside Raqib, so registries know nothing about them. Say so honestly."""
    na = {"source": "-", "status": "unknown", "detail": "simulated demo domain, not queried"}
    return {"domain": reg, "simulated": True,
            "who": {"created": None, "age_days": None, "registrar": "simulated demo domain (no registry record)",
                    "registrant": "—", "nameservers": []},
            "where": {"ip": ip, "org": "Raqib demo laptop", "country": "AE"}, "dns": {},
            "history": {"archived": None, "first_archived": None, "first_certificate": None},
            "bot_view": {}, "favicon_sha1": None,
            "reputation": [{**na, "source": s} for s in ("Google Safe Browsing", "VirusTotal", "URLhaus (abuse.ch)",
                                                           "OpenPhish", "urlscan.io")],
            "check_manually": []}


async def gather_intel(host: str, reg: str, url: str, ip: Optional[str] = None, favicon_url: str = "") -> dict:
    if host in SIMULATED:
        return simulated_intel(host, reg, ip)
    key = f"intel:{reg}:{ip}"
    hit = _cached(key, ttl=1800)
    if hit:
        return hit
    async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": UA}) as c:
        if not ip:
            d = await dns_records(host)
            ip = (d.get("A") or [None])[0]
        tasks = [_safe("rdap", rdap_domain(c, reg)), _safe("dns", dns_records(reg)),
                 _safe("wayback", wayback_first(c, reg)), _safe("crtsh", crtsh_first(c, reg)),
                 _safe("gsb", safe_browsing(c, url)), _safe("vt", virustotal(c, reg)),
                 _safe("urlhaus", urlhaus(c, host)), _safe("openphish", openphish(c, host, reg)),
                 _safe("urlscan", urlscan(c, reg)), _safe("bot", bot_fetch(c, url)),
                 _safe("favicon", favicon_hash(c, favicon_url))]
        if ip:
            tasks += [_safe("ipinfo", ip_info(c, ip)), _safe("iprdap", ip_rdap(c, ip))]
        res = dict(await asyncio.gather(*tasks))

    who = res.get("rdap", {})
    if "error" in who or not who.get("created"):
        w = (await _safe("whois", whois43(reg)))[1]
        if "error" not in w:
            who = w
    created = who.get("created") if "error" not in who else None
    reg_ = who.get("registrant") or {}
    hidden = not any((reg_ or {}).values()) or bool(re.search(r"redact|privacy|proxy|withheld|not disclosed",
                                                              str(reg_), re.I))
    host_info = {**({} if "error" in res.get("ipinfo", {"error": 1}) else res.get("ipinfo", {})),
                 **({} if "error" in res.get("iprdap", {"error": 1}) else res.get("iprdap", {}))}
    if ip:
        host_info["ip"] = ip
    wb, ct = res.get("wayback", {}), res.get("crtsh", {})
    rep = [res[k] for k in ("gsb", "vt", "urlhaus", "openphish", "urlscan") if k in res]
    rep = [r if "source" in r else {"source": k, "status": "error", "detail": r.get("error")}
           for k, r in zip(("Google Safe Browsing", "VirusTotal", "URLhaus (abuse.ch)", "OpenPhish", "urlscan.io"), rep)]
    out = {
        "domain": reg,
        "who": {"created": created, "age_days": _days_since(created), "updated": who.get("updated"),
                "expires": who.get("expires"), "registrar": who.get("registrar"),
                "registrar_abuse": who.get("registrar_abuse"),
                "registrant": "hidden (privacy protection, normal since GDPR)" if hidden else reg_,
                "nameservers": who.get("nameservers", []), "source": who.get("source"),
                "error": who.get("error")},
        "where": host_info or {"ip": ip},
        "dns": res.get("dns", {}),
        "history": {"first_archived": wb.get("first"), "archived": wb.get("captures"),
                    "first_certificate": ct.get("first"), "certificates": ct.get("certs"),
                    "wayback_error": wb.get("error"), "crtsh_error": ct.get("error")},
        "bot_view": res.get("bot", {}),
        "favicon_sha1": res.get("favicon") if isinstance(res.get("favicon"), str) else None,
        "reputation": rep,
        "check_manually": manual_links(reg),
    }
    return _store(key, out)
