"""
Raqib Guard: AI-assisted DNS resolver. Demonstrates what carrier/TDRA-level enforcement of
Raqib verdicts looks like. Point the phone's Wi-Fi DNS at this laptop.

Decision per lookup (AI decides once per domain in the engine; this code only enforces):
  1. allowlisted (big platforms, official UAE domains)   -> answer normally
  2. already scanned -> act on its red-flag tier (per device):
       CLEAN -> open | WARN -> open + alert with [Trust] | CAUTION -> hold + [Open once]/[Trust]
       RESTRICTED -> block + [Request review] | BLOCKED -> block, no override
  3. not scanned, fast score >= BLOCK_SCORE (look-alike)  -> hold + alert + scan
  4. not scanned, fast score >= SCAN_SCORE or demo domain -> open with 30 s TTL + background scan
       (the engine alerts the phone if the scan finds flags; the next lookup applies the tier)
  5. otherwise                                           -> answer normally

Run:  sudo python guard.py            (port 53 needs root; or PORT=5353 for testing)
Env:  UPSTREAM=1.1.1.1  ENGINE_URL=http://127.0.0.1:8000  BLOCK_SCORE=0.7  SCAN_SCORE=0.25
      HOST_MAP="adpolice-fines-pay.com=192.168.1.20,uae-fines-portal.com=192.168.1.20"  (same as engine)
      TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
"""
import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

import engine  # reuse the scorer, brand list and verdict store (same SQLite file)

UPSTREAM = os.getenv("UPSTREAM", "1.1.1.1")
ENGINE_URL = os.getenv("ENGINE_URL", "http://127.0.0.1:8000")
PORT = int(os.getenv("PORT", "53"))
LISTEN = os.getenv("LISTEN", "0.0.0.0")
BLOCK_SCORE = float(os.getenv("BLOCK_SCORE", "0.7"))
SCAN_SCORE = float(os.getenv("SCAN_SCORE", "0.25"))
SHORT_TTL = 30
HOST_MAP = engine.HOST_MAP
TG_TOKEN, TG_CHAT = engine.TG_TOKEN, engine.TG_CHAT

ALLOW_SUFFIXES = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "gvt2.com",
    "googlevideo.com", "youtube.com", "ytimg.com", "doubleclick.net", "google-analytics.com", "android.com",
    "whatsapp.com", "whatsapp.net", "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "apple.com", "icloud.com", "mzstatic.com", "microsoft.com", "live.com", "office.com", "outlook.com",
    "windows.com", "cloudflare.com", "cloudflare-dns.com", "akamaihd.net", "akamaized.net", "amazonaws.com",
    "cloudfront.net", "telegram.org", "t.me", "discord.com", "discordapp.com", "discord.gg", "tiktok.com",
    "tiktokcdn.com", "twitter.com", "x.com", "twimg.com", "snapchat.com", "github.com", "githubusercontent.com",
    "wikipedia.org", "mozilla.org", "lineageos.org", "gmail.com",
}
_extra = Path(__file__).parent / "allowlist.txt"  # optional: Tranco top-N, one domain per line (or rank,domain)
if _extra.exists():
    ALLOW_SUFFIXES |= {l.strip().split(",")[-1].lower() for l in _extra.read_text().splitlines() if l.strip()}

_last_push: dict = {}
_scanned: dict = {}


def _bg(fn, *a):
    threading.Thread(target=fn, args=a, daemon=True).start()


def _post(path: str, payload: dict, timeout=3):
    try:
        req = urllib.request.Request(ENGINE_URL + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=timeout).read()
    except Exception:
        pass


def event(host, action, reason="", score=0.0, device=""):
    _bg(_post, "/api/events", {"host": host, "action": action, "reason": reason, "score": score, "device": device})


def scan(host, device=""):
    reg = engine.reg_domain(host)
    if time.time() - _scanned.get(reg, 0) < 600:
        return
    _scanned[reg] = time.time()
    url = f"http://{host}/" if host in HOST_MAP else f"https://{host}/"
    _bg(_post, "/api/scan?background=true", {"url": url, "source": "guard", "device": device or None}, 10)


def push(host, note, device=""):
    key = f"{device}|{engine.reg_domain(host)}"
    if not (TG_TOKEN and TG_CHAT and note) or time.time() - _last_push.get(key, 0) < 20:
        return
    _last_push[key] = time.time()
    body = json.dumps({"chat_id": TG_CHAT, "text": engine.alert_text(note), "disable_web_page_preview": True}).encode()

    def send():
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data=body,
                headers={"Content-Type": "application/json"}), timeout=6).read()
        except Exception:
            pass
    _bg(send)


def preemptive_note(host, fast, device=""):
    b = next((x for x in engine.KB if x["name"] == fast.get("brand")), None)
    brand_ar = next((a for a in (b or {}).get("aliases", []) if re.search(r"[؀-ۿ]", a)), fast.get("brand"))
    shown = (fast.get("chars") or {}).get("unicode", host)
    fake = next((f for f in (fast.get("chars") or {}).get("foreign", []) if f.get("looks_like")), None)
    trick_en = (f" It hides a {fake['script'].title()} '{fake['char']}' that looks like the Latin '{fake['looks_like']}'."
                if fake else "")
    trick_ar = (f" يحتوي على حرف '{fake['char']}' من أبجدية أخرى يشبه الحرف اللاتيني '{fake['looks_like']}'."
                if fake else "")
    if b:
        en = (f"Blocked {shown} before it loaded. It uses the name of {b['name']} but is not an official "
              f"{b['name']} domain.{trick_en} Do not enter any details. Report: Aman 8002626.")
        ar = (f"تم حظر {shown} قبل فتحه. يستخدم اسم {brand_ar} لكنه ليس نطاقاً رسمياً.{trick_ar} "
              f"لا تُدخل أي بيانات. للإبلاغ: خدمة أمان 8002626.")
    else:
        en = f"Blocked {host}: suspicious domain ({'; '.join(fast['reasons'][:2])}). Report: Aman 8002626."
        ar = f"تم حظر {host}: نطاق مشبوه. للإبلاغ: خدمة أمان 8002626."
    links = {}
    if device:
        tok = engine.device_token(device, engine.reg_domain(host))
        links = {a: f"{engine.PUBLIC_BASE_URL}/t/{tok}?a={a}" for a in ("once", "trust", "report")}
    return {"en": en, "ar": ar, "links": links}


def allowlisted(host: str) -> bool:
    if engine.official_brand_of(host):
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in ALLOW_SUFFIXES for i in range(len(parts) - 1))


class GuardResolver(BaseResolver):
    def resolve(self, request, handler):
        q = request.q
        host = str(q.qname).rstrip(".").lower()
        device = handler.client_address[0] if handler and handler.client_address else ""
        if not host or (allowlisted(host) and host not in HOST_MAP):
            return self.forward(request)
        reg = engine.reg_domain(host)
        ok = lambda: self.answer_map(request, host) if host in HOST_MAP else self.forward(request)
        trusted = engine.is_trusted(device, reg) if device else None

        last = engine.latest_for_domain(reg)
        tier = last["verdict"] if last else None
        if tier in ("WARN", "CAUTION", "RESTRICTED", "BLOCKED"):
            if trusted and tier in ("WARN", "CAUTION"):
                event(host, "ALLOW", f"{tier}, trusted by this device ({trusted})", last.get("risk", 0), device)
                return ok()
            push(host, engine.make_alert(last, device), device)
            if tier == "WARN":  # 1 flag: opens, with a warning and a Trust button
                event(host, "WARN", last.get("tier_reason", ""), last.get("risk", 0), device)
                return ok()
            event(host, "BLOCK" if tier != "CAUTION" else "HOLD", last.get("tier_reason", ""), last.get("risk", 1), device)
            return self.block(request)
        if tier == "CLEAN":
            return ok()

        fast = engine.score_domain(host)
        if fast["score"] >= BLOCK_SCORE and not trusted:  # held until the full scan (acts as CAUTION)
            event(host, "HOLD", "pre-emptive: " + "; ".join(fast["reasons"][:2]), fast["score"], device)
            push(host, preemptive_note(host, fast, device), device)
            scan(host, device)
            return self.block(request)
        if fast["score"] >= SCAN_SCORE or host in HOST_MAP:
            event(host, "SCAN", "allowed with 30 s TTL while scanning: " + "; ".join(fast["reasons"][:2]), fast["score"], device)
            scan(host, device)
            return self.answer_map(request, host) if host in HOST_MAP else self.forward(request, SHORT_TTL)
        return ok()

    def block(self, request):
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def answer_map(self, request, host):
        reply = request.reply()
        if QTYPE[request.q.qtype] == "A":
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(HOST_MAP[host]), ttl=SHORT_TTL))
        return reply

    def forward(self, request, ttl_cap=None):
        try:
            reply = DNSRecord.parse(request.send(UPSTREAM, 53, timeout=3))
            if reply.header.tc:
                reply = DNSRecord.parse(request.send(UPSTREAM, 53, tcp=True, timeout=3))
            if ttl_cap:
                for rr in reply.rr:
                    rr.ttl = min(rr.ttl, ttl_cap)
            return reply
        except Exception:
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


if __name__ == "__main__":
    engine.init_db()
    resolver = GuardResolver()
    logger = DNSLogger("-request,-reply,-truncated,-data,-recv,-send")
    servers = [DNSServer(resolver, port=PORT, address=LISTEN, logger=logger, tcp=t) for t in (False, True)]
    for s in servers:
        s.start_thread()
    print(f"Raqib Guard on {LISTEN}:{PORT} (udp+tcp), upstream {UPSTREAM}, engine {ENGINE_URL}")
    while True:
        time.sleep(1)
