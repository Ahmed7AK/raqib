"""
Red-flag system. Every flag is an observable fact (never the AI's opinion), explainable in one sentence.

Tiers (count of flags raised):
  0 -> CLEAN       opens normally
  1 -> WARN        opens, alert explains, user can "Trust this site"
  2-3 -> CAUTION   held; user can "Open once (10 min)" or "Trust"
  4-5 -> RESTRICTED blocked; only a guardian or an analyst review can release it
  6+ or any critical flag -> BLOCKED   blocked for everyone, evidence goes to police
Trust anchor: domain older than 2 years and no critical flag -> capped at WARN.
Edit FLAGS to change titles, explanations or criticality.
"""
import re
import time
from urllib.parse import urlparse

FLAGS = {
    # A. Who and when
    "F01": ("Brand-new domain", "The domain was registered less than 30 days ago. Scam domains are disposable and used within days.", False),
    "F02": ("No history", "The domain has no archived pages or certificates older than 30 days, so the website itself is new even if the name is older.", False),
    # B. Where it lives
    "F03": ("Linked to a blocked site", "Shares a server, page fingerprint or icon with a site Raqib already blocked (same scam kit or campaign).", False),
    "F04": ("No email set up", "The domain cannot receive email. Real businesses and authorities can; throwaway scam domains usually cannot.", False),
    "F05": ("Redirect hopping", "The link jumps through several different domains before landing, a common way to route and filter scam traffic.", False),
    # C. The name
    "F06": ("Brand name in the domain", "The domain uses a UAE brand or authority name but is not that organisation's official domain.", False),
    "F07": ("Typo of an official domain", "The domain is one or two letters away from an official domain.", False),
    "F08": ("Look-alike characters", "The domain hides letters from another alphabet that look like Latin letters.", False),
    "F09": ("Suspicious name pattern", "The name combines several scam patterns: high-abuse ending, words like pay/fine/verify, many hyphens.", False),
    # D. What the page says and asks
    "F10": ("Pretends to be a UAE entity", "The page presents itself as a known UAE brand or authority on a domain that does not belong to it.", False),
    "F11": ("Asks for sensitive data directly", "The page itself asks for card, CVV, OTP, password, Emirates ID or bank details (not through a payment provider).", False),
    "F12": ("Pressure tactics", "Deadlines, threats of fines, suspension or legal action to rush you.", False),
    "F13": ("Too good to be true", "Unrealistic discounts, prizes or prices far below market.", False),
    "F14": ("Unusual payment method", "Asks for bank transfer to a personal account, crypto, gift cards or payment over WhatsApp.", False),
    "F15": ("No identifiable business", "Asks for money or data but shows no address, phone, trade licence or terms.", False),
    "F16": ("Copies official assets", "Loads its logo or files directly from the real organisation's website.", False),
    # E. Technical tricks
    "F17": ("Hidden instructions to AI", "Contains hidden text telling security scanners the page is safe. No legitimate site does this.", True),
    "F18": ("Sends your data to a third party", "Sends form data to a Telegram bot, webhook or another domain.", True),
    "F19": ("Cloaking", "Shows security scanners a different site than it shows phones.", False),
    # F. What other sites say
    "F20": ("Listed as dangerous", "Listed by Google Safe Browsing, URLhaus or OpenPhish, or flagged by 2+ VirusTotal engines.", True),
    "F21": ("Mixed reputation", "One security engine or an earlier urlscan.io scan marks it as malicious or suspicious.", False),
    # G. What only our network sees
    "F22": ("Sudden lookup burst", "Many different phones looked up this never-before-seen domain within minutes (typical of an SMS blast).", False),
    "F23": ("Reported by users", "Three or more Raqib users reported it.", False),
    # Combination
    "C01": ("Impersonation asking for your data", "Pretends to be a UAE entity AND asks for card or ID details: conclusive.", True),
}

TIERS = [(0, "CLEAN"), (1, "WARN"), (2, "CAUTION"), (4, "RESTRICTED"), (6, "BLOCKED")]
TIER_ORDER = ["CLEAN", "WARN", "CAUTION", "RESTRICTED", "BLOCKED"]
CDN_ORGS = re.compile(r"cloudflare|akamai|fastly|amazon|google|microsoft|azure|incapsula|imperva|edgecast|stackpath", re.I)
KNOWN_REDIRECTORS = {"google.com", "facebook.com", "instagram.com", "whatsapp.com", "t.co", "linkedin.com",
                     "youtube.com", "lnkd.in", "l.wl.co"}
PRESSURE_RE = re.compile(r"within \d+ ?(hours?|days?)|immediately|urgent|last (chance|notice|warning)|"
                         r"suspend|legal action|arrest|penalt|will be (blocked|cancelled)|خلال \d+|فوراً|فورا|"
                         r"إيقاف|إجراءات قانونية|غرامة|آخر فرصة", re.I)
DEAL_RE = re.compile(r"\b([5-9]\d)\s?% ?(off|discount|خصم)|خصم\s?([5-9]\d)\s?%|\bfree (iphone|gift|car)|"
                     r"you (have )?won|congratulations|winner|prize|جائزة|مبروك|ربحت", re.I)
PAYMENT_RE = re.compile(r"bitcoin|\busdt\b|crypto|wallet address|gift ?card|itunes card|western union|"
                        r"transfer (the amount )?to (this|the following) account|\bAE\d{2}\s?\d{3}|"
                        r"pay (via|on|through) whatsapp|تحويل .{0,20}حساب|محفظة", re.I)
IDENTITY_RE = re.compile(r"(\+971|00971|\b0[2-9]\d?[\s-]?\d{3}[\s-]?\d{4})|trade licen[cs]e|رخصة تجارية|"
                         r"terms (and|&) conditions|privacy policy|الشروط والأحكام|سياسة الخصوصية|"
                         r"p\.?o\.? box|ص\.?ب|address|العنوان|[\w.]+@[\w-]+\.\w+", re.I)


def _reg(host: str) -> str:
    from engine import reg_domain
    return reg_domain(host)


def evaluate(rec: dict, crawl: dict, intel: dict, facts: dict, extraction: dict, dscore: dict,
             history_db=None, events=None, reports: int = 0) -> dict:
    """Return raised flags, count, tier. `facts` comes from engine.decide()."""
    raised = []

    def add(fid, evidence):
        title, why, critical = FLAGS[fid]
        raised.append({"id": fid, "title": title, "why": why, "critical": critical, "evidence": evidence})

    sig = dscore.get("signals", {})
    who, hist = intel.get("who", {}), intel.get("history", {})
    age = who.get("age_days")
    text = f"{crawl.get('title', '')}\n{crawl.get('visible_text', '')}"
    host, reg = rec["host"], rec["reg_domain"]

    # A. Who and when
    if age is not None and age < 30:
        add("F01", f"Registered {age} days ago ({(who.get('created') or '')[:10]}) via {who.get('registrar') or 'unknown registrar'}")
    else:
        fa, fc = hist.get("first_archived"), hist.get("first_certificate")
        from intel import _days_since
        da, dc = _days_since(fa), _days_since(fc)
        answered = hist.get("archived") is not None or fc is not None
        if answered and (da is None or da < 30) and (dc is None or dc < 30):
            add("F02", f"First archived: {fa[:10] if fa else 'never'}; first certificate: {fc[:10] if fc else 'none found'}")

    # B. Where it lives
    if history_db:
        hit = history_db(rec, intel)
        if hit:
            add("F03", hit)
    mx = (intel.get("dns") or {}).get("MX")
    if mx == [] and ((intel.get("dns") or {}).get("A") or (intel.get("dns") or {}).get("AAAA")):
        add("F04", f"{reg} has no mail (MX) record")
    chain = rec.get("redirect_chain") or []
    hops = []
    for u in chain:
        r = _reg(urlparse(u).hostname or "")
        if r and r not in KNOWN_REDIRECTORS and r not in hops:
            hops.append(r)
    if len(hops) >= 3:
        add("F05", " → ".join(hops))

    # C. The name
    if sig.get("brand_keyword"):
        add("F06", sig["brand_keyword"])
    elif sig.get("typosquat"):
        add("F07", sig["typosquat"])
    if sig.get("lookalike"):
        add("F08", sig["lookalike"])
    weak = [x for x in (sig.get("risky_tld"), sig.get("risky_words"), sig.get("hyphens_or_long")) if x]
    if len(weak) >= 2:
        add("F09", "; ".join(weak))

    # D. What the page says and asks
    if facts.get("impersonation"):
        add("F10", f"Presents itself as {facts['brand']} ({extraction.get('brand_evidence') or 'page content'})")
    sensitive_fields = sorted(set(rec.get("fields_found", [])) & {"card_number", "cvv", "expiry", "otp", "password", "emirates_id", "iban"})
    if sensitive_fields:
        add("F11", "Fields: " + ", ".join(sensitive_fields))
    flags_llm = " ".join(f"{f.get('flag', '')} {f.get('evidence', '')}" for f in extraction.get("red_flags", []))
    m = PRESSURE_RE.search(text) or PRESSURE_RE.search(flags_llm)
    if m or re.search(r"urgen|threat|penalt|deadline", flags_llm, re.I):
        add("F12", f"\"{m.group(0)}\"" if m else "AI noted urgency or threats")
    m = DEAL_RE.search(text)
    if m or re.search(r"unrealistic|too good|discount|prize", flags_llm, re.I):
        add("F13", f"\"{m.group(0)}\"" if m else "AI noted an unrealistic offer")
    m = PAYMENT_RE.search(text)
    if m or "payment_transfer" in extraction.get("requested_data", []):
        add("F14", f"\"{m.group(0)}\"" if m else "asks for a bank transfer")
    asks = sensitive_fields or any(x["id"] in ("F13", "F14") for x in raised)
    if asks and not IDENTITY_RE.search(text):
        add("F15", "No phone, address, licence or terms found on the page")
    brand_domains = facts.get("brand_domains") or []
    copied = sorted({urlparse(u).hostname for u in crawl.get("requests", [])
                     if any((urlparse(u).hostname or "").endswith(d) for d in brand_domains)})
    if facts.get("impersonation") and copied:
        add("F16", "Loads files from " + ", ".join(copied[:3]))

    # E. Technical tricks
    if facts.get("hidden_injection"):
        add("F17", f"Hidden text: \"{(crawl.get('hidden_text') or '')[:120]}\"")
    tg = [e for e in facts.get("exfil", []) if "telegram" in e]
    if tg or (sensitive_fields and (facts.get("exfil") or facts.get("posts_elsewhere"))):
        add("F18", ", ".join(dict.fromkeys(tg + facts.get("exfil", []) + facts.get("posts_elsewhere", [])))[:200])
    bv = intel.get("bot_view") or {}
    if bv.get("final_url") and rec.get("final_url"):
        b_reg = _reg(urlparse(bv["final_url"]).hostname or "")
        p_reg = _reg(urlparse(rec["final_url"]).hostname or "")
        if b_reg != p_reg or (bv.get("status", 200) >= 400 and (rec.get("status") or 200) < 400):
            add("F19", f"Bots get {bv['final_url']} ({bv.get('status')}); phones get {rec['final_url']} ({rec.get('status')})")

    # F. What other sites say
    rep = intel.get("reputation", [])
    listed = [r["source"] for r in rep if r.get("status") == "listed"]
    mixed = [r["source"] for r in rep if r.get("status") == "mixed"]
    if listed:
        add("F20", "Listed by " + ", ".join(listed))
    elif mixed:
        add("F21", "; ".join(f"{r['source']}: {r.get('detail', '')}" for r in rep if r.get("status") == "mixed"))

    # G. What only our network sees
    if events:
        now = time.time()
        devices = {e.get("device") for e in events if e.get("host") == host and e.get("device")
                   and now - e.get("t", now) < 600}
        if len(devices) >= 3:
            add("F22", f"{len(devices)} different devices in 10 minutes")
    if reports >= 3:
        add("F23", f"{reports} user reports")

    # Combination
    if facts.get("impersonation") and sensitive_fields:
        add("C01", f"{facts['brand']} + {', '.join(sensitive_fields)}")

    count = len([f for f in raised if f["id"] != "C01"])
    critical = [f for f in raised if f["critical"]]
    tier = "CLEAN"
    for threshold, name in TIERS:
        if count >= threshold:
            tier = name
    reason = f"{count} red flag{'s' if count != 1 else ''}"
    if critical:
        tier, reason = "BLOCKED", f"critical: {critical[0]['title']}"
    elif age is not None and age >= 730 and TIER_ORDER.index(tier) > 1:
        tier, reason = "WARN", f"{count} flags, capped at WARN (trust anchor: domain is {age // 365} years old)"
    return {"flags": raised, "count": count, "tier": tier, "tier_reason": reason}

FLAGS_AR = {
    "F01": "نطاق جديد جداً", "F02": "لا يوجد سجل سابق للموقع", "F03": "مرتبط بموقع محظور",
    "F04": "لا يوجد بريد إلكتروني للنطاق", "F05": "تحويلات متعددة بين النطاقات", "F06": "اسم جهة إماراتية في النطاق",
    "F07": "نسخة بخطأ إملائي من نطاق رسمي", "F08": "حروف مشابهة من أبجدية أخرى", "F09": "نمط اسم مشبوه",
    "F10": "ينتحل صفة جهة إماراتية", "F11": "يطلب بيانات حساسة مباشرة", "F12": "أساليب ضغط وتهديد",
    "F13": "عرض أفضل من أن يكون حقيقياً", "F14": "طريقة دفع غير معتادة", "F15": "لا توجد هوية تجارية واضحة",
    "F16": "ينسخ ملفات الجهة الرسمية", "F17": "تعليمات مخفية لأنظمة الذكاء الاصطناعي", "F18": "يرسل بياناتك لطرف ثالث",
    "F19": "يُظهر محتوى مختلفاً لأنظمة الفحص", "F20": "مُدرج كموقع خطير", "F21": "سمعة مختلطة",
    "F22": "ارتفاع مفاجئ في عمليات البحث", "F23": "بلاغات من المستخدمين", "C01": "انتحال صفة مع طلب بياناتك",
}
