"""Raqib on WhatsApp: forward a suspicious message, get the same verdict back.

Speaks the WhatsApp Business Cloud API webhook format, so the /whatsapp simulator sends exactly the
payload Meta would send. Replies reuse the engine's own bilingual alert text, so the verdict and wording
match the network alerts.

Modes:
- simulation (default): the webhook returns the replies in its HTTP response; nothing is sent anywhere.
- live: set WHATSAPP_TOKEN, WHATSAPP_PHONE_ID and WHATSAPP_VERIFY_TOKEN. Replies go out through the
  Graph API. NOT TESTED against a real WhatsApp number.
"""
import os
import re
from typing import Iterator, Optional

import httpx

WA_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WA_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID", "")
WA_VERIFY = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
GRAPH = "https://graph.facebook.com/v21.0"


def live() -> bool:
    return bool(WA_TOKEN and WA_PHONE_ID)


URL_RE = re.compile(r"https?://[^\s<>\"'«»]+|(?<![@\w.])(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>\"'«»]*)?", re.I)


def extract_url(text: str) -> Optional[str]:
    m = URL_RE.search(text or "")
    return m.group(0).rstrip(".,;:!?)]}”’") if m else None


def parse(payload: dict) -> Iterator[tuple]:
    """Yield (sender, kind, value) for each incoming message: kind is 'text' or 'button'."""
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            for m in (change.get("value") or {}).get("messages") or []:
                sender = m.get("from", "")
                if m.get("type") == "text":
                    yield sender, "text", (m.get("text") or {}).get("body", "")
                elif m.get("type") == "interactive":
                    br = (m.get("interactive") or {}).get("button_reply") or {}
                    yield sender, "button", br.get("id", "")
                elif m.get("type") == "button":  # quick-reply on a template message
                    yield sender, "button", (m.get("button") or {}).get("payload", "")


HEAD = {
    "CLEAN": ("✅", "CLEAN", "سليم"),
    "WARN": ("🟡", "WARNING", "تحذير"),
    "CAUTION": ("🟠", "CAUTION", "حذر"),
    "RESTRICTED": ("🔴", "RESTRICTED", "مقيّد"),
    "BLOCKED": ("⛔", "BLOCKED", "محظور"),
    "UNREACHABLE": ("⚪", "COULD NOT OPEN", "تعذّر الفتح"),
}

HELP = ("مرحباً، أنا رقيب 👋\nأرسل لي أي رابط أو رسالة مشبوهة وسأفحصها لك خلال ثوانٍ.\n\n"
        "Hi, I'm *Raqib* 👋\nForward me any link or message you're unsure about and I'll check it in seconds.")

REPORT = ("شكراً لك. أبلغ شرطة أبوظبي عبر خدمة *أمان 8002626*. لا تدفع، ولا تشارك بيانات بطاقتك أو رمز التحقق.\n\n"
          "Thank you. Report it to Abu Dhabi Police through *Aman on 8002626*. "
          "Don't pay, and never share card details or OTP codes.")


def _host(rec: dict) -> str:
    return ((rec.get("domain_score") or {}).get("chars") or {}).get("unicode") or rec.get("host") or ""


def verdict_reply(rec: dict) -> dict:
    tier = rec.get("verdict", "UNREACHABLE")
    icon, en, ar = HEAD.get(tier, HEAD["UNREACHABLE"])
    note = rec.get("notification")
    lines = [f"{icon} *{en} · {ar}*", f"```{_host(rec)}```", ""]
    if note:
        lines += [note["ar"], "", note["en"]]
    elif tier == "CLEAN":
        lines += ["لم نعثر على أي علامات تحذير في هذه الصفحة حالياً. تذكّر: لا تشارك رمز التحقق مع أي أحد.", "",
                  "No red flags found on this page right now. Stay careful: never share an OTP code with anyone."]
    else:
        lines += ["تعذّر فتح الصفحة، لذلك لا يمكننا الحكم عليها. لا تُدخل أي بيانات فيها.", "",
                  "The page could not be opened, so Raqib can't judge it. Don't enter any details there."]
    mode = "AI analysis" if rec.get("llm_used") else "heuristic analysis"
    secs = (rec.get("elapsed_ms") or 0) / 1000
    lines += ["", f"_Checked by Raqib in {secs:.1f} s · {mode}_"]
    body = "\n".join(lines)[:1024]  # WhatsApp interactive body limit
    if rec.get("flags"):
        return {"type": "interactive", "text": body, "buttons": [
            {"id": f"why:{rec['id']}", "title": "Why? · لماذا؟"},
            {"id": f"report:{rec['id']}", "title": "Report · إبلاغ"}]}
    return {"type": "text", "text": body}


def why_reply(rec: dict, flags_ar: dict) -> dict:
    fl = sorted(rec.get("flags") or [], key=lambda f: (not f.get("critical"), f["id"]))
    lines = [f"*Why Raqib flagged* ```{_host(rec)}```", ""]
    for f in fl[:8]:
        crit = " · _critical_" if f.get("critical") else ""
        lines.append(f"{'🔴' if f.get('critical') else '•'} *{f['title']}*{crit}")
        lines.append(flags_ar.get(f["id"], ""))
        lines.append(f"_{f.get('why', '')}_")
        lines.append("")
    lines.append("The verdict comes from these rules, not from AI.")
    return {"type": "text", "text": "\n".join(lines).strip()[:4096]}


def text_reply(body: str) -> dict:
    return {"type": "text", "text": body}


async def send(to: str, reply: dict) -> dict:
    """Send one reply through the WhatsApp Cloud API. NOT TESTED against a real number."""
    if reply["type"] == "interactive":
        msg = {"type": "interactive", "interactive": {"type": "button", "body": {"text": reply["text"]}, "action": {
            "buttons": [{"type": "reply", "reply": {"id": b["id"], "title": b["title"][:20]}} for b in reply["buttons"]]}}}
    else:
        msg = {"type": "text", "text": {"body": reply["text"], "preview_url": False}}
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"{GRAPH}/{WA_PHONE_ID}/messages", headers={"Authorization": f"Bearer {WA_TOKEN}"},
                         json={"messaging_product": "whatsapp", "to": to, **msg})
        return {"status": r.status_code}
