# Raqib رقيب: finds UAE scam sites before victims do

**AI extracts the facts, code decides the verdict, the network enforces it.**

- **Hunter** (`hunter.py`) finds new domains that use UAE brand names: Certificate Transparency logs plus dnstwist look-alikes.
- **Engine** (`engine.py`) opens each site in a sandboxed mobile browser with a UAE locale and captures:
  - a screenshot and the *visible* text only (hidden text is set aside, and flagged if it talks to AI scanners);
  - the form fields (card, CVV, OTP, Emirates ID…) and any data sent to Telegram bots or webhooks.

  A vision LLM then extracts facts only: who the page claims to be, the scam type, the red flags. Code checks the claimed brand against official UAE domains and decides BLOCK, REVIEW or ALLOW. Every verdict comes with an evidence pack and an Arabic/English alert.
- **Guard** (`guard.py`) is a DNS resolver that enforces verdicts for every app on a phone. It simulates TDRA/carrier-level deployment.

## Setup (Python 3.10+)
```bash
pip install -r requirements.txt
python -m playwright install --with-deps chromium     # on macOS: python -m playwright install chromium
cp .env.example .env    # then fill it in; never commit .env
```

## Run
```bash
# 1. Engine and dashboard (port 80 so the phone can open demo domains; needs sudo)
set -a; source .env; set +a
sudo -E python -m uvicorn engine:app --host 0.0.0.0 --port 80

# 2. Guard resolver (port 53, needs sudo)
sudo -E ENGINE_URL=http://127.0.0.1:80 python guard.py

# 3. Hunter (run it early so real results are on the dashboard)
python hunter.py --days 30 --max-scans 60 --engine http://127.0.0.1:80
```
Open `http://<laptop-ip>/` to reach the dashboard and the "Analyse a link" box.

## Phone demo (LineageOS / Android)
1. Settings → Network → **Private DNS: Off**. In Chrome: Settings → Privacy → **Use secure DNS: Off**.
2. Wi-Fi → your network → Edit → IP settings **Static**, **DNS 1 = laptop IP**.
   First check the phone can open `http://<laptop-ip>/`. University Wi-Fi sometimes blocks device-to-device traffic; if so, use a hotspot.
3. Set `HOST_MAP` in `.env` to two demo names pointing at the laptop IP. They exist **only inside Raqib**, so nothing public imitates a real authority:
   - `adpolice-fines-pay.com`: blocked **before it loads**, because its name copies Abu Dhabi Police.
   - `uae-fines-portal.com`: has an innocent-looking name, so it loads. The engine scans it in the background (about 2 s with heuristics, longer with the LLM), a Telegram alert says "don't enter your details", and the next lookup (after the 30 s TTL) is blocked.
4. Send `http://adpolice-fines-pay.com/` and `http://uae-fines-portal.com/` to the phone through WhatsApp, SMS and Gmail, then tap each one.

## API (for the dashboard and integrations)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` `{"url": "...", "source": "manual"}` | Full analysis; returns the evidence record. Add `?background=true` to queue it instead |
| GET | `/api/scans?limit=50&verdict=BLOCK&source=hunter` | Recent analyses |
| GET | `/api/scans/{id}` | One evidence record |
| GET | `/api/domain/{host}` | Fast score plus latest verdict (used by the resolver) |
| GET | `/api/score?host=...` | Fast domain score only |
| GET | `/api/events` | Live resolver decisions (BLOCK / WARN) |
| GET | `/shots/{id}.jpg` | Screenshot |
| GET | `/demo/fine` | Training sample page (watermarked; contains a hidden prompt-injection test) |

## Red flags and tiers (`flags.py`)
Every flag is an observable fact, never the AI's opinion. The more flags, the more restrictions:

| Flags | Tier | On the phone |
|---|---|---|
| 0 | CLEAN | opens normally |
| 1 | WARN | opens; alert explains why, with [Trust this site] and [Report] |
| 2–3 | CAUTION | held; [Open once (10 min)] or [Trust] |
| 4–5 | RESTRICTED | blocked; only [Request review] (an analyst decides on the dashboard) |
| 6+ or any critical | BLOCKED | blocked for everyone, no override |

**Trust anchor:** a domain older than 2 years with no critical flag is capped at WARN.

The 23 flags are F01–F23, plus the combination C01:
- **Who/when:** F01–F02
- **Where:** F03–F05
- **Name:** F06–F09
- **Content:** F10–F16
- **Tricks:** F17–F19
- **Other services:** F20–F21
- **Our network:** F22–F23

Critical flags: F17, F18, F20, C01. Titles, explanations and criticality are edited in one table in `flags.py`.

## Site intelligence (`intel.py`, also `GET /api/intel?host=`)
- **Who and when:** registration, update and expiry dates, registrar and abuse contact, and the owner (usually hidden by privacy protection, which is normal), name servers. Source: RDAP, with WHOIS port 43 as fallback.
- **Where:** server IP, hosting company, network number, city and country (ipinfo.io), network owner and abuse email (RDAP), mail records.
- **History:** first Wayback Machine capture and first certificate (crt.sh).
- **What other services say:**
  - Google Safe Browsing (`GSB_API_KEY`, free, non-commercial)
  - VirusTotal (`VT_API_KEY`, free: 4 lookups per minute, 500 per day)
  - URLhaus (`URLHAUS_AUTH_KEY`, free from auth.abuse.ch)
  - OpenPhish feed
  - urlscan.io
  - plus manual links to ScamAdviser, Trustpilot, ICANN Lookup and the Wayback Machine.

A missing key shows "not_configured"; it never crashes. Demo domains in `HOST_MAP` are marked "simulated" and are not queried.

## Trust links
Alerts include links such as `PUBLIC_BASE_URL/t/<token>?a=trust|once|review|report`. Trust and "open once" are per device. A BLOCKED site cannot be trusted. Review requests appear on the dashboard with [Release] and [Keep blocked].

## Demo domains (set in `HOST_MAP`, pointed at the laptop IP)
| Domain | Page | Expected result |
|---|---|---|
| `dubai-events-guide.com` | events | **WARN** (1 flag: pressure tactics). Opens, alert with [Trust] |
| `iphone-mega-sale.com` | deal | **CAUTION** (3 flags). Held, [Open once] / [Trust] |
| `adpolice-fines-pay.com` | fine | Held instantly by name, then **BLOCKED** (critical) |
| `uae-fines-portal.com` | fine | Opens, scanned in the background, then **BLOCKED**. Also linked to the domain above (identical page, F03) |
| `аdpolice-pay.com` (Cyrillic а; use its punycode in `HOST_MAP`) | fine | **BLOCKED**; the alert names the fake letter |

## Character-level reading
Every domain is read one character at a time, and each character is tagged with its Unicode script. A Cyrillic `р` (U+0440) is never treated as a Latin `p` (U+0070).
- A label that mixes scripts (`аdpolice` with a Cyrillic `а`) is flagged.
- A label written entirely in look-alike letters (`аррӏе`, all Cyrillic) is flagged.
- The Latin "skeleton" is still matched against UAE brand names.
- Page text is checked the same way, e.g. "Аbu Dhabi Police" typed with a Cyrillic `А`.
- Legitimate Arabic domains (e.g. `تم.ae`) are not flagged: Arabic letters don't imitate Latin ones.

To demo it on the phone, add the punycode form to `HOST_MAP`: `python -c "print('аdpolice-pay.com'.encode('idna').decode())"`.

## Older verdict notes (superseded by the flags above)
- **BLOCK:** impersonates a known UAE brand on a non-official domain **and** asks for sensitive data, sends data to a third party, or posts its form elsewhere. Also BLOCK: hidden instructions to AI scanners, or a Telegram/webhook exfiltration endpoint, combined with sensitive fields.
- **REVIEW:** uses a brand name on an unofficial domain; or a new or suspicious domain that asks for sensitive data; or a scam category plus red flags. A human analyst decides.
- **ALLOW:** an official domain, or nothing suspicious.

## Honest limits
- DNS only sees the domain name, never the full path. Scam kits that only show content on a per-victim path need the full URL, which comes from Hunter, user reports or search results.
- Scams on shared hosts (Google Sites, Firebase) can't be blocked at DNS level without breaking the whole host.
- Cloaked sites may show the scanner a harmless page. The UAE mobile profile helps, but it doesn't solve this.
- Fake shops and other scams that don't impersonate a brand go to REVIEW, not automatic BLOCK.
- The brand list in `brands.json` must be verified; every entry currently starts as `verified: false`.
