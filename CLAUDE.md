# Raqib (رقيب): handover for Claude Code

Read this before touching anything. It's a hackathon prototype built overnight. **Help us run, verify and ship it. Don't refactor it.**

## Context
- **Event:** ScamShield AI Hackathon (42 Abu Dhabi × Abu Dhabi Police), team "Team Sarr".
- **Challenge:** detect fraudulent links and websites used in cybercrime and financial fraud.
- **Submission deadline: Wed 25 Nov 2026, 08:00 (Asia/Dubai). Aim to submit by 07:30.**
- **The form needs:** title, description (600 characters max), tools used, a **public GitHub repo URL**, the presentation as a PDF or PPTX, and a **demo video of 1 minute or less** (a real screen recording; AI-generated video is not accepted). A live URL is optional.
- **The deck** is already built as a Claude Slides artifact (https://claude.ai/artifact/8LEc6bHZquNaiDkQthsVrp). Export it to PDF from there.

## What the product does
Raqib checks every link **the moment it is opened, in any app, with nothing to install**. It works at the DNS level.

1. **Guard** (`guard.py`): a DNS resolver. Every app looks up a domain before opening a link, so the resolver sees every tap.
2. **Engine** (`engine.py`): opens unknown sites in a sandboxed headless Chromium with a mobile, UAE locale profile. It captures:
   - a screenshot;
   - the **visible** text only (hidden text is kept separately);
   - form fields (card, CVV, OTP, Emirates ID…);
   - network requests (e.g. to `api.telegram.org`).

   It then gets **facts only** from an LLM: claimed brand, scam category, requested data, red flags. If there's no LLM key, it falls back to keyword heuristics.
3. **Flags** (`flags.py`): code turns those facts into **red flags**. The flag count decides the **tier**. **The AI never decides the verdict.** This is the design principle, because it makes prompt injection useless.
4. **Intel** (`intel.py`):
   - **Who and when:** RDAP, with WHOIS port 43 as fallback.
   - **Where:** DNS records, ipinfo.io, RDAP for the IP.
   - **History:** the Wayback Machine and crt.sh.
   - **What other services say:** Google Safe Browsing, VirusTotal, URLhaus, OpenPhish, urlscan.io, plus manual links to ScamAdviser and Trustpilot.
5. **Alerts:** in Arabic and English, sent via Telegram, with per-device action links: Trust, Open once, Request review, Report.

Principle: **AI reads · code decides · the network enforces.**

## Tiers (`flags.py`)
| Flags | Tier | Behaviour (Guard, per device) |
|---|---|---|
| 0 | CLEAN | resolves normally |
| 1 | WARN | resolves; alert with [Trust] / [Report] |
| 2–3 | CAUTION | NXDOMAIN (held); [Open once (10 min)] / [Trust] |
| 4–5 | RESTRICTED | blocked; only [Request review] (an analyst releases it on the dashboard) |
| 6+ or any critical | BLOCKED | blocked, no override |

- **Critical flags:** F17 (hidden instructions to AI), F18 (data sent to a Telegram bot or webhook), F20 (blocklisted), C01 (impersonation **and** a sensitive field).
- **Trust anchor:** a domain older than 2 years with no critical flag is capped at WARN.
- **The flags:** 23 in total, F01–F23, plus the combination rule C01. Titles and explanations live in the `FLAGS` table; Arabic titles in `FLAGS_AR`.
- **UNREACHABLE** means the page failed to load and no flags fired.

## Files
| File | Purpose |
|---|---|
| `engine.py` | FastAPI app: crawl, LLM extraction, `decide()` (facts), domain scorer with character-level script analysis, SQLite storage, alerts, trust and review endpoints, the dashboard |
| `flags.py` | Flag table, `evaluate()`, tier logic, Arabic flag titles |
| `intel.py` | Site intelligence; every source is optional and fails soft. Domains in `HOST_MAP` get honest "simulated" intel |
| `guard.py` | dnslib resolver (UDP + TCP) that applies tiers per device (client IP) and per-device trust |
| `hunter.py` | crt.sh + dnstwist candidate discovery → queued scans. **Not tested live** |
| `brands.json` | About 25 UAE brands and authorities with official domains. **All `verified: false`: verify before relying on them** |
| `static/index.html` | Dashboard: scan box, result card with flags, site-intelligence panel, recent scans, live network decisions, review queue. Cool Metal palette |
| `demo/fine.html` | Watermarked fake "Abu Dhabi Police fine" page: hidden AI-injection text and a dummy Telegram bot string → **BLOCKED** |
| `demo/deal.html` | Fake 80%-off iPhone sale with bank transfer → **CAUTION** (3 flags) |
| `demo/events.html` | Events guide with one pressure phrase → **WARN** (1 flag) |
| `.env.example` | All settings. `.env` is gitignored and **must never be committed** |

## API (engine)
- `POST /api/scan` with `{"url","source","device"}`: runs the full analysis. Add `?background=true` to queue it instead.
- `GET /api/scans?limit=&verdict=&source=` lists scans; `GET /api/scans/{id}` returns one.
- `GET /api/domain/{host}`: fast score plus latest verdict.
- `GET /api/score?host=`: fast score only.
- `GET /api/intel?host=`: the site-intelligence report alone.
- `POST /api/events` / `GET /api/events`: resolver decisions.
- `GET /t/{token}?a=trust|once|review|report`: the alert action links.
- `GET /api/reviews`; `POST /api/reviews/{id}?decision=release|keep`.
- `GET /demo/{fine|deal|events}`; `GET /shots/{id}.jpg`.
- `GET /` serves the dashboard. If the `Host` is a `HOST_MAP` domain, it serves the matching demo page instead (name contains deal/sale → deal, event/guide → events, otherwise fine).

## Settings (`.env`; load with `set -a; source .env; set +a`)
- **Engine:**
  - `LLM_BASE_URL` (empty means OpenAI), `LLM_API_KEY`, `LLM_MODEL` (must accept images).
  - `LLM_MOCK=1` forces heuristics.
  - `ALLOW_PRIVATE=1` allows scanning localhost/LAN (**laptop demo only**).
  - `MAX_CONCURRENT`, `RATE_LIMIT_PER_10MIN`, `DATA_DIR`.
  - `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`.
  - `HOST_MAP=domain=ip,...` defines demo domains that exist only inside Raqib.
  - `PUBLIC_BASE_URL` (base of the alert links; must be reachable from the phone), `RAQIB_SECRET`.
- **Intel:** `GSB_API_KEY`, `VT_API_KEY` (free: 4 per minute, 500 per day; already throttled in code), `URLHAUS_AUTH_KEY`, `URLSCAN_API_KEY`. All optional.
- **Guard:** `UPSTREAM` (default 1.1.1.1), `ENGINE_URL`, `PORT` (default 53), `LISTEN`, `BLOCK_SCORE` (0.7), `SCAN_SCORE` (0.25).

## Run it: the minimum for the demo
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
ALLOW_PRIVATE=1 python -m uvicorn engine:app --port 8000
```
Open http://localhost:8000 and check all three:
- click **/demo/fine** → **BLOCKED** (critical: hidden AI instructions + data sent to a Telegram bot);
- `http://localhost:8000/demo/deal` → **CAUTION**;
- `http://localhost:8000/demo/events` → **WARN**.

Without `LLM_API_KEY` the card says "heuristic analysis." That's expected; **don't claim AI analysis in the video unless a key is set.**

## "Simulated phone": the real Guard, with `dig` standing in for phone taps
```bash
# Terminal 1 (port 80 so demo domains resolve to the engine)
sudo -E env ALLOW_PRIVATE=1 HOST_MAP="adpolice-fines-pay.com=127.0.0.1,iphone-mega-sale.com=127.0.0.1,dubai-events-guide.com=127.0.0.1" .venv/bin/python -m uvicorn engine:app --port 80
# Terminal 2
ENGINE_URL=http://127.0.0.1:80 PORT=5353 LISTEN=127.0.0.1 HOST_MAP="adpolice-fines-pay.com=127.0.0.1,iphone-mega-sale.com=127.0.0.1,dubai-events-guide.com=127.0.0.1" .venv/bin/python guard.py
# Terminal 3
dig @127.0.0.1 -p 5353 adpolice-fines-pay.com     # NXDOMAIN: held by name, then scanned → BLOCKED
dig @127.0.0.1 -p 5353 iphone-mega-sale.com       # first lookup resolves + scan; ~30 s later → NXDOMAIN (CAUTION)
dig @127.0.0.1 -p 5353 dubai-events-guide.com     # resolves (WARN)
```
The dashboard's "Live network decisions" panel shows each lookup. **Real phone:** set the phone's Wi-Fi DNS to the laptop IP, set `HOST_MAP` and `PUBLIC_BASE_URL` to the laptop's LAN IP, run the Guard on port 53 with sudo, and turn off Private DNS and Chrome's secure DNS. Full steps are in the README.

## Tested vs. not tested
- **Tested** (in a sandbox, LLM in mock mode):
  - all four tiers through the Guard;
  - per-device trust and "open once," and refusing trust on a BLOCKED site;
  - the SSRF guard (localhost and the cloud metadata address are refused);
  - character-level reading (`аdpolice-pay.com` with a Cyrillic а → flagged; Arabic `تم.ae` not flagged);
  - F03 linking two identical fake pages as one campaign;
  - the dashboard rendering.
- **Not tested:**
  - a real LLM call;
  - live intel sources (RDAP, WHOIS, ipinfo, Wayback, crt.sh, VirusTotal, Google Safe Browsing, URLhaus, OpenPhish, urlscan);
  - normal DNS forwarding to a real upstream;
  - a real phone;
  - Telegram delivery;
  - `hunter.py` against live crt.sh.
- **Quick live check:** scan `google.com`. It should come back CLEAN, and the site-intelligence panel should fill in.

## Rules
1. **Don't refactor or restructure.** Fix only what blocks the demo. Small, surgical edits.
2. **Never host a lookalike of a real authority on the public internet.** Demo domains live only in `HOST_MAP`, and the demo pages keep their DEMO watermark.
3. **Never commit `.env`** or any key. `.gitignore` already covers `.env`, `data/` and `hunter_candidates.csv`.
4. **Be honest in the demo.** Label simulated parts (phone, carrier deployment) as simulated. Don't say "AI" for heuristic results.
5. **Ask before anything irreversible:** pushing to a public repo, deleting files, or spending money on API credits.

## Likely next tasks, in priority order
1. Get it running on this machine and confirm the 3 demo scans give BLOCKED, CAUTION and WARN.
2. Optionally add an LLM key, then scan `/demo/fine` again and confirm "AI analysis" with a sensible `claimed_brand`.
3. Create a **public GitHub repo** and push. Check that no `.env` is included.
4. Optionally: Telegram bot token and chat ID, then the simulated-phone run.

## Known quirks
- `decide()` in `engine.py` still computes an older verdict. `run_scan` drops it and uses `flags.evaluate()`. Leave it alone.
- `domain_age_days()` is unused; age comes from `intel.py`.
- The dashboard loads Space Grotesk and Azeret Mono from Google Fonts; offline it falls back to system fonts.
- `hunter.py` defaults to `--engine http://127.0.0.1:8000`. Pass `--engine` if the engine runs on port 80.
- Python 3.10+ is required.
