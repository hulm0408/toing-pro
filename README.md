# Toing Pro

Swiggy ordering bot + Telegram Mini App — tumhare apne Swiggy account se,
Swiggy ke official MCP server (`https://mcp.swiggy.com/food`) ke upar.
Menu, price, payment kuch bhi local nahi — sab API se aata hai.

## Kya-kya hai

| Hissa | Kya karta hai |
| --- | --- |
| `toing.py` | Single-file product — `login` (OAuth DCR + PKCE) aur `bot` (Telegram bot) subcommands |
| `webapp/index.html` | Telegram Mini App — Cart, Orders, Accounts, Address, Search, Bulk (self-contained HTML) |
| `tests/` | Unit tests — httpx.MockTransport, koi live network call nahi |
| `run_checks.sh` | ruff + compile + tests — ek command me sab |
| `tests/fixtures/` | MCP/token response fixtures (mocked transport ke liye) |

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env    # BOT_TOKEN (BotFather) + ADMIN_ID (numeric Telegram ID) bharo
```

## Login (Swiggy account)

```bash
python toing.py login
```

1. Print hua authorize URL browser me kholo — phone + OTP do.
2. Page `http://localhost/callback` par fail hoga (expected) — URL bar se
   poora address copy karo (`?code=...` wala).
3. Paste karo (prompt me ya `--code '<url>'` se).

Result: `session.json` (0600) — `{client_id, access_token, refresh_token, expires_at}`.
Access token 5 din ka, refresh token 30 din ka aur **rotate hota hai** — har
refresh par file update hoti hai. Code ~2 min me expire hota hai, jaldi paste karo.

Bot me bhi yahi flow hai: `/login` → button → OTP → callback URL chat me paste →
bot khud session.json banata hai aur `/schema` dump bhejta hai.

## Bot chalao

```bash
python toing.py bot
```

Commands: `/start`, `/login`, `/schema` (tools/list dump), `session.json`
document upload (validate + save). Ek time par ek session — naya aane par purana
replace.

## Checks

```bash
./run_checks.sh     # ruff + compile + tests (sab mocked — koi live call nahi)
```

## Mini App (webapp/index.html)

Self-contained HTML — koi external CSS/JS nahi (Telegram WebApp script optional).
Local preview: `python3 -m http.server 8080 --directory webapp`.
Telegram me attach: public HTTPS URL chahiye (tunnel ya hosting) phir
`setChatMenuButton` se menu button set karo (script `toing.py` me live example).

## Zaroori warnings

- **Swiggy app aur bot saath me mat chalao** — order state clash ho sakta hai.
- `session.json` aur `.env` **kabhi commit mat karo** (gitignore me hain) —
  token/session secrets hain.
- `place_food_order` idempotent nahi hai — 504 par retry mat karo, pehle
  `get_food_orders` se check karo order bana ya nahi.
- COD orders cancel nahi hote — place se pehle bill review mandatory.
- Ek hi poller/token — do instance saath me 409 denge (PID lock isliye).

## Status

- MCP client (initialize → notifications/initialized → tools/call; SSE parse;
  `Mcp-Session-Id`; 401/-32001 → refresh → retry; rotation persist) — done, tested.
- OAuth login (DCR + PKCE, exchange, refresh) — done, tested (24 checks green).
- Telegram bot skeleton (`/start`, `/login`, `/schema`, session upload) — live.
- Mini app UI (poora Toing Pro interface) — live, abhi demo data.
- Ordering flow + mini app ka real data wiring — `/schema` verification ke baad
  (user ka login code aate hi; argument names guess nahi kiye jaate).
