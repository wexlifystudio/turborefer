"""
Turbo Refer V2 — Mini App Backend
FastAPI + Telethon + MongoDB + Telegram WebApp auth
"""

import os, re, hmac, json, time, uuid, asyncio, hashlib, random, base64, urllib.request, urllib.parse
from urllib.parse import parse_qsl

import emoji as emoji_lib
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest
from telethon.tl.functions.messages import ImportChatInviteRequest, CheckChatInviteRequest
from telethon.tl.types import ChatInviteAlready, ChatInvitePeek, MessageEntityTextUrl, MessageEntityUrl
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = FastAPI(title="Turbo Refer Mini App")

# ── Config (Render → Environment) ────────────────────────────────
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")              # from @BotFather
# One or more owners, comma-separated: OWNER_ID=8451097117,6176958592
OWNER_IDS   = [x.strip() for x in os.getenv("OWNER_ID", "").split(",") if x.strip()]
OWNER_ID    = OWNER_IDS[0] if OWNER_IDS else ""      # primary owner (used for old-data migration)
def is_owner(uid): return str(uid) in OWNER_IDS
MONGO_URL   = os.getenv("MONGO_URL", "")
API_SECRET  = os.getenv("API_SECRET", "")             # optional: legacy TBC access
DEFAULT_API_ID   = int(os.getenv("DEFAULT_API_ID", "21235972"))
DEFAULT_API_HASH = os.getenv("DEFAULT_API_HASH", "74231665725501b82753c06e72271545")

def creds(b):
    """API id/hash from request if given, else defaults. Session name = phone digits if not given."""
    api_id = int(b.get("api_id") or DEFAULT_API_ID)
    api_hash = (b.get("api_hash") or DEFAULT_API_HASH).strip()
    phone = re.sub(r"[^\d+]", "", b.get("phone", ""))
    name = (b.get("session_name") or "").strip() or ("acc_" + re.sub(r"\D", "", phone))
    return name, api_id, api_hash, phone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_HTML = os.path.join(BASE_DIR, "static", "index.html")

# ── MongoDB ──────────────────────────────────────────────────────
_mongo = None
def db():
    global _mongo
    if _mongo is None:
        _mongo = MongoClient(MONGO_URL, server_api=ServerApi("1"))
    return _mongo["turbo_refer"]

def load_accounts(owner=None):
    """owner=None → all accounts (admin). Else only that user's accounts."""
    try:
        q = {} if owner is None else {"owner": str(owner)}
        return list(db()["accounts"].find(q, {"_id": 0}))
    except Exception as e:
        print("DB error:", e); return []

def save_account(acc):
    db()["accounts"].update_one({"owner": acc["owner"], "session_name": acc["session_name"]}, {"$set": acc}, upsert=True)

def delete_account_db(owner, name):
    db()["accounts"].delete_one({"owner": str(owner), "session_name": name})
    db()["sessions"].delete_one({"owner": str(owner), "session_name": name})

def save_session(owner, name, s):
    db()["sessions"].update_one({"owner": str(owner), "session_name": name},
                                {"$set": {"owner": str(owner), "session_name": name, "session_str": s}}, upsert=True)

async def asave_session(owner, name, s):
    """Non-blocking version — use inside async Telethon workers so PyMongo's
    blocking I/O doesn't stall the event loop while other accounts are connecting."""
    await asyncio.to_thread(save_session, owner, name, s)

def get_session(owner, name):
    d = db()["sessions"].find_one({"owner": str(owner), "session_name": name})
    return d["session_str"] if d else None

async def aget_session(owner, name):
    return await asyncio.to_thread(get_session, owner, name)

def del_session(owner, name):
    db()["sessions"].delete_one({"owner": str(owner), "session_name": name})

def touch_user(user):
    """Record every person who opens the app."""
    uid = str(user.get("id"))
    db()["users"].update_one({"user_id": uid}, {"$set": {
        "user_id": uid, "name": (user.get("first_name", "") + " " + user.get("last_name", "")).strip(),
        "username": user.get("username", ""), "last_seen": int(time.time())},
        "$setOnInsert": {"first_seen": int(time.time())}}, upsert=True)

def migrate():
    """One-time: old accounts without owner belong to OWNER_ID."""
    try:
        if OWNER_ID:
            db()["accounts"].update_many({"owner": {"$exists": False}}, {"$set": {"owner": OWNER_ID}})
            db()["sessions"].update_many({"owner": {"$exists": False}}, {"$set": {"owner": OWNER_ID}})
        if setting_get("access_mode") is None:
            setting_set("access_mode", "approved")
    except Exception as e:
        print("migrate:", e)

def user_list(kind):  # kind: "whitelist" | "banlist"
    return [str(x["user_id"]) for x in db()[kind].find({}, {"_id": 0})]

def user_add(kind, uid, meta=None):
    doc = {"user_id": str(uid), "added_at": int(time.time())}
    if meta: doc.update(meta)
    db()[kind].update_one({"user_id": str(uid)}, {"$set": doc}, upsert=True)

def user_remove(kind, uid):
    db()[kind].delete_one({"user_id": str(uid)})

def setting_get(key, default=None):
    d = db()["settings"].find_one({"key": key})
    return d["value"] if d else default

def setting_set(key, value):
    db()["settings"].update_one({"key": key}, {"$set": {"key": key, "value": value}}, upsert=True)

# ── Telegram WebApp auth ──────────────────────────────────────────
def verify_init_data(init_data: str):
    """Returns user dict if initData signature is valid, else None."""
    if not init_data or not BOT_TOKEN:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True))
        their_hash = pairs.pop("hash", "")
        check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calc = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, their_hash):
            return None
        if time.time() - int(pairs.get("auth_date", "0")) > 86400 * 3:
            return None
        return json.loads(pairs.get("user", "{}"))
    except Exception:
        return None

def current_user(request: Request):
    """Resolve caller → {id, name, role}. role: owner | user. Raises 401/403."""
    init_data = request.headers.get("x-init-data", "")
    secret = request.headers.get("x-api-secret", "")

    if API_SECRET and secret and hmac.compare_digest(secret, API_SECRET):
        return {"id": OWNER_ID or "0", "name": "Owner (API)", "role": "owner"}

    if not BOT_TOKEN:
        raise HTTPException(500, "BOT_TOKEN is not set on the server.")
    user = verify_init_data(init_data)
    if user is None:
        raise HTTPException(401, "Open this app from Telegram.")

    uid = str(user.get("id"))
    name = (user.get("first_name", "") + " " + user.get("last_name", "")).strip() or "User"
    try: touch_user(user)
    except Exception: pass
    if uid in user_list("banlist"):
        raise HTTPException(403, "You are banned.")
    if is_owner(uid):
        return {"id": uid, "name": name, "role": "owner", "username": user.get("username", "")}
    if setting_get("lockdown", False) and not is_owner(uid):
        raise HTTPException(423, setting_get("lockdown_msg") or "The app is temporarily down for maintenance. Please try again soon.")
    if setting_get("access_mode", "approved") == "open" or uid in user_list("whitelist"):
        return {"id": uid, "name": name, "role": "user", "username": user.get("username", "")}
    raise HTTPException(403, "no_access")

def require_owner(request: Request):
    u = current_user(request)
    if u["role"] != "owner":
        raise HTTPException(403, "Owner only.")
    return u

# ── Telethon helpers ─────────────────────────────────────────────
_ACC_LOCKS = {}
def _acc_lock(acc):
    """One lock per (owner, session_name) so the same account's session string
    is never opened by two Telethon clients at the same time (causes 'EOF when
    reading a line' / corrupted auth key)."""
    key = (acc["owner"], acc["session_name"])
    lock = _ACC_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _ACC_LOCKS[key] = lock
    return lock

async def get_client(acc):
    s = await aget_session(acc["owner"], acc["session_name"])
    session = StringSession()
    if s:
        try:
            session = StringSession(s)
            # Force-validate the session string right away — a corrupted string
            # (e.g. from an old race condition) won't raise until the first real
            # network read, which is what produced "EOF when reading a line".
            session.auth_key
        except Exception as e:
            raise RuntimeError(f"Saved session for '{acc['session_name']}' is corrupted ({type(e).__name__}). Delete and re-add this account.") from e
    # connection_retries=1 + short timeout: fail fast instead of hanging a slot for
    # 20s+ on a bad account — this is what actually speeds up a big batch, since one
    # stuck connection no longer blocks the concurrency pool for the others.
    return TelegramClient(session, acc["api_id"], acc["api_hash"],
                           connection_retries=1, retry_delay=1, timeout=10,
                           auto_reconnect=False, request_retries=2)

def alert_dead_accounts(owner, dead_names):
    if not dead_names: return
    try:
        lines = ["🚨 <b>Account problem detected</b>", "",
                 f"{len(dead_names)} account(s) need to be re-added:"]
        for n in dead_names[:10]:
            lines.append(f"• <code>{n}</code>")
        lines.append("\nOpen the app → Accounts → delete and add them again.")
        tg_send(owner, "\n".join(lines))
    except Exception as e:
        print("dead alert error:", e)

def friendly_error(e):
    msg = str(e)
    if "EOF when reading a line" in msg or "Server sent a very weird response" in msg:
        return f"Connection hiccup ({type(e).__name__}: {msg[:120]})"
    if "database is locked" in msg.lower():
        return "Account busy with another task — try again in a moment"
    if "The authorization key" in msg or "AUTH_KEY" in msg:
        return "Session expired — needs re-login"
    if "A wait of" in msg and "is required" in msg:
        return msg  # flood wait, already clear
    return f"{type(e).__name__}: {msg[:180]}"

def parse_bot_link(link):
    m = re.match(r"https?://t\.me/([A-Za-z0-9_]+)(?:\?start=(.*))?", link.strip())
    return (m.group(1), m.group(2) or "") if m else (None, None)

def parse_invite_hash(link):
    """Return the invite hash if `link` is a private-channel invite link
    (t.me/+<hash> or t.me/joinchat/<hash>), else None."""
    s = link.strip()
    m = re.match(r"https?://t\.me/\+([A-Za-z0-9_-]+)", s)
    if m:
        return m.group(1)
    m = re.match(r"https?://t\.me/joinchat/([A-Za-z0-9_-]+)", s)
    if m:
        return m.group(1)
    return None

def pick_accounts(owner, names, skip_dead=True, exclude=None):
    accs = load_accounts(owner)
    sel = [a for a in accs if not a.get("excluded")] if not names else [a for a in accs if a["session_name"] in names]
    # The Link Finder default account is reserved for that job only — never let
    # it run Referral / Join-Leave / Message, even if it was explicitly picked.
    sel = [a for a in sel if not a.get("link_finder_default")]
    if exclude:
        ex = set(exclude)
        sel = [a for a in sel if a["session_name"] not in ex]
    if skip_dead:
        alive = [a for a in sel if a.get("health") != "dead"]
        return alive, [a["session_name"] for a in sel if a.get("health") == "dead"]
    return sel, []

# ── Job system (background + live polling) ───────────────────────
JOBS = {}

def job_new(owner, kind, total, meta=None):
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"id": jid, "owner": str(owner), "kind": kind, "status": "running", "total": total,
                 "done": 0, "success": 0, "failed": 0, "results": [],
                 "meta": meta or {}, "started": int(time.time())}
    return jid

def job_push(jid, r):
    j = JOBS[jid]; j["results"].append(r); j["done"] += 1
    if r.get("status") == "success": j["success"] += 1
    else: j["failed"] += 1

def job_cancel_requested(jid):
    j = JOBS.get(jid)
    return bool(j and j.get("cancel"))

# Rough rolling counter of Telegram API calls made by this server, for a simple
# "how close to Telegram's limits are we" dashboard. Not exact — Telegram doesn't
# expose real quotas — but useful as a live activity gauge.
_API_CALL_LOG = []  # list of unix timestamps

def log_api_call():
    now = time.time()
    _API_CALL_LOG.append(now)
    if len(_API_CALL_LOG) > 5000:
        del _API_CALL_LOG[:2500]

def api_call_rate():
    now = time.time()
    last_min = sum(1 for t in _API_CALL_LOG if now - t <= 60)
    last_hour = sum(1 for t in _API_CALL_LOG if now - t <= 3600)
    return {"per_minute": last_min, "per_hour": last_hour}

KIND_LABEL = {"refer": "Referral", "channels": "Join / Leave", "message": "Send message",
              "health": "Health check", "auto_leave": "Auto-leave"}

MILESTONES = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000]

def update_progress(owner, success_count):
    """Bump this owner's lifetime success counter and daily-streak, return any
    milestone just crossed (or None) so the frontend can celebrate it once."""
    if success_count <= 0 or not owner:
        return None, None
    today = time.strftime("%Y-%m-%d", time.gmtime())
    col = db()["progress"]
    doc = col.find_one({"owner": owner}) or {"owner": owner, "total_success": 0, "streak": 0, "last_day": ""}
    prev_total = doc.get("total_success", 0)
    new_total = prev_total + success_count
    streak = doc.get("streak", 0)
    last_day = doc.get("last_day", "")
    if last_day != today:
        yesterday = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
        streak = (streak + 1) if last_day == yesterday else 1
    col.update_one({"owner": owner}, {"$set": {"total_success": new_total, "streak": streak, "last_day": today}}, upsert=True)
    milestone = next((m for m in MILESTONES if prev_total < m <= new_total), None)
    return milestone, streak

def job_finish(jid):
    j = JOBS[jid]
    j["status"] = "cancelled" if j.get("cancel") else "done"
    j["ended"] = int(time.time())
    milestone, streak = update_progress(j.get("owner"), j.get("success", 0))
    j["milestone"] = milestone
    j["streak"] = streak
    try: db()["jobs"].insert_one(dict(j))
    except Exception: pass
    # Notify the owner of this job in Telegram
    try:
        if j["total"] >= 1 and j.get("owner"):
            label = KIND_LABEL.get(j["kind"], j["kind"])
            icon = "🛑" if j["status"] == "cancelled" else ("✅" if not j["failed"] else ("⚠️" if j["success"] else "❌"))
            took = j["ended"] - j.get("started", j["ended"])
            lines = [f"{icon} <b>{label} {j['status']}</b>",
                     f"✅ {j['success']} ok · ❌ {j['failed']} failed · {j['total']} total",
                     f"⏱ {took}s"]
            if j["meta"].get("skipped_dead"):
                lines.append(f"⏭ Skipped {len(j['meta']['skipped_dead'])} dead account(s)")
            if milestone:
                lines.append(f"\n🎉 <b>Milestone unlocked: {milestone:,} lifetime successful runs!</b>")
            bad = [r for r in j.get("results", []) if r.get("status") != "success"][:5]
            if bad:
                lines.append("\n<b>Failed:</b>")
                for r in bad:
                    lines.append(f"• <code>{r['account']}</code> — {str(r.get('msg',''))[:70]}")
            tg_send(j["owner"], "\n".join(lines))
            log_chan = setting_get("log_channel", "")
            if log_chan:
                tg_send(log_chan, "\n".join(lines))
    except Exception as e:
        print("job alert error:", e)

# ── Referral workers ─────────────────────────────────────────────
# After an answer is sent, the bot's next reply tells us if it was accepted.
_CAPTCHA_BAD  = re.compile(r"wrong|incorrect|invalid|failed|not correct|try again|mismatch|❌", re.I)
_CAPTCHA_GOOD = re.compile(r"success|verified|correct|passed|✅|welcome|thank", re.I)
CAPTCHA_MAX_TRIES = 3

async def _captcha_flow(acc, bot_link, solver):
    client = await get_client(acc)
    wait_s = getattr(solver, "timeout", 20)
    result = {"account": acc["session_name"], "status": "timeout", "msg": f"No captcha response in {wait_s}s"}
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        answered = asyncio.Event()   # solver sent/clicked an answer
        done = asyncio.Event()       # bot confirmed (or we gave up after too many wrong answers)
        state = {"answered": False, "wrong": 0}

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                if state["answered"]:
                    t = event.raw_text or ""
                    if _CAPTCHA_BAD.search(t):
                        state["wrong"] += 1; state["answered"] = False
                        result.update({"status": "error", "msg": f"Bot rejected answer ({state['wrong']}x)"})
                        if state["wrong"] >= CAPTCHA_MAX_TRIES:
                            done.set(); return
                        # fall through — this same message may carry a fresh captcha
                    elif _CAPTCHA_GOOD.search(t):
                        result["status"] = "success"; result["msg"] += " · verified ✓"
                        done.set(); return
                    else:
                        return
                r = await solver(event, client, bot_user)
                if r:
                    result.update(r); state["answered"] = True; answered.set()
            except Exception as ex:
                result.update({"status": "error", "msg": str(ex)[:80]}); answered.set(); done.set()

        await client.send_message(bot_user, f"/start {param}".strip())
        try:
            await asyncio.wait_for(answered.wait(), timeout=wait_s)
        except asyncio.TimeoutError:
            pass
        if answered.is_set() and getattr(solver, "verify", False) and not done.is_set():
            # give the bot time to say right/wrong (and to resend a new captcha if wrong)
            try:
                await asyncio.wait_for(done.wait(), timeout=wait_s)
            except asyncio.TimeoutError:
                if state["answered"] and result["status"] == "success":
                    result["msg"] += " · (no confirmation from bot)"
        await asave_session(acc["owner"], acc["session_name"], client.session.save())
    except errors.FloodWaitError:
        raise
    except Exception as e:
        result.update({"status": "error", "msg": friendly_error(e)})
    finally:
        try: await client.disconnect()
        except Exception: pass
    return result

async def solve_none(event, client, bot_user):
    return {"status": "success", "msg": "Started"}

async def solve_emoji(event, client, bot_user):
    if not event.buttons: return None
    emojis = [it["emoji"] for it in emoji_lib.emoji_list(event.raw_text or "")]
    for row in event.buttons:
        for btn in row:
            for e in emojis:
                if e in (btn.text or ""):
                    await btn.click(); return {"status": "success", "msg": f"Emoji {e}"}
    return None

async def solve_math(event, client, bot_user):
    m = re.search(r"(\d+)\s*([+\-*/×÷x])\s*(\d+)", event.raw_text or "")
    if not m: return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    ans = a + b if op == "+" else a - b if op == "-" else a * b if op in "*×x" else (a // b if b else 0)
    if event.buttons:
        for row in event.buttons:
            for btn in row:
                if str(ans) == (btn.text or "").strip():
                    await btn.click(); return {"status": "success", "msg": f"{a}{op}{b}={ans}"}
    await client.send_message(bot_user, str(ans))
    return {"status": "success", "msg": f"Answered {ans}"}

async def solve_button(event, client, bot_user):
    if not event.buttons: return None
    await event.buttons[0][0].click()
    return {"status": "success", "msg": f"Clicked '{event.buttons[0][0].text}'"}

# ── Text-code captcha ────────────────────────────────────────────
# Bot shows a code (usually in monospace) and asks you to send it back exactly,
# e.g. "Your Verification Code: 7LsT4oFd".
_CODE_HINT = re.compile(r"code|captcha|verif|security|copy|send it|type", re.I)
_CODE_TOKEN = re.compile(r"^[A-Za-z0-9_\-]{3,32}$")

def _looks_like_code(t):
    """A real code has a digit or several capitals (7LsT4oFd, XKQPD) — not an
    ordinary word like 'what' / 'Please' / 'below'."""
    return any(c.isdigit() for c in t) or sum(c.isupper() for c in t) >= 2

def _extract_text_code(msg):
    text = msg.raw_text or ""
    if not _CODE_HINT.search(text):
        return None
    # 1) monospace / pre-formatted entities — the most reliable signal
    try:
        for ent, val in (msg.get_entities_text() or []):
            if type(ent).__name__ in ("MessageEntityCode", "MessageEntityPre"):
                v = (val or "").strip()
                if _CODE_TOKEN.match(v) and not v.lower().startswith(("http", "start")):
                    return v
    except Exception:
        pass
    # 2) plain text: the token right after "code:" / "captcha:" (same or next line)
    m = re.search(r"(?:code|captcha)[^\n:：]{0,20}[:：]?\s*\n?\s*([A-Za-z0-9]{4,16})\b", text, re.I)
    if m and _looks_like_code(m.group(1)):
        return m.group(1)
    # 3) a line that is nothing but a code-looking token (mixed letters+digits)
    for line in text.splitlines():
        s = line.strip()
        if re.fullmatch(r"(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9]{5,16}", s):
            return s
    return None

async def solve_text_code(event, client, bot_user):
    code = _extract_text_code(event.message)
    if not code:
        return None
    await client.send_message(bot_user, code)
    return {"status": "success", "msg": f"Sent code {code}"}
solve_text_code.verify = True

# ── Image captcha (numbers/letters drawn in a picture) ───────────
# Uses the free OCR.space API. Set OCR_API_KEY on Render (free key from
# https://ocr.space/ocrapi) — the built-in "helloworld" demo key is heavily rate-limited.
# If the optional `ddddocr` package is installed it is tried first (offline, no key).
OCR_API_KEY = os.getenv("OCR_API_KEY", "helloworld")
_OCR_CACHE = {}
_DDDD = {"engine": None, "tried": False}
_DIGIT_FIX = str.maketrans({"O": "0", "o": "0", "Q": "0", "D": "0", "I": "1", "l": "1", "|": "1", "i": "1",
                            "S": "5", "s": "5", "B": "8", "Z": "2", "z": "2", "G": "6", "g": "9", "q": "9"})

def _ocr_local(img):
    if not _DDDD["tried"]:
        _DDDD["tried"] = True
        try:
            import ddddocr
            try: _DDDD["engine"] = ddddocr.DdddOcr(show_ad=False)
            except TypeError: _DDDD["engine"] = ddddocr.DdddOcr()
        except Exception:
            _DDDD["engine"] = None
    eng = _DDDD["engine"]
    return eng.classification(img) if eng else None

def _ocr_space(img):
    data = urllib.parse.urlencode({
        "apikey": OCR_API_KEY, "OCREngine": "2", "scale": "true", "isOverlayRequired": "false",
        "base64Image": "data:image/jpeg;base64," + base64.b64encode(img).decode(),
    }).encode()
    req = urllib.request.Request("https://api.ocr.space/parse/image", data=data)
    with urllib.request.urlopen(req, timeout=25) as r:
        j = json.loads(r.read().decode())
    if j.get("IsErroredOnProcessing"):
        raise RuntimeError("OCR: " + str(j.get("ErrorMessage"))[:70])
    return "\n".join(p.get("ParsedText", "") for p in (j.get("ParsedResults") or []))

def _pick_captcha_answer(raw):
    """OCR text may include banner words (e.g. 'SN BOT CREATOR 15473') — pick the captcha."""
    lines = [l.strip() for l in (raw or "").splitlines() if l.strip()]
    # 1) longest pure digit run (spaces inside a line removed: '1 5 4 7 3' → 15473)
    best = ""
    for l in lines:
        for run in re.findall(r"\d{3,}", l.replace(" ", "")):
            if len(run) > len(best): best = run
    if best:
        return best
    # 2) mostly-digit tokens with typical OCR confusions fixed (O→0, S→5, …)
    for l in lines:
        tok = l.replace(" ", "")
        if 3 <= len(tok) <= 10 and any(c.isdigit() for c in tok):
            fixed = tok.translate(_DIGIT_FIX)
            if fixed.isdigit(): return fixed
    # 3) alphanumeric captcha: prefer tokens containing a digit, then the longest
    toks = [t for t in re.findall(r"[A-Za-z0-9]{4,12}", " ".join(lines))]
    if not toks: return None
    with_digit = [t for t in toks if any(c.isdigit() for c in t)]
    return max(with_digit or toks, key=len)

async def _ocr_image(img):
    key = hashlib.sha1(img).hexdigest()
    if key in _OCR_CACHE:
        return _OCR_CACHE[key]
    ans = None
    try:
        raw = await asyncio.to_thread(_ocr_local, img)
        if raw: ans = _pick_captcha_answer(raw)
    except Exception:
        ans = None
    if not ans:
        ans = _pick_captcha_answer(await asyncio.to_thread(_ocr_space, img))
    if ans:
        if len(_OCR_CACHE) > 500: _OCR_CACHE.clear()
        _OCR_CACHE[key] = ans
    return ans

_IMG_HINT = re.compile(r"captcha|code|enter|verif|solve|type|number|digit", re.I)

async def solve_image(event, client, bot_user):
    m = event.message
    is_img = bool(m.photo) or bool(m.document and (m.document.mime_type or "").startswith("image/"))
    if not is_img:
        return None
    text = m.raw_text or ""
    if text and not _IMG_HINT.search(text):
        return None   # a banner / welcome picture, not the captcha
    img = await client.download_media(m, file=bytes)
    if not img:
        return None
    ans = await _ocr_image(img)
    if not ans:
        raise RuntimeError("Couldn't read the captcha image")
    await client.send_message(bot_user, ans)
    return {"status": "success", "msg": f"Image captcha → {ans}"}
solve_image.verify = True
solve_image.timeout = 40   # OCR takes a few seconds; allow more time

solve_math.verify = True

# ── Auto-detect captcha ──────────────────────────────────────────
# Looks at a bot message and picks the matching solver itself. Conservative on
# purpose: math/emoji only fire when the text actually asks for it, so ordinary
# welcome/sponsor messages are never "answered".
_MATH_HINT = re.compile(r"captcha|solve|answer|calculate|result|=\s*\?|\?\s*$|how much|what is", re.I | re.M)
_TAP_HINT  = re.compile(r"captcha|verif|click|tap|press|select|choose|human|robot|bot check", re.I)

def _has_url_buttons(m):
    return any(getattr(btn, "url", None) for row in (m.buttons or []) for btn in row)

async def solve_auto(event, client, bot_user):
    m = event.message
    if m.photo or (m.document and (m.document.mime_type or "").startswith("image/")):
        r = await solve_image(event, client, bot_user)
        if r: return {**r, "msg": "🖼️ " + r["msg"]}
    text = m.raw_text or ""
    # math before text-code: "Captcha: what is 5 + 3 = ?" must be answered 8, not "what"
    if _MATH_HINT.search(text) and re.search(r"\d+\s*[+\-*/×÷x]\s*\d+", text):
        r = await solve_math(event, client, bot_user)
        if r: return {**r, "msg": "➗ " + r["msg"]}
    r = await solve_text_code(event, client, bot_user)
    if r: return {**r, "msg": "🔤 " + r["msg"]}
    if m.buttons and not _has_url_buttons(m) and _TAP_HINT.search(text):
        r = await solve_emoji(event, client, bot_user)
        if r: return {**r, "msg": "😀 " + r["msg"]}
    return None
solve_auto.verify = True
solve_auto.timeout = 40

SOLVERS = {"no_captcha": None, "auto": solve_auto, "emoji": solve_emoji, "math": solve_math, "button": solve_button,
           "text_code": solve_text_code, "image": solve_image}

async def refer_plain(acc, bot_link):
    client = await get_client(acc)
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user: return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        await client.send_message(bot_user, f"/start {param}".strip())
        await asyncio.sleep(2)
        await asave_session(acc["owner"], acc["session_name"], client.session.save())
        return {"account": acc["session_name"], "status": "success", "msg": "Started"}
    except Exception as e:
        return {"account": acc["session_name"], "status": "error", "msg": friendly_error(e)}
    finally:
        try: await client.disconnect()
        except Exception: pass

FLOOD_AUTO_WAIT_MAX = 60  # only auto-wait out floods this short; longer ones are reported instead

async def run_with_flood_retry(worker, acc, jid):
    """Run worker(acc) once. If Telegram replies with a short flood-wait, wait it
    out and retry automatically (once) instead of failing the account outright."""
    log_api_call()
    try:
        return await worker(acc)
    except errors.FloodWaitError as e:
        if e.seconds <= FLOOD_AUTO_WAIT_MAX and not job_cancel_requested(jid):
            await asyncio.sleep(e.seconds + 1)
            try:
                r = await worker(acc)
                r["msg"] = f"(auto-retried after {e.seconds}s flood-wait) " + str(r.get("msg", ""))
                return r
            except Exception as e2:
                return {"account": acc["session_name"], "status": "error", "msg": friendly_error(e2)}
        return {"account": acc["session_name"], "status": "error", "msg": f"Flood-wait {e.seconds}s — too long to auto-retry"}
    except Exception as e:
        return {"account": acc["session_name"], "status": "error", "msg": friendly_error(e)}

async def _run_pool(jid, accs, worker, concurrency, delay):
    """Run worker(acc) over accs with N at a time; delay between starts.
    'last_used' timestamps are buffered and flushed to MongoDB in one batched
    update_many() every 2s instead of one update_one() per account — far fewer
    DB round trips on a big run, and no worker blocks waiting on its own write."""
    concurrency = max(1, min(int(concurrency), 50))
    sem = asyncio.Semaphore(concurrency)
    touched = set()
    owner = accs[0]["owner"] if accs else None
    async def flush_touched():
        if not touched: return
        names = list(touched); touched.clear()
        try:
            await asyncio.to_thread(
                lambda: db()["accounts"].update_many(
                    {"owner": owner, "session_name": {"$in": names}},
                    {"$set": {"last_used": int(time.time())}}))
        except Exception as e:
            print("last_used batch flush error:", e)
    async def periodic_flush():
        try:
            while True:
                await asyncio.sleep(2)
                await flush_touched()
        except asyncio.CancelledError:
            pass
    async def one(i, acc):
        await asyncio.sleep(i * delay if concurrency > 1 else 0)   # stagger starts
        if job_cancel_requested(jid):
            return
        async with sem:
            if job_cancel_requested(jid):
                return
            async with _acc_lock(acc):   # never run this same account's session twice at once
                r = await run_with_flood_retry(worker, acc, jid)
            touched.add(acc["session_name"])
            job_push(jid, r)
            if concurrency == 1:
                await asyncio.sleep(delay)
    flusher = asyncio.create_task(periodic_flush())
    await asyncio.gather(*(one(i, a) for i, a in enumerate(accs)))
    flusher.cancel()
    await flush_touched()   # final flush for anything since the last periodic tick
    job_finish(jid)

async def run_refer_job(jid, accs, link, method, delay, concurrency=1):
    solver = SOLVERS.get(method)
    async def worker(acc):
        return await (refer_plain(acc, link) if solver is None else _captcha_flow(acc, link, solver))
    await _run_pool(jid, accs, worker, concurrency, delay)

async def _join_one(client, ch):
    """Join a public channel/username or a private invite link (t.me/+hash,
    t.me/joinchat/hash). Raises on real failure; returns quietly on success
    (including 'already a member')."""
    inv_hash = parse_invite_hash(ch)
    if inv_hash:
        try:
            await client(ImportChatInviteRequest(inv_hash))
        except errors.UserAlreadyParticipantError:
            pass  # already in the channel — treat as success
        except (errors.InviteHashExpiredError, errors.InviteHashInvalidError):
            raise
        except errors.InviteRequestSentError:
            # join request submitted, awaiting admin approval — count as success
            pass
    else:
        await client(JoinChannelRequest(ch))

async def _leave_one(client, ch):
    """Leave a public channel/username or a private invite link. For invite
    links we must resolve the actual entity first (CheckChatInviteRequest for
    a link we're not in returns a peek object, not something we can leave)."""
    inv_hash = parse_invite_hash(ch)
    if inv_hash:
        info = await client(CheckChatInviteRequest(inv_hash))
        if isinstance(info, ChatInviteAlready):
            entity = info.chat
        elif isinstance(info, ChatInvitePeek):
            entity = info.chat
        else:
            entity = getattr(info, "chat", None)
        if entity is None:
            raise ValueError("not a member of this invite link")
        await client(LeaveChannelRequest(entity))
    else:
        await client(LeaveChannelRequest(await client.get_entity(ch)))

async def run_channel_job(jid, accs, channels, action, delay=2, concurrency=1):
    async def worker(acc):
        client = await get_client(acc); ok = 0; lines = []
        try:
            await client.start()
            for ch in channels:
                try:
                    if action == "join":
                        await _join_one(client, ch)
                    else:
                        await _leave_one(client, ch)
                    ok += 1; lines.append(f"✓ {ch}")
                except Exception as e:
                    lines.append(f"✗ {ch}: {str(e)[:60]}")
                await asyncio.sleep(delay)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
            st = "success" if ok == len(channels) else ("partial" if ok else "error")
            return {"account": acc["session_name"], "status": st, "msg": f"{ok}/{len(channels)} · " + " · ".join(lines)}
        finally:
            try: await client.disconnect()
            except Exception: pass
    await _run_pool(jid, accs, worker, concurrency, delay)

async def run_message_job(jid, accs, target, text, delay=2, concurrency=1):
    async def worker(acc):
        client = await get_client(acc)
        try:
            await client.start()
            await client.send_message(target, text)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
            return {"account": acc["session_name"], "status": "success", "msg": "Sent"}
        finally:
            try: await client.disconnect()
            except Exception: pass
    await _run_pool(jid, accs, worker, concurrency, delay)

def speed_params(b, n_accounts):
    """speed: single | parallel | custom → (concurrency, delay).
    Default (no speed sent, or mode missing) is now 'fast': 8 accounts at once, 1.5s delay —
    tuned to stay inside Render's free 512MB RAM instead of the old single/slow default."""
    mode = b.get("speed", "fast")
    delay = float(b.get("delay", 1.5))
    if mode == "parallel":
        return min(n_accounts, 50), max(0.3, min(delay, 2))
    if mode == "custom":
        return max(1, int(b.get("concurrency", 8))), delay
    if mode == "single":
        return 1, max(delay, 1)
    # "fast" (new default): safe high concurrency within free-tier RAM
    return min(n_accounts, 8), max(0.5, min(delay, 1.5))

# ── Pages ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/app", response_class=HTMLResponse)
async def index():
    with open(INDEX_HTML, encoding="utf-8") as f:
        html = f.read()
    # Telegram's in-app WebView aggressively caches the Mini App page, so a
    # deploy can go live on Render while users still see the old HTML/JS for
    # days. Force it to always refetch — every screen already re-fetches its
    # own data from the API, so a fresh load is cheap.
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

@app.get("/ping")
async def ping():
    return {"ping": "pong"}

# ── Auth ─────────────────────────────────────────────────────────
@app.get("/api/progress")
async def progress(request: Request):
    """Lifetime success count + daily streak for the Home screen."""
    u = current_user(request)
    doc = db()["progress"].find_one({"owner": u["id"]}, {"_id": 0}) or {"total_success": 0, "streak": 0, "last_day": ""}
    today = time.strftime("%Y-%m-%d", time.gmtime())
    yesterday = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
    streak = doc.get("streak", 0)
    if doc.get("last_day") not in (today, yesterday):
        streak = 0  # streak broken — hasn't run today or yesterday
    next_milestone = next((m for m in MILESTONES if m > doc.get("total_success", 0)), None)
    return {"total_success": doc.get("total_success", 0), "streak": streak, "next_milestone": next_milestone}

@app.get("/api/weekly-recap")
async def weekly_recap(request: Request):
    """A shareable 'wrapped'-style summary of the last 7 days for this user."""
    u = current_user(request)
    owner = u["id"]
    d = db()
    now = int(time.time()); week_ago = now - 7 * 86400
    q = {"owner": owner, "ended": {"$gt": week_ago}}
    jobs = list(d["jobs"].find(q, {"_id": 0})) + \
           [j for j in JOBS.values() if j.get("owner") == owner and j.get("started", 0) > week_ago and j.get("status") != "running"]
    seen = set(); uniq = []
    for j in jobs:
        if j["id"] in seen: continue
        seen.add(j["id"]); uniq.append(j)
    if not uniq:
        return {"has_data": False}

    total_success = sum(j.get("success", 0) for j in uniq)
    total_failed = sum(j.get("failed", 0) for j in uniq)
    per_acc = {}
    fastest = None
    for j in uniq:
        for r in j.get("results", []):
            a = per_acc.setdefault(r["account"], {"account": r["account"], "success": 0})
            if r.get("status") == "success": a["success"] += 1
        started, ended, total = j.get("started"), j.get("ended"), j.get("total", 0)
        if started and ended and ended > started and total:
            rate = total / (ended - started)
            if not fastest or rate > fastest["rate"]:
                fastest = {"rate": round(rate, 2), "kind": j.get("kind"), "total": total}
    best_account = max(per_acc.values(), key=lambda a: a["success"], default=None)
    by_kind = {}
    for j in uniq:
        k = j.get("kind", "?"); by_kind[k] = by_kind.get(k, 0) + 1
    busiest_kind = max(by_kind.items(), key=lambda x: x[1])[0] if by_kind else None
    return {
        "has_data": True, "jobs": len(uniq), "success": total_success, "failed": total_failed,
        "best_account": best_account, "fastest_run": fastest,
        "busiest_task": KIND_LABEL.get(busiest_kind, busiest_kind),
        "accounts_used": len(per_acc),
    }

@app.get("/api/me")
async def me(request: Request):
    try:
        u = current_user(request)
    except HTTPException as e:
        if e.detail == "no_access":
            user = verify_init_data(request.headers.get("x-init-data", "")) or {}
            return JSONResponse({"role": "none", "id": str(user.get("id", "")), "name": user.get("first_name", "")}, 403)
        raise
    return {**u, "accounts": len(load_accounts(u["id"]))}

@app.post("/api/request-access")
async def request_access(request: Request):
    """Pending user asks for approval → owner gets a bot message."""
    if not BOT_TOKEN: raise HTTPException(500, "BOT_TOKEN is not set on the server.")
    user = verify_init_data(request.headers.get("x-init-data", ""))
    if not user: raise HTTPException(401, "Open this app from Telegram.")
    uid = str(user.get("id"))
    if uid in user_list("banlist"): raise HTTPException(403, "You are banned.")
    touch_user(user)
    rec = db()["users"].find_one({"user_id": uid}) or {}
    if rec.get("requested_at") and time.time() - rec["requested_at"] < 3600:
        return {"status": "success", "already": True}
    db()["users"].update_one({"user_id": uid}, {"$set": {"requested_at": int(time.time())}})
    name = (user.get("first_name", "") + " " + user.get("last_name", "")).strip()
    un = ("@" + user["username"]) if user.get("username") else "no username"
    for _oid in OWNER_IDS:
        tg_send(_oid, f"🔔 <b>Access request</b>\n\n👤 {name} ({un})\n🆔 <code>{uid}</code>\n\nOpen the app → Admin → Pending to approve.")
    return {"status": "success", "already": False}

# ── Accounts ─────────────────────────────────────────────────────
@app.get("/api/accounts/diagnose/{name}")
async def diagnose_account(name: str, request: Request):
    """Quick check: is the saved session string for this account well-formed?"""
    u = current_user(request)
    acc = next((a for a in load_accounts(u["id"]) if a["session_name"] == name), None)
    if not acc: raise HTTPException(404, "Account not found")
    s = await aget_session(u["id"], name)
    if not s:
        return {"session_name": name, "has_session": False}
    try:
        sess = StringSession(s)
        auth_ok = sess.auth_key is not None and len(sess.auth_key.key) == 256
        return {"session_name": name, "has_session": True, "length": len(s), "auth_key_ok": auth_ok, "dc_id": sess.dc_id}
    except Exception as e:
        return {"session_name": name, "has_session": True, "length": len(s), "corrupted": True, "error": f"{type(e).__name__}: {e}"}

@app.get("/api/accounts")
async def accounts(request: Request):
    u = current_user(request)
    out = []
    for a in load_accounts(u["id"]):
        p = a.get("phone", "")
        out.append({"session_name": a["session_name"], "api_id": a["api_id"],
                    "name": a.get("name", ""), "username": a.get("username", ""),
                    "phone": p[:4] + "•••" + p[-3:] if len(p) > 7 else p,
                    "health": a.get("health", "unknown"), "health_detail": a.get("health_detail", ""),
                    "health_checked": a.get("health_checked"),
                    "note": a.get("note", ""), "excluded": bool(a.get("excluded")),
                    "last_used": a.get("last_used"), "created": a.get("created"),
                    "link_finder_default": bool(a.get("link_finder_default"))})
    return {"count": len(out), "accounts": out}

@app.post("/api/accounts/request-code")
async def request_code(request: Request):
    u = current_user(request)
    b = await request.json()
    name, api_id, api_hash, phone = creds(b)
    if not re.match(r"^\+\d{7,15}$", phone):
        return {"status": "error", "message": "Phone must start with + and country code"}
    _digits = re.sub(r"\D", "", phone)
    for a in load_accounts(u["id"]):
        if a["session_name"] == name or re.sub(r"\D", "", a.get("phone", "")) == _digits:
            return {"status": "error", "message": f"This number is already added as '{a['session_name']}'"}
    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    try:
        r = await client.send_code_request(phone)
        await asave_session(u["id"], name + "_temp", client.session.save())
        return {"status": "code_sent", "phone_code_hash": r.phone_code_hash, "session_name": name, "phone": phone}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/api/accounts/verify-code")
async def verify_code(request: Request):
    u = current_user(request)
    b = await request.json()
    name, api_id, api_hash, phone = creds(b)
    b["phone"] = phone
    tmp = await aget_session(u["id"], name + "_temp")
    client = TelegramClient(StringSession(tmp) if tmp else StringSession(), api_id, api_hash)
    await client.connect()
    try:
        await client.sign_in(phone=b["phone"], code=b["code"], phone_code_hash=b["phone_code_hash"])
        me_ = await client.get_me()
        await asave_session(u["id"], name, client.session.save()); del_session(u["id"], name + "_temp")
        save_account({"owner": u["id"], "session_name": name, "api_id": api_id, "api_hash": api_hash, "phone": b["phone"],
                      "username": me_.username or "", "name": f"{me_.first_name or ''} {me_.last_name or ''}".strip(), "created": int(time.time())})
        return {"status": "success", "message": f"Logged in as {me_.first_name}"}
    except errors.SessionPasswordNeededError:
        await asave_session(u["id"], name, client.session.save()); del_session(u["id"], name + "_temp")
        save_account({"owner": u["id"], "session_name": name, "api_id": api_id, "api_hash": api_hash, "phone": b["phone"], "username": "", "name": "pending 2FA"})
        return {"status": "2fa_needed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/api/accounts/verify-2fa")
async def verify_2fa(request: Request):
    u = current_user(request)
    b = await request.json()
    acc = next((a for a in load_accounts(u["id"]) if a["session_name"] == b["session_name"]), None)
    if not acc: return {"status": "error", "message": "Account not found"}
    client = await get_client(acc); await client.connect()
    try:
        await client.sign_in(password=b["password"])
        me_ = await client.get_me()
        await asave_session(acc["owner"], acc["session_name"], client.session.save())
        acc.update({"username": me_.username or "", "name": f"{me_.first_name or ''} {me_.last_name or ''}".strip()})
        save_account(acc)
        return {"status": "success", "message": f"Logged in as {me_.first_name}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/api/accounts/{name}/health")
async def account_health(name: str, request: Request):
    """Ping the account: alive, restricted, or dead (auth key lost / banned)."""
    u = current_user(request)
    acc = next((a for a in load_accounts(u["id"]) if a["session_name"] == name), None)
    if not acc: raise HTTPException(404, "Account not found")
    result = {"session_name": name, "status": "unknown", "detail": ""}
    async with _acc_lock(acc):
        client = await get_client(acc)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                result.update({"status": "dead", "detail": "Session expired — needs re-login"})
            else:
                me_ = await client.get_me()
                try:
                    await client.send_message("me", ".")  # harmless self-message, confirms send works
                    result.update({"status": "ok", "detail": f"Active as {me_.first_name}"})
                except errors.UserDeactivatedBanError:
                    result.update({"status": "banned", "detail": "Account deleted/banned by Telegram"})
                except errors.FloodWaitError as e:
                    result.update({"status": "limited", "detail": f"Flood-wait {e.seconds}s"})
                except Exception as e:
                    result.update({"status": "limited", "detail": str(e)[:120]})
                await asave_session(u["id"], name, client.session.save())
        except errors.AuthKeyUnregisteredError:
            result.update({"status": "dead", "detail": "Logged out from this device"})
        except errors.UserDeactivatedBanError:
            result.update({"status": "banned", "detail": "Account deleted/banned by Telegram"})
        except Exception as e:
            result.update({"status": "error", "detail": str(e)[:150]})
        finally:
            try: await client.disconnect()
            except Exception: pass
    db()["accounts"].update_one({"owner": u["id"], "session_name": name},
        {"$set": {"health": result["status"], "health_detail": result["detail"], "health_checked": int(time.time())}})
    return result

@app.post("/api/accounts/health-check-all")
async def health_check_all(request: Request):
    u = current_user(request)
    accs = load_accounts(u["id"])
    if not accs: raise HTTPException(400, "No accounts to check.")
    jid = job_new(u["id"], "health", len(accs), {})
    async def run():
        _dead = []
        for acc in accs:
            try:
                async with _acc_lock(acc):
                    client = await get_client(acc)
                    await client.connect()
                    if not await client.is_user_authorized():
                        res = {"status": "dead", "detail": "Session expired"}
                    else:
                        me_ = await client.get_me()
                        try:
                            await client.send_message("me", ".")
                            res = {"status": "ok", "detail": f"Active as {me_.first_name}"}
                        except errors.UserDeactivatedBanError:
                            res = {"status": "banned", "detail": "Banned by Telegram"}
                        except errors.FloodWaitError as e:
                            res = {"status": "limited", "detail": f"Flood-wait {e.seconds}s"}
                        except Exception as e:
                            res = {"status": "limited", "detail": str(e)[:120]}
                        await asave_session(u["id"], acc["session_name"], client.session.save())
                    await client.disconnect()
            except errors.AuthKeyUnregisteredError:
                res = {"status": "dead", "detail": "Logged out"}
            except errors.UserDeactivatedBanError:
                res = {"status": "banned", "detail": "Banned by Telegram"}
            except Exception as e:
                res = {"status": "error", "detail": str(e)[:150]}
            await asyncio.to_thread(db()["accounts"].update_one,
                {"owner": u["id"], "session_name": acc["session_name"]},
                {"$set": {"health": res["status"], "health_detail": res["detail"], "health_checked": int(time.time())}})
            if res["status"] in ("dead", "banned"):
                _dead.append(acc["session_name"])
            job_push(jid, {"account": acc["session_name"], "status": "success" if res["status"] == "ok" else "error", "msg": res["status"] + " — " + res["detail"]})
            await asyncio.sleep(1.5)
        job_finish(jid)
        alert_dead_accounts(u["id"], _dead)
    asyncio.create_task(run())
    return {"job_id": jid}

@app.post("/api/accounts/{name}/meta")
async def update_meta(name: str, request: Request):
    """Set tag (safe/new/risky/'') and/or note for an account."""
    u = current_user(request)
    b = await request.json()
    acc = next((a for a in load_accounts(u["id"]) if a["session_name"] == name), None)
    if not acc: raise HTTPException(404, "Account not found")
    upd = {}
    if "note" in b:
        upd["note"] = str(b["note"])[:500]
    if "excluded" in b:
        upd["excluded"] = bool(b["excluded"])
    if upd:
        db()["accounts"].update_one({"owner": u["id"], "session_name": name}, {"$set": upd})
    if b.get("link_finder_default"):
        # only one account can be the Link Finder default — clear it off the others
        db()["accounts"].update_many({"owner": u["id"]}, {"$unset": {"link_finder_default": ""}})
        db()["accounts"].update_one({"owner": u["id"], "session_name": name}, {"$set": {"link_finder_default": True}})
    return {"status": "success"}

@app.post("/api/accounts/export")
async def export_accounts(request: Request):
    """Build a backup file of this user's accounts+sessions and send it to them as a Telegram document."""
    u = current_user(request)
    if not BOT_TOKEN: raise HTTPException(500, "BOT_TOKEN is not set on the server.")
    accs = load_accounts(u["id"])
    if not accs: raise HTTPException(400, "No accounts to back up.")
    out = []
    for a in accs:
        sess = await aget_session(u["id"], a["session_name"])
        out.append({**{k: v for k, v in a.items() if k != "owner"}, "session_str": sess})
    payload = {"turbo_refer_backup": True, "version": 1, "exported_at": int(time.time()), "accounts": out}
    data = json.dumps(payload, indent=2).encode()
    fname = f"turbo_refer_backup_{time.strftime('%Y-%m-%d')}.json"
    ok = tg_send_document(u["id"], data, fname,
        caption=f"🔒 <b>Backup file</b> — {len(out)} account(s)\n\nKeep this safe — it contains login sessions. Use Import in the app to restore.")
    if not ok:
        raise HTTPException(502, "Couldn't send the file via the bot. Open a chat with the bot first (send /start), then try again.")
    return {"status": "success", "sent": True, "count": len(out)}

@app.post("/api/accounts/import")
async def import_accounts(request: Request):
    """Restore accounts + sessions from an exported backup JSON."""
    u = current_user(request)
    b = await request.json()
    accs = b.get("accounts") or []
    if not isinstance(accs, list) or not accs:
        raise HTTPException(400, "No accounts found in this file.")
    existing = {a["session_name"] for a in load_accounts(u["id"])}
    added, skipped = 0, 0
    for a in accs:
        try:
            name = a.get("session_name")
            if not name or name in existing:
                skipped += 1; continue
            sess = a.pop("session_str", None)
            a["owner"] = u["id"]
            save_account(a)
            if sess: save_session(u["id"], name, sess)
            existing.add(name); added += 1
        except Exception:
            skipped += 1
    return {"status": "success", "added": added, "skipped": skipped}

@app.delete("/api/accounts/{name}")
async def delete_account(name: str, request: Request):
    u = current_user(request)
    delete_account_db(u["id"], name)
    return {"status": "success"}

# ── Link Finder ──────────────────────────────────────────────────
# Sends /start to any bot with one account, reads back its reply (buttons +
# inline text links), and returns every URL found — handy for pulling all the
# "Follow Sponsor" / "Join Channel" links out of airdrop/referral bots.
_LF_SKIP_HOSTS = ("t.me/share", "t.me/premium", "telegram.org")

def _extract_all_links(messages):
    button_urls, text_urls = [], []
    for msg in messages:
        if not msg:
            continue
        if msg.buttons:
            for row in msg.buttons:
                for btn in row:
                    url = getattr(btn, "url", None)
                    if url:
                        button_urls.append(url)
        if msg.entities:
            for ent in msg.entities:
                if isinstance(ent, MessageEntityTextUrl):
                    text_urls.append(ent.url)
                elif isinstance(ent, MessageEntityUrl):
                    text_urls.append((msg.text or "")[ent.offset: ent.offset + ent.length])
    def clean(urls):
        seen, out = set(), []
        for u_ in urls:
            u_ = u_.strip()
            if not u_ or u_ in seen or any(h in u_ for h in _LF_SKIP_HOSTS):
                continue
            seen.add(u_); out.append(u_)
        return out
    return clean(button_urls), clean(text_urls)

@app.post("/api/linkfinder")
async def link_finder(request: Request):
    """Send /start to `bot` using one of this user's accounts and return every
    channel/sponsor link it replies with (from buttons and from text)."""
    u = current_user(request)
    b = await request.json()
    bot_username, _ = parse_bot_link(b["bot"]) if str(b.get("bot", "")).startswith("http") else (str(b.get("bot", "")).strip().lstrip("@"), "")
    if not bot_username:
        raise HTTPException(400, "Enter a valid bot username or t.me link.")
    accs = load_accounts(u["id"])
    if not accs:
        raise HTTPException(400, "Add at least one account first.")
    acc_name = b.get("account")
    acc = next((a for a in accs if a["session_name"] == acc_name), None) if acc_name else None
    if not acc:
        acc = next((a for a in accs if a.get("link_finder_default") and a.get("health") != "dead"), None)
    if not acc:
        acc = next((a for a in accs if a.get("health") != "dead"), accs[0])
    if acc.get("health") == "dead":
        raise HTTPException(400, f"Account '{acc['session_name']}' is dead — pick another or re-add it.")

    method = b.get("captcha", "auto")
    solver = SOLVERS.get(method) if method != "no_captcha" else None
    captcha_log, messages, replies = [], [], 0

    async with _acc_lock(acc):
        client = await get_client(acc)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                raise HTTPException(400, f"Account '{acc['session_name']}' session expired — re-add it.")
            try:
                sent = await client.send_message(bot_username, "/start")
            except Exception as e:
                raise HTTPException(400, f"Couldn't message @{bot_username}: {friendly_error(e)}")
            messages, replies = await _lf_collect(client, bot_username, sent.id, solver, captcha_log)
            if not messages:
                # nothing new with links — fall back to the latest chat history
                messages = await client.get_messages(bot_username, limit=8)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
        finally:
            try: await client.disconnect()
            except Exception: pass

    button_urls, text_urls = _extract_all_links(messages)
    all_urls = list(dict.fromkeys(button_urls + text_urls))
    return {"status": "success", "bot": bot_username, "account": acc["session_name"],
            "button_links": button_urls, "text_links": text_urls, "all_links": all_urls,
            "total": len(all_urls), "captcha": captcha_log, "replies": replies}

class _MsgEvent:
    """Minimal stand-in for a Telethon NewMessage event so the captcha solvers
    (which read event.message / .raw_text / .buttons) can run on polled messages."""
    def __init__(self, m):
        self.message = m; self.raw_text = m.raw_text; self.buttons = m.buttons

LF_MAX_WAIT   = 45   # hard cap for the whole run (seconds)
LF_SILENT_MAX = 15   # give up if the bot says nothing at all for this long
LF_SETTLE     = 4    # after the last link message, wait this long for more
LF_MAX_SOLVES = 3    # captcha attempts (a wrong answer usually brings a new captcha)

async def _lf_collect(client, bot_username, after_id, solver, captcha_log):
    """Poll the bot chat after /start. Solve captcha messages as they arrive;
    keep every message that carries links (a bot may also *edit* its captcha
    message into the sponsor list, so edits are re-checked too)."""
    loop = asyncio.get_event_loop()
    start = loop.time()
    processed, link_msgs = set(), {}
    last_link = last_reply = None
    solves = 0
    while loop.time() - start < LF_MAX_WAIT:
        try:
            batch = await client.get_messages(bot_username, min_id=after_id, limit=30)
        except Exception:
            batch = []
        for m in reversed(batch):            # oldest first
            if m.out:
                continue                      # our own /start and captcha answers
            key = (m.id, m.edit_date)
            if key in processed:
                continue
            processed.add(key)
            last_reply = loop.time()
            bu, tu = _extract_all_links([m])
            if bu or tu:
                link_msgs[m.id] = m; last_link = loop.time()
                continue
            link_msgs.pop(m.id, None)         # an edit removed its links
            if solver and solves < LF_MAX_SOLVES:
                try:
                    r = await solver(_MsgEvent(m), client, bot_username)
                    if r:
                        solves += 1; captcha_log.append(r.get("msg", "solved"))
                        last_link = None      # expect the real content next
                except Exception as e:
                    solves += 1; captcha_log.append("⚠️ " + str(e)[:80])
        now = loop.time()
        if link_msgs and last_link and now - last_link >= LF_SETTLE:
            break
        if last_reply is None and now - start >= LF_SILENT_MAX:
            break
        await asyncio.sleep(1.5)
    replies = len({k[0] for k in processed})
    return [link_msgs[k] for k in sorted(link_msgs)], replies

# ── Jobs ─────────────────────────────────────────────────────────
@app.post("/api/refer")
async def refer(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    if not accs: raise HTTPException(400, "No usable accounts — all selected accounts are dead. Re-add them first.")
    if not parse_bot_link(b.get("bot_link", ""))[0]: raise HTTPException(400, "Invalid bot link.")
    conc, delay = speed_params(b, len(accs))
    jid = job_new(u["id"], "refer", len(accs), {"link": b["bot_link"], "method": b.get("method", "no_captcha"), "speed": b.get("speed", "fast"), "concurrency": conc, "skipped_dead": skipped})
    asyncio.create_task(run_refer_job(jid, accs, b["bot_link"], b.get("method", "no_captcha"), delay, conc))
    return {"job_id": jid}

@app.post("/api/channels/auto-leave")
async def auto_leave(request: Request):
    """Leave N random channels/groups per selected account."""
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    if not accs: raise HTTPException(400, "No usable accounts — all selected accounts are dead. Re-add them first.")
    count = max(1, min(int(b.get("count", 5)), 3000))
    conc, delay = speed_params(b, len(accs))
    jid = job_new(u["id"], "auto_leave", len(accs), {"count": count, "speed": b.get("speed", "fast"), "concurrency": conc, "skipped_dead": skipped})

    async def worker(acc):
        client = await get_client(acc)
        try:
            await client.start()
            dialogs = await client.get_dialogs(limit=None)
            candidates = [dl for dl in dialogs if dl.is_channel or dl.is_group]
            random.shuffle(candidates)
            picked = candidates[:count]
            ok = 0; lines = []
            for dl in picked:
                try:
                    await client(LeaveChannelRequest(dl.entity))
                    ok += 1; lines.append(f"✓ {dl.name}")
                except Exception as e:
                    lines.append(f"✗ {dl.name}: {str(e)[:50]}")
                await asyncio.sleep(delay)
            await asave_session(u["id"], acc["session_name"], client.session.save())
            st = "success" if ok else ("error" if picked else "partial")
            msg = f"Left {ok}/{len(picked)}" if picked else "No channels/groups to leave"
            return {"account": acc["session_name"], "status": st, "msg": msg}
        finally:
            try: await client.disconnect()
            except Exception: pass
    asyncio.create_task(_run_pool(jid, accs, worker, conc, delay))
    return {"job_id": jid}

@app.post("/api/channels/random-leave")
async def random_leave_alias(request: Request):
    return await auto_leave(request)

@app.post("/api/channels")
async def channels(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    chans = [c.strip() for c in b.get("channels", []) if c.strip()]
    if not accs: raise HTTPException(400, "No usable accounts — all selected accounts are dead. Re-add them first.")
    if not chans: raise HTTPException(400, "No channels given.")
    conc, delay = speed_params(b, len(accs))
    jid = job_new(u["id"], "channels", len(accs), {"action": b.get("action", "join"), "channels": chans, "speed": b.get("speed", "fast"), "concurrency": conc, "skipped_dead": skipped})
    asyncio.create_task(run_channel_job(jid, accs, chans, b.get("action", "join"), delay, conc))
    return {"job_id": jid}

@app.post("/api/message")
async def message(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    if not accs: raise HTTPException(400, "No usable accounts — all selected accounts are dead. Re-add them first.")
    if not b.get("target") or not b.get("text"): raise HTTPException(400, "Target and message are required.")
    conc, delay = speed_params(b, len(accs))
    jid = job_new(u["id"], "message", len(accs), {"target": b["target"], "speed": b.get("speed", "fast"), "concurrency": conc, "skipped_dead": skipped})
    asyncio.create_task(run_message_job(jid, accs, b["target"], b["text"], delay, conc))
    return {"job_id": jid}

@app.get("/api/jobs/{jid}")
async def job(jid: str, request: Request):
    u = current_user(request)
    j = JOBS.get(jid) or db()["jobs"].find_one({"id": jid}, {"_id": 0})
    if not j: raise HTTPException(404, "Job not found (server may have restarted).")
    if j.get("owner") != u["id"] and u["role"] != "owner": raise HTTPException(403, "Not your job.")
    return j

@app.post("/api/jobs/{jid}/cancel")
async def cancel_job(jid: str, request: Request):
    u = current_user(request)
    j = JOBS.get(jid)
    if not j: raise HTTPException(404, "Job not found or already finished.")
    if j.get("owner") != u["id"] and u["role"] != "owner": raise HTTPException(403, "Not your job.")
    if j["status"] != "running": return {"status": "already_finished"}
    j["cancel"] = True
    return {"status": "cancelling"}

@app.get("/api/health-summary")
async def health_summary(request: Request):
    """Small card for Home: how many accounts are ok / need attention."""
    u = current_user(request)
    accs = load_accounts(u["id"])
    counts = {"ok": 0, "limited": 0, "dead": 0, "banned": 0, "unknown": 0, "error": 0}
    for a in accs:
        counts[a.get("health", "unknown")] = counts.get(a.get("health", "unknown"), 0) + 1
    needs = counts["dead"] + counts["banned"]
    last = max([a.get("health_checked") or 0 for a in accs], default=0)
    return {"total": len(accs), "counts": counts, "needs_attention": needs, "last_checked": last or None}

@app.get("/api/recent-links")
async def recent_links(request: Request):
    """Referral links this user has run before, newest first."""
    u = current_user(request)
    seen, out = set(), []
    cur = db()["jobs"].find({"owner": u["id"], "kind": "refer"}, {"_id": 0, "meta": 1, "ended": 1}).sort("ended", -1).limit(40)
    for j in cur:
        link = (j.get("meta") or {}).get("link")
        if link and link not in seen:
            seen.add(link); out.append(link)
        if len(out) >= 8: break
    return {"links": out}

@app.get("/api/jobs")
async def jobs(request: Request):
    u = current_user(request)
    live = sorted([j for j in JOBS.values() if j.get("owner") == u["id"]], key=lambda x: -x["started"])[:10]
    return {"jobs": [{k: v for k, v in j.items() if k != "results"} for j in live]}

# ── Analytics ────────────────────────────────────────────────────
@app.get("/api/stats")
async def stats(request: Request):
    u = current_user(request)
    owner = u["id"]
    d = db()
    now = int(time.time()); day = 86400
    since30 = now - 30 * day
    q = {"owner": owner, "ended": {"$gt": since30}}
    all_jobs = list(d["jobs"].find(q, {"_id": 0, "results": 0})) + \
               [j for j in JOBS.values() if j.get("owner") == owner and j.get("started", 0) > since30]
    seen = set(); jobs = []
    for j in all_jobs:
        if j["id"] in seen: continue
        seen.add(j["id"]); jobs.append(j)

    by_day = {}
    for j in jobs:
        ts = j.get("ended") or j.get("started", now)
        key = time.strftime("%Y-%m-%d", time.gmtime(ts))
        b = by_day.setdefault(key, {"date": key, "success": 0, "failed": 0, "jobs": 0})
        b["success"] += j.get("success", 0); b["failed"] += j.get("failed", 0); b["jobs"] += 1
    days = [by_day.get(time.strftime("%Y-%m-%d", time.gmtime(now - i * day)), {"date": time.strftime("%Y-%m-%d", time.gmtime(now - i * day)), "success": 0, "failed": 0, "jobs": 0}) for i in range(13, -1, -1)]

    by_kind = {}
    for j in jobs:
        k = j.get("kind", "?")
        b = by_kind.setdefault(k, {"kind": k, "success": 0, "failed": 0, "jobs": 0})
        b["success"] += j.get("success", 0); b["failed"] += j.get("failed", 0); b["jobs"] += 1

    acc_stat = {}
    for j in jobs:
        for r in (j.get("results") or db()["jobs"].find_one({"id": j["id"]}, {"results": 1}) or {}).get("results", []) if not j.get("results") else j.get("results", []):
            pass
    per_acc = {}
    full_jobs = list(d["jobs"].find(q, {"_id": 0})) + [j for j in JOBS.values() if j.get("owner") == owner and j.get("started", 0) > since30]
    fseen = set()
    for j in full_jobs:
        if j["id"] in fseen: continue
        fseen.add(j["id"])
        for r in j.get("results", []):
            a = per_acc.setdefault(r["account"], {"account": r["account"], "success": 0, "failed": 0})
            if r.get("status") == "success": a["success"] += 1
            else: a["failed"] += 1
    top_accounts = sorted(per_acc.values(), key=lambda x: -(x["success"] + x["failed"]))[:10]

    total_success = sum(j.get("success", 0) for j in jobs); total_failed = sum(j.get("failed", 0) for j in jobs)
    recent_jobs = sorted(jobs, key=lambda j: -(j.get("ended") or j.get("started", 0)))[:20]
    recent_jobs = [{"id": j["id"], "kind": j.get("kind"), "status": j.get("status"),
                     "success": j.get("success", 0), "failed": j.get("failed", 0), "total": j.get("total", 0),
                     "ended": j.get("ended") or j.get("started"), "meta": j.get("meta", {})} for j in recent_jobs]

    # Speed history: accounts/sec for each completed job with a real duration, oldest→newest.
    speed_history = []
    for j in sorted(jobs, key=lambda j: j.get("ended") or j.get("started", 0)):
        started = j.get("started"); ended = j.get("ended")
        if not started or not ended or ended <= started or not j.get("total"):
            continue
        rate = round(j["total"] / (ended - started), 2)
        speed_history.append({"ended": ended, "rate": rate, "kind": j.get("kind"),
                               "speed_mode": j.get("meta", {}).get("speed", "single")})
    speed_history = speed_history[-30:]  # last 30 timed jobs

    # Time saved: for every job that ran faster than "single" (1 account at a time,
    # ~1.5s each), estimate how much longer it would have taken at that baseline pace
    # and sum the difference. Rough, but gives a genuinely meaningful number.
    SINGLE_BASELINE_SEC_PER_ACCOUNT = 1.5
    time_saved_sec = 0
    for j in jobs:
        started = j.get("started"); ended = j.get("ended")
        mode = j.get("meta", {}).get("speed", "single")
        if not started or not ended or ended <= started or mode == "single" or not j.get("total"):
            continue
        actual = ended - started
        baseline = j["total"] * SINGLE_BASELINE_SEC_PER_ACCOUNT
        if baseline > actual:
            time_saved_sec += (baseline - actual)

    return {
        "totals": {"jobs": len(jobs), "success": total_success, "failed": total_failed,
                   "accounts": len(load_accounts(owner))},
        "daily": days, "by_kind": list(by_kind.values()), "top_accounts": top_accounts,
        "recent_jobs": recent_jobs, "speed_history": speed_history, "time_saved_sec": round(time_saved_sec),
    }

# ── Admin panel (owner only) ─────────────────────────────────────
def tg_send_document(chat_id, file_bytes, filename, caption=""):
    try:
        boundary = uuid.uuid4().hex
        parts = []
        def field(name, value):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        field("chat_id", chat_id)
        if caption: field("caption", caption); field("parse_mode", "HTML")
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'.encode())
        parts.append(file_bytes)
        parts.append(f'\r\n--{boundary}--\r\n'.encode())
        body = b"".join(parts)
        req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()).get("ok", False)
    except Exception as e:
        print("tg_send_document error:", e); return False

def tg_send(chat_id, text):
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10); return True
    except Exception: return False

@app.get("/api/admin/overview")
async def admin_overview(request: Request):
    require_owner(request)
    d = db()
    wl, bl = set(user_list("whitelist")), set(user_list("banlist"))
    acc_counts = {}
    for a in d["accounts"].find({}, {"_id": 0, "owner": 1}):
        acc_counts[a.get("owner", "")] = acc_counts.get(a.get("owner", ""), 0) + 1
    users = []
    for x in d["users"].find({}, {"_id": 0}).sort("last_seen", -1):
        uid = x["user_id"]
        status = "owner" if is_owner(uid) else "banned" if uid in bl else "approved" if uid in wl else "pending"
        users.append({**x, "status": status, "accounts": acc_counts.get(uid, 0)})
    day_ago = int(time.time()) - 86400
    return {
        "access_mode": setting_get("access_mode", "approved"),
        "stats": {"users": len(users), "approved": len(wl), "banned": len(bl),
                  "accounts": sum(acc_counts.values()),
                  "jobs_24h": d["jobs"].count_documents({"started": {"$gt": day_ago}}) + len([j for j in JOBS.values() if j["status"] == "running"]),
                  "active_24h": d["users"].count_documents({"last_seen": {"$gt": day_ago}})},
        "users": users,
    }

@app.post("/api/admin/settings")
async def admin_settings(request: Request):
    require_owner(request)
    b = await request.json()
    if b.get("access_mode") in ("approved", "open"):
        setting_set("access_mode", b["access_mode"])
    if "lockdown" in b:
        setting_set("lockdown", bool(b["lockdown"]))
        if b.get("lockdown_msg"): setting_set("lockdown_msg", str(b["lockdown_msg"])[:200])
    if "log_channel" in b:
        setting_set("log_channel", str(b["log_channel"]).strip())
    return {"status": "success", "access_mode": setting_get("access_mode"),
            "lockdown": setting_get("lockdown", False), "log_channel": setting_get("log_channel", "")}

@app.get("/api/admin/settings")
async def get_admin_settings(request: Request):
    require_owner(request)
    return {"access_mode": setting_get("access_mode", "approved"), "lockdown": setting_get("lockdown", False),
            "lockdown_msg": setting_get("lockdown_msg", ""), "log_channel": setting_get("log_channel", "")}

@app.get("/api/admin/system-stats")
async def system_stats(request: Request):
    """Platform-wide numbers across every user, for the owner's eyes only."""
    require_owner(request)
    d = db()
    total_accounts = await asyncio.to_thread(d["accounts"].count_documents, {})
    total_users = await asyncio.to_thread(d["users"].count_documents, {})
    day_ago = int(time.time()) - 86400
    jobs_24h = await asyncio.to_thread(d["jobs"].count_documents, {"started": {"$gt": day_ago}})
    jobs_24h += len([j for j in JOBS.values() if j.get("started", 0) > day_ago])
    total_jobs = await asyncio.to_thread(d["jobs"].estimated_document_count)
    agg = list(d["jobs"].aggregate([{"$group": {"_id": None, "s": {"$sum": "$success"}, "f": {"$sum": "$failed"}}}]))
    ok = agg[0]["s"] if agg else 0; bad = agg[0]["f"] if agg else 0
    for j in JOBS.values(): ok += j.get("success", 0); bad += j.get("failed", 0)
    return {"total_users": total_users, "total_accounts": total_accounts, "total_jobs": total_jobs,
            "jobs_24h": jobs_24h, "total_success": ok, "total_failed": bad,
            "owners": len(OWNER_IDS), "approved": len(user_list("whitelist")), "banned": len(user_list("banlist"))}

@app.get("/api/admin/activity")
async def admin_activity(request: Request):
    """Live feed of what every user has been doing recently."""
    require_owner(request)
    d = db()
    users = {x["user_id"]: x for x in d["users"].find({}, {"_id": 0})}
    def who(uid):
        x = users.get(str(uid), {})
        return x.get("name") or ("@" + x["username"] if x.get("username") else str(uid))
    items = []
    for j in JOBS.values():
        if j.get("status") == "running":
            items.append({"type": "job", "kind": j["kind"], "user": who(j.get("owner")), "user_id": j.get("owner"),
                          "status": "running", "success": j["success"], "failed": j["failed"], "total": j["total"],
                          "ts": j.get("started", 0), "job_id": j["id"]})
    for j in d["jobs"].find({}, {"_id": 0, "results": 0}).sort("ended", -1).limit(40):
        items.append({"type": "job", "kind": j.get("kind"), "user": who(j.get("owner")), "user_id": j.get("owner"),
                      "status": j.get("status"), "success": j.get("success", 0), "failed": j.get("failed", 0),
                      "total": j.get("total", 0), "ts": j.get("ended") or j.get("started", 0), "job_id": j.get("id")})
    for x in users.values():
        if x.get("requested_at"):
            items.append({"type": "request", "user": who(x["user_id"]), "user_id": x["user_id"], "ts": x["requested_at"]})
        if x.get("first_seen"):
            items.append({"type": "joined", "user": who(x["user_id"]), "user_id": x["user_id"], "ts": x["first_seen"]})
    items.sort(key=lambda i: -(i.get("ts") or 0))
    return {"items": items[:50]}

@app.get("/api/admin/rate-limit")
async def rate_limit_dashboard(request: Request):
    """Simple activity gauge: how many Telegram actions this server has made recently."""
    require_owner(request)
    return api_call_rate()

@app.get("/api/admin/server-health")
async def server_health(request: Request):
    """MongoDB connectivity + rough storage usage, and Telegram Bot API reachability."""
    require_owner(request)
    mongo_ok = False; storage_mb = None; storage_pct = None
    try:
        stats = await asyncio.to_thread(lambda: db().command("dbStats"))
        mongo_ok = True
        storage_mb = round((stats.get("dataSize", 0) + stats.get("indexSize", 0)) / (1024 * 1024), 2)
        storage_pct = round(min(100, storage_mb / 512 * 100), 1)  # Atlas free tier = 512MB
    except Exception as e:
        print("server_health mongo error:", e)
    bot_ok = False
    try:
        if BOT_TOKEN:
            req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe")
            with urllib.request.urlopen(req, timeout=8) as r:
                bot_ok = json.loads(r.read()).get("ok", False)
    except Exception as e:
        print("server_health bot error:", e)
    active_jobs = len([j for j in JOBS.values() if j.get("status") == "running"])
    return {"mongo_ok": mongo_ok, "storage_mb": storage_mb, "storage_pct": storage_pct,
            "bot_ok": bot_ok, "active_jobs": active_jobs, "render_alive": True,
            "checked_at": int(time.time())}

@app.post("/api/admin/user/{uid}/{action}")
async def admin_user_action(uid: str, action: str, request: Request):
    require_owner(request)
    if not uid.isdigit(): raise HTTPException(400, "User ID must be numbers only.")
    if is_owner(uid): raise HTTPException(400, "Owners can't be changed here.")
    if action == "approve":
        user_add("whitelist", uid); user_remove("banlist", uid)
        tg_send(uid, "✅ <b>Access granted!</b>\nYou can now open Turbo Refer. Send /start to the bot.")
    elif action == "ban":
        user_add("banlist", uid); user_remove("whitelist", uid)
    elif action == "unban":
        user_remove("banlist", uid)
    elif action == "revoke":
        user_remove("whitelist", uid)
    elif action == "wipe":   # delete that user's accounts + sessions
        db()["accounts"].delete_many({"owner": uid}); db()["sessions"].delete_many({"owner": uid})
    else:
        raise HTTPException(404, "Unknown action.")
    return {"status": "success"}

@app.get("/api/admin/user/{uid}/accounts")
async def admin_user_accounts(uid: str, request: Request):
    require_owner(request)
    return {"accounts": [{"session_name": a["session_name"], "name": a.get("name", ""), "username": a.get("username", ""), "phone": a.get("phone", "")}
                         for a in load_accounts(uid)]}

@app.post("/api/admin/broadcast")
async def admin_broadcast(request: Request):
    require_owner(request)
    b = await request.json(); text = (b.get("text") or "").strip()
    if not text: raise HTTPException(400, "Message is empty.")
    target = b.get("to", "all")   # all | approved
    ids = user_list("whitelist") if target == "approved" else [x["user_id"] for x in db()["users"].find({}, {"_id": 0, "user_id": 1})]
    bl = set(user_list("banlist")); sent = 0
    for uid in ids:
        if uid in bl: continue
        if tg_send(uid, text): sent += 1
    return {"status": "success", "sent": sent, "total": len(ids)}

async def storage_watch():
    """Every 6h: if MongoDB is 80%+ full, alert all owners (max once per day)."""
    while True:
        try:
            st = await asyncio.to_thread(lambda: db().command("dbStats"))
            mb = (st.get("dataSize", 0) + st.get("indexSize", 0)) / (1024 * 1024)
            pct = mb / 512 * 100
            last = setting_get("storage_alert_at", 0) or 0
            if pct >= 80 and time.time() - last > 86400:
                setting_set("storage_alert_at", int(time.time()))
                for oid in OWNER_IDS:
                    tg_send(oid, f"⚠️ <b>Database almost full</b>\n\n💾 {mb:.1f} MB of 512 MB used ({pct:.0f}%)\n\nDelete unused accounts or old data soon, or the app will stop saving.")
        except Exception as e:
            print("storage_watch:", e)
        await asyncio.sleep(6 * 3600)

@app.on_event("startup")
async def _startup():
    migrate()
    asyncio.create_task(storage_watch())

# ── Run ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
