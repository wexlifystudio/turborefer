"""
Turbo Refer V2 — Mini App Backend
FastAPI + Telethon + MongoDB + Telegram WebApp auth
"""

import os, re, hmac, json, time, uuid, asyncio, hashlib, random, base64, threading, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl

import emoji as emoji_lib
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest
from telethon.tl.functions.messages import ImportChatInviteRequest, CheckChatInviteRequest
from telethon.tl.functions.account import UpdateNotifySettingsRequest
from telethon.tl.types import (ChatInviteAlready, ChatInvitePeek, MessageEntityTextUrl, MessageEntityUrl,
                               InputNotifyPeer, InputPeerNotifySettings)
from pymongo import MongoClient, UpdateOne
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
        _mongo = MongoClient(MONGO_URL, server_api=ServerApi("1"), maxPoolSize=60,
                             serverSelectionTimeoutMS=8000, connectTimeoutMS=8000, socketTimeoutMS=20000)
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

# ── Auth cache ───────────────────────────────────────────────────
# current_user() runs on EVERY API call (job polling included). Without a cache it did
# ~5 MongoDB round-trips each time, directly on the event loop — with many users online
# the whole server (and every running job) stalled. Ban/whitelist/lockdown lookups are
# now cached for a few seconds and invalidated the moment an admin changes them.
_AUTH_TTL = 15
_AUTH_CACHE = {}
def _auth_invalidate():
    _AUTH_CACHE.clear()

def cached_user_set(kind):
    now = time.time(); hit = _AUTH_CACHE.get(kind)
    if hit and now - hit[0] < _AUTH_TTL: return hit[1]
    val = set(user_list(kind)); _AUTH_CACHE[kind] = (now, val); return val

def cached_setting(key, default=None):
    now = time.time(); ck = "s:" + key; hit = _AUTH_CACHE.get(ck)
    if hit and now - hit[0] < _AUTH_TTL: return hit[1]
    val = setting_get(key, default); _AUTH_CACHE[ck] = (now, val); return val

_TOUCHED = {}
def touch_user_async(user):
    """last_seen only needs to be roughly right: write it at most once a minute per
    user, and from a background thread so it never blocks a request."""
    uid = str(user.get("id")); now = time.time()
    if now - _TOUCHED.get(uid, 0) < 60: return
    _TOUCHED[uid] = now
    def _w():
        try: touch_user(user)
        except Exception: pass
    threading.Thread(target=_w, daemon=True).start()

def user_add(kind, uid, meta=None):
    doc = {"user_id": str(uid), "added_at": int(time.time())}
    if meta: doc.update(meta)
    db()[kind].update_one({"user_id": str(uid)}, {"$set": doc}, upsert=True)
    _auth_invalidate()

def user_remove(kind, uid):
    db()[kind].delete_one({"user_id": str(uid)})
    _auth_invalidate()

def setting_get(key, default=None):
    d = db()["settings"].find_one({"key": key})
    return d["value"] if d else default

def setting_set(key, value):
    db()["settings"].update_one({"key": key}, {"$set": {"key": key, "value": value}}, upsert=True)
    _auth_invalidate()

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
    touch_user_async(user)
    if uid in cached_user_set("banlist"):
        raise HTTPException(403, "You are banned.")
    if is_owner(uid):
        return {"id": uid, "name": name, "role": "owner", "username": user.get("username", "")}
    if cached_setting("lockdown", False) and not is_owner(uid):
        raise HTTPException(423, cached_setting("lockdown_msg") or "The app is temporarily down for maintenance. Please try again soon.")
    if cached_setting("access_mode", "approved") == "open" or uid in cached_user_set("whitelist"):
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

# ── Smart Alerts ─────────────────────────────────────────────────
# Per-user Telegram notifications. Each kind can be switched off in Settings, and
# every kind except job_done has a cooldown so a bad run can't spam the chat.
ALERT_KINDS = ("job_done", "dead_account", "captcha_fail", "flood", "resumed", "low_health")
_ALERT_LAST = {}
_ALERT_PREF_CACHE = {}

def alert_prefs(owner):
    now = time.time(); hit = _ALERT_PREF_CACHE.get(str(owner))
    if hit and now - hit[0] < 30: return hit[1]
    prefs = {k: True for k in ALERT_KINDS}
    try:
        d = db()["alert_prefs"].find_one({"owner": str(owner)}) or {}
        for k in ALERT_KINDS:
            if k in d: prefs[k] = bool(d[k])
    except Exception as e:
        print("alert prefs:", e)
    _ALERT_PREF_CACHE[str(owner)] = (now, prefs)
    return prefs

def alert_sync(owner, kind, text, cooldown=0):
    """Send one alert if the user wants this kind and it isn't in cooldown."""
    if not owner: return False
    if not alert_prefs(owner).get(kind, True): return False
    key = (str(owner), kind); now = time.time()
    if cooldown and now - _ALERT_LAST.get(key, 0) < cooldown: return False
    ok = tg_send(owner, text)
    if ok: _ALERT_LAST[key] = now
    return ok

_BG_TASKS = set()
def _bg(coro):
    """Fire-and-forget background task (kept referenced so it isn't garbage-collected)."""
    t = asyncio.ensure_future(coro); _BG_TASKS.add(t); t.add_done_callback(_BG_TASKS.discard); return t

async def alert_async(owner, kind, text, cooldown=0):
    try: return await asyncio.to_thread(alert_sync, owner, kind, text, cooldown)
    except Exception as e: print("alert error:", e); return False

def alert_dead_accounts(owner, dead_names):
    if not dead_names: return
    try:
        lines = ["<b>Account problem detected</b>", "",
                 f"{len(dead_names)} account(s) need to be re-added:"]
        for n in dead_names[:10]:
            lines.append(f"• <code>{n}</code>")
        if len(dead_names) > 10: lines.append(f"…and {len(dead_names) - 10} more")
        lines.append("\nOpen the app → Accounts → delete and add them again.")
        alert_sync(owner, "dead_account", "\n".join(lines), cooldown=300)
    except Exception as e:
        print("dead alert error:", e)

# ── Account Health Score ─────────────────────────────────────────
# 0–100 per account from: Telegram health check result, success rate and
# consecutive failures over recent runs, recent flood-waits, and check age.
def health_score(a, now=None):
    """Returns (score, grade, reasons). grade: good ≥80 · fair ≥55 · weak <55 · dead."""
    now = now or time.time()
    h = a.get("health", "unknown")
    if h in ("dead", "banned"):
        return 0, "dead", ["Session dead" if h == "dead" else "Banned by Telegram"]
    sc = 100; why = []
    ok, fail = int(a.get("st_ok") or 0), int(a.get("st_fail") or 0)
    n = ok + fail
    if n >= 3:
        pen = int((fail / n) * 40)
        if pen: sc -= pen; why.append(f"{ok} ok / {fail} failed")
    elif n and fail:
        sc -= int(fail / n * 15); why.append(f"{ok} ok / {fail} failed")
    consec = int(a.get("st_consec") or 0)
    if consec:
        sc -= min(consec, 5) * 6; why.append(f"{consec} failed in a row")
    if h == "limited": sc -= 20; why.append("Telegram limits this account")
    elif h == "error": sc -= 15; why.append("Last health check errored")
    elif h == "unknown": sc -= 5
    fl = a.get("st_flood_at")
    if fl:
        age = now - fl
        if age < 3600: sc -= 20; why.append("flood-wait in the last hour")
        elif age < 86400: sc -= 10; why.append("flood-wait today")
    hc = a.get("health_checked")
    if hc and now - hc > 7 * 86400: sc -= 5; why.append("health not checked for 7+ days")
    sc = max(0, min(100, sc))
    return sc, ("good" if sc >= 80 else "fair" if sc >= 55 else "weak"), why

def filter_weak(accs, min_score):
    """Drop accounts scoring below min_score. Returns (kept, weak_names)."""
    try: ms = int(min_score or 0)
    except Exception: ms = 0
    if ms <= 0: return accs, []
    kept, weak = [], []
    for a in accs:
        (kept if health_score(a)[0] >= ms else weak).append(a)
    return kept, [a["session_name"] for a in weak]

_DEAD_RE   = re.compile(r"Session expired|needs re-login|AuthKeyUnregistered|AuthKeyDuplicated|AuthKeyInvalid|SessionRevoked|SessionExpired|UserDeactivated|PhoneNumberBanned|is corrupted|Logged out from this device", re.I)
_BANNED_RE = re.compile(r"UserDeactivated|PhoneNumberBanned|banned|deactivated", re.I)
_FLOOD_RE  = re.compile(r"flood[- ]?wait|A wait of \d+|auto-retried after", re.I)

def _dead_kind(msg):
    if not _DEAD_RE.search(msg or ""): return None
    return "banned" if _BANNED_RE.search(msg or "") else "dead"

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

def pick_accounts(owner, names, skip_dead=True, exclude=None, allow_reserved=False):
    accs = load_accounts(owner)
    sel = [a for a in accs if not a.get("excluded")] if not names else [a for a in accs if a["session_name"] in names]
    # The Link Finder default account is reserved for that job only — never let
    # it run Referral / Join-Leave / Message, even if it was explicitly picked.
    # (Harmless housekeeping like muting passes allow_reserved=True.)
    if not allow_reserved:
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
JOB_SPECS = {}          # jid → how to re-create the run (account names + settings) so it can resume
_JOB_DIRTY = set()      # jobs changed since the last save to MongoDB
INSTANCE_ID = uuid.uuid4().hex[:8]   # identifies this server process
RESUME_LEASE_S = 15     # a saved job whose heartbeat is older than this has lost its server
JOB_PERSIST_EVERY = 3

def _evict_old_jobs():
    """Finished jobs stay in RAM only for 1h (they're saved in MongoDB anyway)."""
    cut = time.time() - 3600
    for k in [k for k, j in JOBS.items() if j.get("ended") and j["ended"] < cut]:
        JOBS.pop(k, None)

def job_new(owner, kind, total, meta=None, spec=None):
    _evict_old_jobs()
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"id": jid, "owner": str(owner), "kind": kind, "status": "running", "total": total,
                 "done": 0, "success": 0, "failed": 0, "results": [],
                 "meta": meta or {}, "started": int(time.time())}
    if spec: JOB_SPECS[jid] = spec
    _JOB_DIRTY.add(jid)
    return jid

def job_push(jid, r):
    j = JOBS[jid]; j["results"].append(r); j["done"] += 1
    if r.get("status") == "success": j["success"] += 1
    else: j["failed"] += 1
    _JOB_DIRTY.add(jid)

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
              "health": "Health check", "auto_leave": "Auto-leave", "mute": "Mute channels"}

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

def job_finish(jid, status=None):
    j = JOBS[jid]
    j["status"] = status or ("cancelled" if j.get("cancel") else "done")
    j["ended"] = int(time.time())
    milestone, streak = update_progress(j.get("owner"), j.get("success", 0))
    j["milestone"] = milestone
    j["streak"] = streak
    try: db()["jobs"].insert_one(dict(j))
    except Exception: pass
    JOB_SPECS.pop(jid, None); _JOB_DIRTY.discard(jid)
    try: db()["jobs_live"].delete_one({"id": jid})      # no longer needs resuming
    except Exception: pass
    # Notify the owner of this job in Telegram
    try:
        if j["total"] >= 1 and j.get("owner"):
            label = KIND_LABEL.get(j["kind"], j["kind"])
            icon = "[STOPPED]" if j["status"] == "cancelled" else "[INTERRUPTED]" if j["status"] == "interrupted" else ("[DONE]" if not j["failed"] else ("[PARTIAL]" if j["success"] else "[FAILED]"))
            took = j["ended"] - j.get("started", j["ended"])
            lines = [f"{icon} <b>{label} {j['status']}</b>",
                     f"{j['success']} ok · {j['failed']} failed · {j['total']} total",
                     f"Time: {took}s"]
            if j["meta"].get("skipped_dead"):
                lines.append(f"Skipped {len(j['meta']['skipped_dead'])} dead account(s)")
            if milestone:
                lines.append(f"\n<b>Milestone unlocked: {milestone:,} lifetime successful runs!</b>")
            bad = [r for r in j.get("results", []) if r.get("status") != "success"][:5]
            if bad:
                lines.append("\n<b>Failed:</b>")
                for r in bad:
                    lines.append(f"• <code>{r['account']}</code> — {str(r.get('msg',''))[:70]}")
            alert_sync(j["owner"], "job_done", "\n".join(lines))
            log_chan = setting_get("log_channel", "")
            if log_chan:
                tg_send(log_chan, "\n".join(lines))
    except Exception as e:
        print("job alert error:", e)

# ── Persistent Job Queue ─────────────────────────────────────────
# Running jobs are saved to MongoDB every few seconds ("jobs_live") with a heartbeat.
# If the server restarts or crashes, the next start finds jobs whose heartbeat went
# stale, claims them (atomically, so two servers never resume the same job) and
# continues with only the accounts that had not finished yet.
def _persist_jobs_sync():
    now = int(time.time()); col = db()["jobs_live"]
    for jid, j in list(JOBS.items()):
        if j.get("status") != "running": continue
        if jid in _JOB_DIRTY:
            _JOB_DIRTY.discard(jid)
            doc = {k: j[k] for k in ("id", "owner", "kind", "status", "total", "done", "success", "failed", "meta", "started") if k in j}
            doc.update({"results": list(j.get("results", [])), "spec": JOB_SPECS.get(jid), "cancel": bool(j.get("cancel")),
                        "heartbeat": now, "instance": INSTANCE_ID})
            if j.get("status") != "running": continue
            col.update_one({"id": jid}, {"$set": doc}, upsert=True)
        else:
            col.update_one({"id": jid, "instance": INSTANCE_ID}, {"$set": {"heartbeat": now, "cancel": bool(j.get("cancel"))}})

async def job_persist_loop():
    while True:
        try: await asyncio.to_thread(_persist_jobs_sync)
        except Exception as e: print("job persist:", e)
        await asyncio.sleep(JOB_PERSIST_EVERY)

def _claim_stale_jobs_sync():
    now = int(time.time()); out = []; col = db()["jobs_live"]
    for d in list(col.find({"status": "running", "heartbeat": {"$lt": now - RESUME_LEASE_S}}, {"_id": 0})):
        if d["id"] in JOBS: continue
        if db()["jobs"].find_one({"id": d["id"]}, {"_id": 1}):      # it did finish; just a leftover copy
            col.delete_one({"id": d["id"]}); continue
        got = col.find_one_and_update({"id": d["id"], "heartbeat": d["heartbeat"]},
                                      {"$set": {"instance": INSTANCE_ID, "heartbeat": now}})
        if got: out.append(d)
    return out

async def _resume_runner(jid, runner, accs, spec):
    try:
        if accs: await runner(jid, accs, spec)
        else: await asyncio.to_thread(job_finish, jid)
    except Exception as e:
        print("resume runner error:", e)
        try:
            job_push(jid, {"account": "-", "status": "error", "msg": "Resume failed: " + str(e)[:80]})
            await asyncio.to_thread(job_finish, jid)
        except Exception: pass

async def _resume_job(d):
    jid, owner = d["id"], d["owner"]; spec = d.get("spec") or {}
    j = {k: v for k, v in d.items() if k not in ("spec", "heartbeat", "instance")}
    j["status"] = "running"; j.setdefault("results", []); j["meta"] = dict(j.get("meta") or {})
    j["meta"]["resumed"] = int(j["meta"].get("resumed", 0)) + 1
    JOBS[jid] = j
    runner = JOB_RUNNERS.get(j["kind"])
    if j.get("cancel"):
        await asyncio.to_thread(job_finish, jid); return
    if not runner or not spec.get("accounts"):
        j["meta"]["interrupted"] = True
        await asyncio.to_thread(job_finish, jid, "interrupted"); return
    JOB_SPECS[jid] = spec
    done = {r.get("account") for r in j["results"]}
    by_name = {a["session_name"]: a for a in await asyncio.to_thread(load_accounts, owner)}
    todo = [n for n in spec["accounts"] if n not in done]
    for n in todo:
        if n not in by_name: job_push(jid, {"account": n, "status": "error", "msg": "Account no longer exists"})
    accs = [by_name[n] for n in todo if n in by_name]
    _JOB_DIRTY.add(jid)
    _bg(alert_async(owner, "resumed",
        f"<b>Run resumed after a server restart</b>\n{len(done)} of {j['total']} accounts were already done; continuing with the remaining {len(accs)}.", cooldown=60))
    _bg(_resume_runner(jid, runner, accs, spec))

async def job_resume_loop():
    await asyncio.sleep(4)
    while True:
        try:
            for d in await asyncio.to_thread(_claim_stale_jobs_sync):
                await _resume_job(d)
        except Exception as e:
            print("job resume:", e)
        await asyncio.sleep(10)

# ── Referral workers ─────────────────────────────────────────────
# After an answer is sent, the bot's next reply tells us if it was accepted.
_CAPTCHA_BAD  = re.compile(r"wrong|incorrect|invalid|failed|not correct|try again|mismatch|❌", re.I)
_CAPTCHA_GOOD = re.compile(r"success|verified|correct|passed|✅|welcome|thank", re.I)
CAPTCHA_MAX_TRIES = 3

_ASKS_SOMETHING = re.compile(r"select|choose|pick|click|tap|press|enter|type|solve|captcha|code", re.I)

def _note_bot_msg(state, event):
    """Remember the bot's latest message so a timeout can say what the bot actually sent."""
    t = (getattr(event, "raw_text", "") or "").replace("\n", " ").strip()
    m = getattr(event, "message", None)
    if not t and m is not None and (getattr(m, "photo", None) or getattr(m, "document", None)): t = "[image]"
    if t: state["last"] = t[:90]

def _bot_hint(state):
    return f" · bot said: “{state['last']}”" if state.get("last") else " · bot sent nothing"

async def _captcha_flow(acc, bot_link, solver):
    client = await get_client(acc)
    wait_s = getattr(solver, "timeout", 20)
    result = {"account": acc["session_name"], "status": "timeout", "msg": f"No captcha response in {wait_s}s"}
    state = {"answered": False, "wrong": 0, "last": "", "solving": 0, "early_good": False, "early_bad": 0, "answers": 0}
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        answered = asyncio.Event()   # solver sent/clicked an answer
        done = asyncio.Event()       # bot confirmed (or we gave up after too many wrong answers)

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                _note_bot_msg(state, event)
                t = event.raw_text or ""
                if state["solving"]:
                    # our click/answer is still in flight and the bot has already replied (this happens
                    # often): keep its verdict instead of losing it and then waiting for a message that never comes
                    if _CAPTCHA_BAD.search(t): state["early_bad"] += 1
                    elif _CAPTCHA_GOOD.search(t) and not _ASKS_SOMETHING.search(t):
                        state["early_good"] = True; return
                if state["answered"]:
                    if _CAPTCHA_BAD.search(t):
                        state["wrong"] += 1; state["answered"] = False
                        result.update({"status": "error", "msg": f"Bot rejected answer ({state['wrong']}x)"})
                        if state["wrong"] >= CAPTCHA_MAX_TRIES:
                            done.set(); return
                        # fall through — this same message may carry a fresh captcha
                    elif _CAPTCHA_GOOD.search(t):
                        result["status"] = "success"; result["msg"] += " · verified"
                        done.set(); return
                    else:
                        return
                state["solving"] += 1; n0 = state["answers"]
                try: r = await solver(event, client, bot_user)
                finally: state["solving"] -= 1
                if r:
                    state["answers"] += 1
                    r.setdefault("solver", _solver_label(solver, r))
                    result.update(r)
                    if state["early_good"]:
                        state["early_good"] = False; state["early_bad"] = 0; state["answered"] = True
                        result["status"] = "success"; result["msg"] += " · verified"
                        answered.set(); done.set(); return
                    if state["early_bad"]:
                        state["wrong"] += state["early_bad"]; state["early_bad"] = 0
                        if state["answers"] == n0 + 1:     # no newer answer to a fresh captcha in the meantime
                            state["answered"] = False
                            result.update({"status": "error", "msg": f"Bot rejected answer ({state['wrong']}x)"})
                            if state["wrong"] >= CAPTCHA_MAX_TRIES: done.set()
                        answered.set(); return
                    state["answered"] = True; answered.set()
                elif not state["solving"]:
                    state["early_good"] = False; state["early_bad"] = 0
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
    if result.get("status") == "timeout" or str(result.get("msg", "")).startswith("Bot rejected"):
        result["msg"] = str(result["msg"]) + _bot_hint(state)
    return result

async def solve_none(event, client, bot_user):
    return {"status": "success", "msg": "Started"}

# "Select this emoji: ₿" — the target may be a plain symbol that emoji_lib does not know,
# so read it from the instruction line first and match it against the buttons.
_EMOJI_LINE = re.compile(r"(?:emoji|symbol|icon|sticker|sign)\s*[:：=\-–—]\s*(.+)$", re.I | re.M)

def _norm_sym(s):
    return re.sub(r"[\ufe0f\u200d\u200b\s]", "", s or "")

def _emoji_targets(text):
    m = _EMOJI_LINE.search(text or "")
    if not m: return []
    seg = m.group(1)
    out = [it["emoji"] for it in emoji_lib.emoji_list(seg)]
    for ch in _norm_sym(seg):
        if not ch.isascii() and not ch.isalnum() and not any(ch in o for o in out):
            out.append(ch)
    return out

async def solve_emoji(event, client, bot_user):
    if not event.buttons: return None
    text = event.raw_text or ""
    targets = _emoji_targets(text) or [it["emoji"] for it in emoji_lib.emoji_list(text)]
    btns = [b for row in event.buttons for b in row if not getattr(b, "url", None)]
    for exact in (True, False):
        for e in targets:
            ne = _norm_sym(e)
            for btn in btns:
                bt = _norm_sym(btn.text)
                if ne and ((bt == ne) if exact else (ne in bt)):
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
    if len(_num_buttons(event)) >= 2:
        r = await solve_number(event, client, bot_user)
        if r: return r
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
    m = re.search(r"(?:code|captcha)[^\n:：]{0,20}[:：]\s*\n?\s*([A-Za-z0-9]{3,16})\b", text, re.I) \
        or re.search(r"(?:code|captcha)[^\n:：]{0,20}\n\s*([A-Za-z0-9]{3,16})\b", text, re.I) \
        or re.search(r"(?:code|captcha)[^\n:：]{0,20}?\s([A-Za-z0-9]{4,16})\b", text, re.I)
    if m and _looks_like_code(m.group(1)):
        return m.group(1)
    # 3) a line that is nothing but a code-looking token (mixed letters+digits)
    for line in text.splitlines():
        s = line.strip()
        if re.fullmatch(r"(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9]{3,16}", s):
            return s
    return None

# ── Number-button captcha ────────────────────────────────────────
# "Select the number 1 to verify" / "Your verification code: 450269 — pick the
# correct one of the 6 codes below": the answer is one of the numeric buttons.
_NUM_KEY = re.compile(r"(?:number|code|digit|answer|select|click(?:\s+on)?|press|tap|choose|pick)\D{0,24}?(\d+)", re.I)

def _num_buttons(event):
    out = []
    for row in (event.buttons or []):
        for b in row:
            if getattr(b, "url", None): continue
            tx = _norm_sym(getattr(b, "text", ""))
            if re.fullmatch(r"\d{1,12}", tx): out.append((tx, b))
    return out

def _number_target(text, nums):
    have = {tx for tx, _ in nums}
    for m in _NUM_KEY.finditer(text or ""):          # number named next to a keyword wins
        if m.group(1) in have: return m.group(1)
    cands = list(dict.fromkeys(n for n in re.findall(r"\d+", text or "") if n in have))
    return cands[0] if len(cands) == 1 else None      # otherwise only if unambiguous

async def solve_number(event, client, bot_user):
    nums = _num_buttons(event)
    if len(nums) < 2: return None
    target = _number_target(event.raw_text or "", nums)
    if target is None: return None
    for tx, b in nums:
        if tx == target:
            await b.click(); return {"status": "success", "msg": f"Number {target}"}
    return None
solve_number.verify = True

async def solve_text_code(event, client, bot_user):
    if len(_num_buttons(event)) >= 2:
        r = await solve_number(event, client, bot_user)
        if r: return r
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
        "base64Image": ("data:image/png;base64," if img[:4] == b"\x89PNG" else "data:image/jpeg;base64,") + base64.b64encode(img).decode(),
    }).encode()
    req = urllib.request.Request("https://api.ocr.space/parse/image", data=data)
    with urllib.request.urlopen(req, timeout=25) as r:
        j = json.loads(r.read().decode())
    if j.get("IsErroredOnProcessing"):
        raise RuntimeError("OCR: " + str(j.get("ErrorMessage"))[:70])
    return "\n".join(p.get("ParsedText", "") for p in (j.get("ParsedResults") or []))

_CONFUSABLE = set("OoQDIl|iSsBZzGgq")

def _fix_token(tok):
    """Digit-fix OCR confusions (O→0, S→5 …) ONLY when the token is clearly a number
    (at least half real digits). 'O2D' / 'I5R' are letter+digit captchas — left as read."""
    d = sum(c.isdigit() for c in tok)
    if d * 2 >= len(tok) and all(c.isdigit() or c in _CONFUSABLE for c in tok):
        return tok.translate(_DIGIT_FIX)
    return tok

def _pick_captcha_answer(raw):
    """OCR text may include banner words (e.g. 'SN BOT CREATOR 15473') — pick the captcha."""
    lines = [l.strip() for l in (raw or "").splitlines() if l.strip()]
    toks = [re.sub(r"[^A-Za-z0-9]", "", l) for l in lines]
    # 1) a line that is only digits (spaces inside removed: '1 5 4 7 3' → 15473)
    best = ""
    for t in toks:
        if t.isdigit() and len(t) >= 3 and len(t) > len(best): best = t
    if best: return best
    # 2) a short line mixing letters+digits is a letter/number captcha — keep it as read
    for t in toks:
        if 3 <= len(t) <= 10 and any(c.isdigit() for c in t):
            return _fix_token(t)
    # 3) long banner line containing a long digit run ('SN BOT CREATOR 15473')
    for l in lines:
        runs = re.findall(r"\d{3,}", l.replace(" ", ""))
        if runs: return max(runs, key=len)
    # 4) letters-only captcha: the longest plain token (prefer 4–8 chars)
    words = re.findall(r"[A-Za-z0-9]{3,12}", " ".join(lines))
    if not words: return None
    return max(words, key=lambda w: (3 <= len(w) <= 8, len(w)))

def _prep_image(img):
    """Clean a noisy captcha for OCR: grayscale → blur → Otsu threshold → dark text on
    white → upscale + padding. Needs Pillow; returns None if it isn't installed."""
    try:
        from PIL import Image, ImageOps, ImageFilter
        import io
        g = Image.open(io.BytesIO(img)).convert("L")
        g = ImageOps.autocontrast(g, cutoff=2).filter(ImageFilter.GaussianBlur(1.0))
        h = g.histogram(); tot = sum(h); sm = sum(i * c for i, c in enumerate(h))
        wb = sb = 0; best = 0.0; thr = 128
        for i in range(256):
            wb += h[i]
            if wb == 0: continue
            wf = tot - wb
            if wf == 0: break
            sb += i * h[i]
            v = wb * wf * (sb / wb - (sm - sb) / wf) ** 2
            if v > best: best, thr = v, i
        bw = g.point(lambda p: 255 if p > thr else 0)
        if bw.histogram()[255] < tot / 2:        # text is the minority colour → make it black
            bw = ImageOps.invert(bw)
        bw = bw.resize((bw.width * 3, bw.height * 3), Image.LANCZOS)
        bw = ImageOps.expand(bw, border=30, fill=255)
        out = io.BytesIO(); bw.save(out, "PNG")
        return out.getvalue()
    except Exception:
        return None

def _ocr_tesseract(img):
    import shutil, subprocess, tempfile
    exe = shutil.which("tesseract")
    if not exe: return None
    with tempfile.NamedTemporaryFile(suffix=".png") as f:
        f.write(img); f.flush()
        r = subprocess.run([exe, f.name, "-", "--psm", "8", "-c",
                            "tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"],
                           capture_output=True, text=True, timeout=15)
    return r.stdout

_OCR_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ocr")   # OCR must never starve DB threads
_OCR_SEM = None

async def _ocr_run(fn, *a):
    return await asyncio.get_running_loop().run_in_executor(_OCR_POOL, fn, *a)

async def _ocr_image(img):
    """Read the captcha with several engines / image variants and take the majority answer."""
    global _OCR_SEM
    key = hashlib.sha1(img).hexdigest()
    if key in _OCR_CACHE:
        return _OCR_CACHE[key]
    if _OCR_SEM is None: _OCR_SEM = asyncio.Semaphore(4)
    async with _OCR_SEM:
        clean = await _ocr_run(_prep_image, img)
        jobs = [_ocr_run(_ocr_local, img)]                              # priority order = tie-break
        if clean: jobs += [_ocr_run(_ocr_tesseract, clean)]
        jobs += [_ocr_run(_ocr_space, clean or img)]                    # one web call (cleaned image)
        res = await asyncio.gather(*jobs, return_exceptions=True)
        if clean and not any((not isinstance(r, Exception)) and r and _pick_captcha_answer(r) for r in res):
            res += [await asyncio.gather(_ocr_run(_ocr_space, img), return_exceptions=True)][0]   # fallback: original
    cands, err = [], None
    for r in res:
        if isinstance(r, Exception): err = err or r; continue
        a = _pick_captcha_answer(r) if r else None
        if a: cands.append(a)
    if not cands:
        if err: raise err
        return None
    votes = {}
    for i, a in enumerate(cands):
        k = a.upper(); n, first, _ = votes.get(k, (0, i, a)); votes[k] = (n + 1, first, a if n == 0 else votes[k][2])
    ans = max(votes.values(), key=lambda v: (v[0], -v[1]))[2]
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
        if r: return {**r, "msg": "Image: " + r["msg"]}
    text = m.raw_text or ""
    # math before text-code: "Captcha: what is 5 + 3 = ?" must be answered 8, not "what"
    if _MATH_HINT.search(text) and re.search(r"\d+\s*[+\-*/×÷x]\s*\d+", text):
        r = await solve_math(event, client, bot_user)
        if r: return {**r, "msg": "Math: " + r["msg"]}
    if len(_num_buttons(event)) >= 2 and (_TAP_HINT.search(text) or _CODE_HINT.search(text)):
        r = await solve_number(event, client, bot_user)
        if r: return {**r, "msg": "Number: " + r["msg"]}
    r = await solve_text_code(event, client, bot_user)
    if r: return {**r, "msg": "Text: " + r["msg"]}
    if m.buttons and not _has_url_buttons(m) and _TAP_HINT.search(text):
        r = await solve_emoji(event, client, bot_user)
        if r: return {**r, "msg": "Emoji: " + r["msg"]}
    # a lone "I am human" style button
    plain = [b for row in (m.buttons or []) for b in row if not getattr(b, "url", None)]
    if len(plain) == 1 and _TAP_HINT.search(text):
        await plain[0].click()
        return {"status": "success", "msg": f"Button: Clicked '{plain[0].text}'"}
    return None
solve_auto.verify = True
solve_auto.timeout = 40

SOLVERS = {"no_captcha": None, "auto": solve_auto, "emoji": solve_emoji, "math": solve_math, "button": solve_button, "number": solve_number,
           "text_code": solve_text_code, "image": solve_image}

# ── Self-Learning Bot Profiles ───────────────────────────────────
# After every referral run the app remembers, per bot, which solver actually worked
# (image / number / math / …). "Smart" mode then tries the proven solver first and only
# falls back to Auto-Detect — so known bots get solved faster and more reliably.
_SOLVER_LABELS = {"image": solve_image, "math": solve_math, "number": solve_number,
                  "text_code": solve_text_code, "emoji": solve_emoji, "button": solve_button}
_AUTO_PREFIX = {"Image": "image", "Math": "math", "Number": "number", "Text": "text_code", "Emoji": "emoji", "Button": "button"}

def _solver_label(solver, r):
    name = getattr(solver, "__name__", "") or ""
    base = name[6:] if name.startswith("solve_") else name
    if base in ("auto", "smart"):
        if r.get("solver"): return r["solver"]
        m = re.match(r"(?:Smart[^:]*:\s*)?(Image|Math|Number|Text|Emoji|Button)\b", str(r.get("msg", "")))
        return _AUTO_PREFIX.get(m.group(1)) if m else "auto"
    return base

def _bot_key(link):
    link = str(link or "").strip()
    bot, _ = parse_bot_link(link) if link.startswith("http") else (link.lstrip("@").split("?")[0].split("/")[0], "")
    return (bot or "").lower()

def profile_get(owner, link):
    k = _bot_key(link)
    if not k or not owner: return None
    return db()["bot_profiles"].find_one({"owner": str(owner), "bot": k}, {"_id": 0})

def learn_profile_sync(owner, link, method, results):
    k = _bot_key(link)
    if not k or not owner or not results: return
    col = db()["bot_profiles"]
    doc = col.find_one({"owner": str(owner), "bot": k}, {"_id": 0}) or {"owner": str(owner), "bot": k, "runs": 0, "ok": 0, "fail": 0, "solvers": {}, "methods": {}}
    n_ok = n_fail = 0
    for r in results:
        good = r.get("status") in ("success", "partial")
        lab = r.get("solver") or (method if method in _SOLVER_LABELS else None)
        if lab and lab not in ("auto", "flow", "smart"):
            sv = doc["solvers"].setdefault(lab, {"ok": 0, "fail": 0}); sv["ok" if good else "fail"] += 1
        if good: n_ok += 1
        else: n_fail += 1
    doc["runs"] = doc.get("runs", 0) + 1; doc["ok"] = doc.get("ok", 0) + n_ok; doc["fail"] = doc.get("fail", 0) + n_fail
    m = doc.setdefault("methods", {}).setdefault(method or "none", {"ok": 0, "fail": 0}); m["ok"] += n_ok; m["fail"] += n_fail
    doc["updated"] = int(time.time())
    bad = [str(r.get("msg", ""))[:100] for r in results if r.get("status") not in ("success", "partial")]
    if bad: doc["last_errors"] = bad[-3:]
    col.update_one({"owner": str(owner), "bot": k}, {"$set": doc}, upsert=True)

def _profile_order(profile):
    """Solver names to try first, best first. Only ones proven on this bot (≥2 wins, ≥55% rate)."""
    out = []
    for name, v in ((profile or {}).get("solvers") or {}).items():
        ok, fail = int(v.get("ok", 0)), int(v.get("fail", 0))
        score = (ok + 1) / (ok + fail + 2)
        if name in _SOLVER_LABELS and ok >= 2 and score >= 0.55: out.append((score, ok, name))
    out.sort(reverse=True)
    return [n for _, _, n in out]

def profile_summary(profile):
    if not profile: return {"known": False}
    solvers = [{"name": n, "ok": int(v.get("ok", 0)), "fail": int(v.get("fail", 0))} for n, v in (profile.get("solvers") or {}).items()]
    solvers.sort(key=lambda x: -x["ok"])
    ok, fail = int(profile.get("ok", 0)), int(profile.get("fail", 0))
    order = _profile_order(profile)
    return {"known": True, "bot": profile.get("bot"), "runs": profile.get("runs", 0), "ok": ok, "fail": fail,
            "rate": round(ok / (ok + fail), 3) if ok + fail else 0, "best": order[0] if order else None,
            "solvers": solvers, "recommended": "smart" if order else "auto", "updated": profile.get("updated"),
            "last_errors": profile.get("last_errors", [])}

def make_smart_solver(profile):
    order = _profile_order(profile)
    async def solve_smart(event, client, bot_user):
        for name in order:
            r = await _SOLVER_LABELS[name](event, client, bot_user)
            if r: return {**r, "msg": f"Learned·{name}: {r['msg']}", "solver": name}
        r = await solve_auto(event, client, bot_user)
        return r
    solve_smart.verify = True
    solve_smart.timeout = 40
    return solve_smart

# ── Flow Builder ─────────────────────────────────────────────────
# A flow is a list of no-code steps run on every account against the bot:
#   reply · click · send · captcha · join · expect · wait
# The engine below is independent of Telethon (it only needs an inbox of bot messages
# and a few callbacks), which is what makes it testable without a real Telegram connection.
import collections

FLOW_MAX_STEPS = 30
FLOW_MAX_SECONDS = 300
FLOW_TYPES = ("reply", "click", "send", "captcha", "join", "expect", "wait")

class FlowError(Exception): pass

class FlowInbox:
    """Bot messages in arrival order; supports peeking (unget) and waiting with a timeout."""
    def __init__(self):
        self.q = collections.deque(); self._ev = asyncio.Event()
    def put(self, ev):
        if getattr(ev, "ts", None) is None: ev.ts = time.monotonic()
        self.q.append(ev); self._ev.set()
    def unget(self, ev):
        self.q.appendleft(ev); self._ev.set()
    def get_nowait(self):
        if not self.q: raise IndexError
        ev = self.q.popleft()
        if not self.q: self._ev.clear()
        return ev
    def empty(self): return not self.q
    async def get(self, timeout):
        end = time.monotonic() + timeout
        while not self.q:
            left = end - time.monotonic()
            if left <= 0: return None
            self._ev.clear()
            try: await asyncio.wait_for(self._ev.wait(), left)
            except asyncio.TimeoutError: return None
        return self.get_nowait()

def _btn_text(b): return re.sub(r"\s+", " ", str(getattr(b, "text", "") or "")).strip()

def _plain_buttons(ev):
    return [b for row in (getattr(ev, "buttons", None) or []) for b in row if not getattr(b, "url", None)]

def _find_button(ev, mode, value):
    btns = _plain_buttons(ev)
    if mode == "index":
        try: i = int(value)
        except Exception: return None
        return btns[i - 1] if 1 <= i <= len(btns) else None
    v = str(value)
    for b in btns:
        t = _btn_text(b)
        if mode == "exact":
            if t.lower() == v.lower(): return b
        elif mode == "regex":
            try:
                if re.search(v, t, re.I): return b
            except re.error: return None
        elif v.lower() in t.lower(): return b
    return None

def _step_label(st):
    t = st.get("type")
    if t == "click": return f"click “{st.get('value', '')}”" if st.get("mode") != "index" else f"click button #{st.get('value')}"
    if t == "send": return f"send “{str(st.get('text', ''))[:20]}”"
    if t == "expect": return f"expect “{str(st.get('pattern', ''))[:20]}”"
    if t == "captcha": return f"captcha ({st.get('method', 'auto')})"
    if t == "join": return "join channels"
    return t or "step"

async def flow_engine(steps, inbox, send, client, bot_user, ctx, join=None):
    """Run the steps. Returns ("success"|"error", message)."""
    recent = collections.OrderedDict()
    state = {"cur": None, "mark": time.monotonic()}
    ctx.setdefault("notes", []); ctx.setdefault("param", ""); ctx.setdefault("link", "")

    def remember(ev):
        if getattr(ev, "ts", None) is None: ev.ts = time.monotonic()
        mid = getattr(ev.message, "id", None) or id(ev.message)
        recent.pop(mid, None); recent[mid] = ev
        while len(recent) > 8: recent.popitem(last=False)
        state["cur"] = ev
    def drain():
        while not inbox.empty(): remember(inbox.get_nowait())
    async def take(timeout, edits=True):
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0: return None
            ev = await inbox.get(left)
            if ev is None: return None
            remember(ev)
            if getattr(ev, "edited", False) and not edits: continue
            return ev
    def newest_first():
        return list(reversed(list(recent.values())))
    def hint():
        ev = state["cur"]
        t = (getattr(ev, "raw_text", "") or "").replace("\n", " ").strip() if ev else ""
        return f" · bot said: “{t[:80]}”" if t else (" · bot sent nothing" if not recent else "")

    async def x_wait(st): await asyncio.sleep(float(st.get("seconds", 1)))
    async def x_reply(st):
        ev = await take(float(st.get("timeout", 20)), edits=False)
        if ev is None: raise FlowError(f"no reply from the bot within {int(float(st.get('timeout', 20)))}s")
    async def x_send(st):
        drain()
        code = ""
        if "{code}" in str(st.get("text", "")):
            for ev in newest_first():
                code = _extract_text_code(ev.message) or ""
                if code: break
            if not code: raise FlowError("no code found in the bot's messages")
        txt = str(st.get("text", "")).replace("{param}", ctx["param"]).replace("{link}", ctx["link"]).replace("{code}", code)
        if not txt.strip(): raise FlowError("empty message")
        await send(txt)
    async def x_click(st):
        mode = st.get("mode", "contains"); value = st.get("value", "")
        end = time.monotonic() + float(st.get("timeout", 15))
        while True:
            drain()
            btn = None
            for ev in newest_first():
                btn = _find_button(ev, mode, value)
                if btn: break
            if btn:
                try: await btn.click()
                except Exception as e:
                    if type(e).__name__ != "BotResponseTimeoutError":     # unanswered callback is normal for many bots
                        raise FlowError(f"click failed: {str(e)[:60]}")
                await asyncio.sleep(0.8); return
            left = end - time.monotonic()
            if left <= 0:
                avail = [_btn_text(b) for b in _plain_buttons(state["cur"])][:6] if state["cur"] else []
                raise FlowError(f"button “{value}” not found" + (f" (buttons seen: {', '.join(avail)})" if avail else ""))
            await take(min(left, 2.5))
    async def x_captcha(st):
        method = st.get("method", "auto")
        fn = ctx.get("smart") if method == "smart" else SOLVERS.get(method)
        if fn is None: fn = solve_auto
        end = time.monotonic() + float(st.get("timeout", 25))
        attempts = 1 + int(st.get("retries", 2)); tried = set()
        while attempts > 0:
            solved = None
            while solved is None:
                drain()
                for ev in newest_first()[:4]:
                    if id(ev) in tried: continue
                    tried.add(id(ev))
                    try: r = await fn(ev, client, bot_user)
                    except Exception as e: raise FlowError(f"captcha error: {str(e)[:70]}")
                    if r:
                        solved = (ev, r); break
                if solved: break
                left = end - time.monotonic()
                if left <= 0: raise FlowError("captcha not recognised")
                await take(min(left, 2.5))
            ev, r = solved
            ctx["solver"] = _solver_label(fn, r); ctx["notes"].append(str(r.get("msg", ""))[:40])
            attempts -= 1
            if attempts <= 0: return
            nxt = await take(8)      # peek: did the bot say "wrong" and send a new captcha?
            if nxt is None: return
            inbox.unget(nxt)
            if not _CAPTCHA_BAD.search(nxt.raw_text or ""): return
            end = time.monotonic() + float(st.get("timeout", 25))
    async def x_join(st):
        urls = []
        if st.get("source") == "list": urls = [str(c) for c in st.get("channels", [])]
        else:
            end = time.monotonic() + float(st.get("timeout", 15))
            me = f"t.me/{bot_user}".lower()
            while True:
                drain()
                msgs = [ev.message for ev in newest_first()[:3]]
                bu, tu = _extract_all_links(msgs)
                urls = [u_ for u_ in bu + tu if "t.me/" in u_.lower() and me not in u_.lower()]
                if urls: break
                left = end - time.monotonic()
                if left <= 0: break
                await take(min(left, 2.5))
        urls = list(dict.fromkeys(urls))[:15]
        if not urls: raise FlowError("no channel links found")
        if join is None: raise FlowError("joining is not available")
        ok, errs = 0, []
        for u_ in urls:
            try: await join(u_); ok += 1
            except Exception as e: errs.append(str(e)[:40])
            await asyncio.sleep(1.2)
        if not ok: raise FlowError("could not join: " + (errs[0] if errs else "unknown error"))
        ctx["notes"].append(f"joined {ok}/{len(urls)}")
    async def x_expect(st):
        try: pat = re.compile(str(st.get("pattern", "")), re.I)
        except re.error: raise FlowError("invalid pattern")
        fpat = None
        if st.get("fail_pattern"):
            try: fpat = re.compile(str(st["fail_pattern"]), re.I)
            except re.error: fpat = None
        end = time.monotonic() + float(st.get("timeout", 20))
        while True:
            drain()
            for ev in list(recent.values()):
                if (getattr(ev, "ts", 0) or 0) < state["mark"]: continue      # only what arrived since the previous step began
                t = ev.raw_text or ""
                if fpat and fpat.search(t): raise FlowError(f"bot said: “{t.replace(chr(10), ' ')[:70]}”")
                if pat.search(t): state["cur"] = ev; return
            left = end - time.monotonic()
            if left <= 0: raise FlowError("expected text not seen" + hint())
            await take(min(left, 2.5))

    X = {"wait": x_wait, "reply": x_reply, "send": x_send, "click": x_click, "captcha": x_captcha, "join": x_join, "expect": x_expect}
    n = len(steps); prev_start = time.monotonic()
    for i, st in enumerate(steps, 1):
        state["mark"] = prev_start; t0 = time.monotonic()
        try:
            await X[st["type"]](st)
        except FlowError as e:
            if st.get("optional"):
                ctx["notes"].append(f"skipped step {i}"); prev_start = t0; continue
            return "error", f"Step {i}/{n} ({_step_label(st)}): {e}" + (hint() if "bot said" not in str(e) and "bot sent" not in str(e) else "")
        prev_start = t0
    extra = (" · " + " · ".join(ctx["notes"][-3:])) if ctx["notes"] else ""
    return "success", f"Flow OK · {n} steps{extra}"

def normalize_flow_steps(steps):
    """Validate + clean a flow from the client. Raises ValueError with a readable message."""
    if not isinstance(steps, list) or not steps: raise ValueError("Add at least one step.")
    if len(steps) > FLOW_MAX_STEPS: raise ValueError(f"A flow can have at most {FLOW_MAX_STEPS} steps.")
    def num(v, lo, hi, dflt):
        try: x = float(v)
        except Exception: x = dflt
        return max(lo, min(hi, x))
    out = []
    for i, st in enumerate(steps, 1):
        if not isinstance(st, dict) or st.get("type") not in FLOW_TYPES: raise ValueError(f"Step {i}: unknown step type.")
        t = st["type"]; c = {"type": t}
        if st.get("optional") and t in ("reply", "click", "join", "expect"): c["optional"] = True
        if t == "wait": c["seconds"] = num(st.get("seconds"), 0.5, 60, 2)
        elif t == "reply": c["timeout"] = num(st.get("timeout"), 3, 90, 20)
        elif t == "send":
            c["text"] = str(st.get("text", ""))[:500]
            if not c["text"].strip(): raise ValueError(f"Step {i}: message text is empty.")
        elif t == "click":
            c["mode"] = st.get("mode") if st.get("mode") in ("contains", "exact", "regex", "index") else "contains"
            c["value"] = str(st.get("value", "")).strip()[:80]
            if not c["value"]: raise ValueError(f"Step {i}: enter the button text (or its number).")
            if c["mode"] == "index" and not re.fullmatch(r"\d{1,2}", c["value"]): raise ValueError(f"Step {i}: button number must be 1–99.")
            if c["mode"] == "regex":
                try: re.compile(c["value"])
                except re.error: raise ValueError(f"Step {i}: the button pattern is not valid.")
            c["timeout"] = num(st.get("timeout"), 3, 60, 15)
        elif t == "captcha":
            m = st.get("method", "auto")
            c["method"] = m if (m in SOLVERS and m != "no_captcha") or m == "smart" else "auto"
            c["timeout"] = num(st.get("timeout"), 5, 90, 25)
            c["retries"] = int(num(st.get("retries"), 0, 3, 2))
        elif t == "join":
            c["source"] = "list" if st.get("source") == "list" else "buttons"
            c["timeout"] = num(st.get("timeout"), 3, 60, 15)
            if c["source"] == "list":
                ch = [str(x).strip()[:120] for x in (st.get("channels") or []) if str(x).strip()][:10]
                if not ch: raise ValueError(f"Step {i}: add at least one channel to join.")
                c["channels"] = ch
        elif t == "expect":
            c["pattern"] = str(st.get("pattern", "")).strip()[:120]
            if not c["pattern"]: raise ValueError(f"Step {i}: enter the text to look for.")
            try: re.compile(c["pattern"])
            except re.error: raise ValueError(f"Step {i}: the text pattern is not valid.")
            fp = str(st.get("fail_pattern", "")).strip()[:120]
            if fp:
                try: re.compile(fp); c["fail_pattern"] = fp
                except re.error: raise ValueError(f"Step {i}: the failure pattern is not valid.")
            c["timeout"] = num(st.get("timeout"), 3, 120, 20)
        out.append(c)
    return out

class _FlowEvent(object):
    """Telethon event → the small interface the flow engine and the solvers read."""
    def __init__(self, event, edited):
        m = event.message
        self.message = m; self.raw_text = m.raw_text; self.buttons = m.buttons; self.edited = edited

async def _flow_run(acc, bot_link, flow, smart=None):
    client = await get_client(acc)
    result = {"account": acc["session_name"], "status": "error", "msg": "Flow did not run", "solver": "flow"}
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link", "solver": "flow"}
        inbox = FlowInbox()
        async def on_msg(event):
            inbox.put(_FlowEvent(event, isinstance(event, events.MessageEdited.Event)))
        client.add_event_handler(on_msg, events.NewMessage(from_users=bot_user))
        client.add_event_handler(on_msg, events.MessageEdited(from_users=bot_user))
        await client.send_message(bot_user, f"/start {param}".strip())
        ctx = {"param": param, "link": bot_link, "notes": [], "solver": None, "smart": smart}
        async def send(t): await client.send_message(bot_user, t)
        async def join(u_): await _join_one(client, u_)
        status, msg = await asyncio.wait_for(flow_engine(flow["steps"], inbox, send, client, bot_user, ctx, join), FLOW_MAX_SECONDS)
        result.update(status=status, msg=msg, solver=ctx.get("solver") or "flow")
        await asave_session(acc["owner"], acc["session_name"], client.session.save())
    except asyncio.TimeoutError:
        result.update(status="error", msg=f"Flow timed out after {FLOW_MAX_SECONDS}s")
    except errors.FloodWaitError:
        raise
    except Exception as e:
        result.update(status="error", msg=friendly_error(e))
    finally:
        try: await client.disconnect()
        except Exception: pass
    return result

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

async def _run_once_with_flood(worker, acc, jid):
    """Run worker(acc) once. If Telegram replies with a short flood-wait, wait it
    out and retry automatically (once) instead of failing the account outright."""
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

# ── Smart Retry ──────────────────────────────────────────────────
# Failures that are usually temporary (slow bot, dropped connection, wrong captcha that
# gets a fresh one) are retried with a growing pause. Dead sessions, bans, bad links and
# long flood-waits are NOT retried — repeating those would only waste time or risk the account.
_TRANSIENT_RE = re.compile(r"No captcha response|timed? ?out|Timeout|Connection hiccup|EOF when reading|ConnectionError|"
                           r"ConnectionReset|ConnectionAborted|Cannot connect|busy with another task|database is locked|"
                           r"Server closed|ServerError|rejected answer|Couldn't read the captcha|OSError|BrokenPipe|IncompleteRead", re.I)
_NO_RETRY_RE = re.compile(r"Invalid link|too long to auto-retry|No usable|no longer exists", re.I)
RETRY_BACKOFF = (3, 8, 15)

def is_transient(r):
    if r.get("status") in ("success", "partial"): return False
    msg = str(r.get("msg", ""))
    if _dead_kind(msg) or _NO_RETRY_RE.search(msg): return False
    return bool(_TRANSIENT_RE.search(msg))

async def run_with_retry(worker, acc, jid, retries=0):
    log_api_call()
    attempts = 0
    while True:
        r = await _run_once_with_flood(worker, acc, jid)
        attempts += 1
        if attempts > retries or job_cancel_requested(jid) or not is_transient(r): break
        await asyncio.sleep(RETRY_BACKOFF[min(attempts - 1, len(RETRY_BACKOFF) - 1)] + random.random())
    if attempts > 1:
        r["attempts"] = attempts
        r["msg"] = f"{r.get('msg', '')} · tried {attempts}×"
    return r

# ── per-account stats (feed the Health Score) ────────────────────
def _stat_record(stats, name, r):
    s_ = stats.setdefault(name, {"ok": 0, "fail": 0, "last": None, "trail": 0, "flood": False, "err": "", "dead": None})
    msg = str(r.get("msg", ""))
    if r.get("status") in ("success", "partial"):
        s_["ok"] += 1; s_["last"] = "ok"; s_["trail"] = 0
    else:
        s_["fail"] += 1; s_["last"] = "fail"; s_["trail"] += 1; s_["err"] = msg[:120]
        d = _dead_kind(msg)
        if d: s_["dead"] = d
    if _FLOOD_RE.search(msg): s_["flood"] = True

def _stat_ops(owner, names, stats, now=None):
    now = now or int(time.time()); ops = []
    for n in names:
        s_ = stats.get(n); upd = {"$set": {"last_used": now}}
        if s_:
            inc = {}
            if s_["ok"]: inc["st_ok"] = s_["ok"]
            if s_["fail"]: inc["st_fail"] = s_["fail"]
            upd["$set"]["st_last_at"] = now
            if s_["last"] == "ok":
                upd["$set"]["st_consec"] = 0; upd["$set"]["st_last_ok"] = now
            elif s_["trail"]:
                inc["st_consec"] = s_["trail"]; upd["$set"]["st_last_err"] = s_["err"]
            if inc: upd["$inc"] = inc
            if s_["flood"]: upd["$set"]["st_flood_at"] = now
            if s_["dead"]:
                upd["$set"].update({"health": s_["dead"], "health_detail": "Detected during last run: " + s_["err"][:90], "health_checked": now})
        ops.append(UpdateOne({"owner": owner, "session_name": n}, upd))
    return ops

def _apply_stats(owner, names, stats):
    ops = _stat_ops(owner, names, stats)
    if ops: db()["accounts"].bulk_write(ops, ordered=False)

# ── live monitoring → Smart Alerts ───────────────────────────────
_CAPTCHA_FAIL_RE = re.compile(r"rejected answer|No captcha response|Couldn't read the captcha|captcha", re.I)

def _monitor(jid, owner, r, mon):
    kind = (JOBS.get(jid) or {}).get("kind")
    msg = str(r.get("msg", ""))
    if _FLOOD_RE.search(msg):
        mon["flood_n"] += 1
        if not mon["flood_alerted"] and (mon["flood_n"] >= 3 or "too long" in msg):
            mon["flood_alerted"] = True
            _bg(alert_async(owner, "flood", "<b>Flood-wait detected</b>\nTelegram is slowing these accounts down "
                            f"({mon['flood_n']} so far in this run). Consider the <b>Single</b> speed or a longer delay.", cooldown=900))
    if kind == "refer":
        rec = mon["recent"]; rec.append(r); del rec[:-6]
        if (not mon["captcha_alerted"] and len(rec) == 6 and all(x.get("status") not in ("success", "partial") for x in rec)
                and sum(1 for x in rec if _CAPTCHA_FAIL_RE.search(str(x.get("msg", "")))) >= 4):
            mon["captcha_alerted"] = True
            meta = (JOBS.get(jid) or {}).get("meta") or {}
            bot = re.sub(r"^https?://t\.me/", "@", str(meta.get("link", ""))).split("?")[0]
            _bg(alert_async(owner, "captcha_fail", f"<b>Captcha keeps failing</b>\n6 accounts in a row failed on <code>{bot}</code>.\n"
                            f"Last reason: {msg[:120]}\nTry another captcha type, <b>Smart</b> mode, or build a <b>Flow</b>.", cooldown=900))

async def _low_health_alert(owner, names):
    try:
        accs = await asyncio.to_thread(load_accounts, owner)
        weak = [a["session_name"] for a in accs if a["session_name"] in names and a.get("health") not in ("dead", "banned")
                and health_score(a)[0] < 40]
        if weak:
            lines = ["<b>Weak accounts</b>", f"{len(weak)} account(s) now have a low health score (under 40):"] + [f"• <code>{n}</code>" for n in weak[:10]]
            lines.append("\nOpen Accounts → sort by Score. Consider resting or removing them.")
            await alert_async(owner, "low_health", "\n".join(lines), cooldown=6 * 3600)
    except Exception as e:
        print("low-health alert:", e)

# One cap shared by EVERY user's job. Before, each user got their own pool (8–50 Telegram
# clients each), so many users starting at once opened hundreds of connections on a small
# free-tier server (RAM/CPU exhausted → everything froze). Now all jobs share these slots,
# first-come-first-served, so everyone's job keeps moving instead of the server choking.
MAX_ACTIVE_CLIENTS = int(os.getenv("MAX_ACTIVE_CLIENTS", "16"))
_GLOBAL_SLOTS = None
def _global_slots():
    global _GLOBAL_SLOTS
    if _GLOBAL_SLOTS is None:
        _GLOBAL_SLOTS = asyncio.Semaphore(max(1, MAX_ACTIVE_CLIENTS))
    return _GLOBAL_SLOTS

async def _run_pool(jid, accs, worker, concurrency, delay, retries=0):
    """Run worker(acc) over accs with N at a time; delay between starts.
    Per-account stats and 'last_used' are buffered and flushed to MongoDB in one batched
    bulk write every 2s instead of one write per account — far fewer DB round trips,
    and no worker blocks waiting on its own write."""
    concurrency = max(1, min(int(concurrency), 50))
    retries = max(0, min(int(retries or 0), 3))
    sem = asyncio.Semaphore(concurrency)
    touched, stats, dead_found = set(), {}, {}
    mon = {"recent": [], "captcha_alerted": False, "flood_n": 0, "flood_alerted": False}
    owner = accs[0]["owner"] if accs else None
    async def flush_touched():
        if not touched: return
        names = list(touched); touched.clear(); st = dict(stats); stats.clear()
        try:
            await asyncio.to_thread(_apply_stats, owner, names, st)
        except Exception as e:
            print("stats batch flush error:", e)
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
                async with _global_slots():   # server-wide cap shared by all users' jobs
                    if job_cancel_requested(jid): return
                    r = await run_with_retry(worker, acc, jid, retries)
            name = acc["session_name"]
            touched.add(name); _stat_record(stats, name, r)
            d = _dead_kind(str(r.get("msg", "")))
            if d: dead_found[name] = d
            job_push(jid, r)
            try: _monitor(jid, owner, r, mon)
            except Exception as e: print("monitor error:", e)
            if concurrency == 1:
                await asyncio.sleep(delay)
    flusher = asyncio.create_task(periodic_flush())
    await asyncio.gather(*(one(i, a) for i, a in enumerate(accs)))
    flusher.cancel()
    await flush_touched()   # final flush for anything since the last periodic tick
    await asyncio.to_thread(job_finish, jid)   # Mongo writes + Telegram notice: keep off the event loop
    if dead_found:
        await asyncio.to_thread(alert_dead_accounts, owner, list(dead_found))
    if (JOBS.get(jid) or {}).get("kind") in ("refer", "channels", "message"):
        await _low_health_alert(owner, {a["session_name"] for a in accs})

async def run_refer_job(jid, accs, link, method, delay, concurrency=1, retries=0, flow=None):
    owner = accs[0]["owner"] if accs else None
    if method == "flow" and flow:
        smart = make_smart_solver(await asyncio.to_thread(profile_get, owner, link))
        async def worker(acc):
            return await _flow_run(acc, link, flow, smart)
    else:
        solver = SOLVERS.get(method)
        if method == "smart":
            solver = make_smart_solver(await asyncio.to_thread(profile_get, owner, link))
        async def worker(acc):
            return await (refer_plain(acc, link) if solver is None else _captcha_flow(acc, link, solver))
    await _run_pool(jid, accs, worker, concurrency, delay, retries)
    try:   # Self-Learning Bot Profiles: remember what worked on this bot
        j = JOBS.get(jid)
        if j and owner: await asyncio.to_thread(learn_profile_sync, owner, link, method, list(j["results"]))
    except Exception as e:
        print("profile learn error:", e)

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

async def run_channel_job(jid, accs, channels, action, delay=2, concurrency=1, retries=0):
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
                    ok += 1; lines.append(f"OK {ch}")
                except Exception as e:
                    lines.append(f"FAIL {ch}: {str(e)[:60]}")
                await asyncio.sleep(delay)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
            st = "success" if ok == len(channels) else ("partial" if ok else "error")
            return {"account": acc["session_name"], "status": st, "msg": f"{ok}/{len(channels)} · " + " · ".join(lines)}
        finally:
            try: await client.disconnect()
            except Exception: pass
    await _run_pool(jid, accs, worker, concurrency, delay, retries)

async def run_message_job(jid, accs, target, text, delay=2, concurrency=1, retries=0):
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
    await _run_pool(jid, accs, worker, concurrency, delay, retries)

# ── workers for auto-leave and mute (factories so a resumed job can rebuild them) ──
def _auto_leave_worker(count, delay):
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
                    ok += 1; lines.append(f"OK {dl.name}")
                except Exception as e:
                    lines.append(f"FAIL {dl.name}: {str(e)[:50]}")
                await asyncio.sleep(delay)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
            st = "success" if ok else ("error" if picked else "partial")
            msg = f"Left {ok}/{len(picked)}" if picked else "No channels/groups to leave"
            return {"account": acc["session_name"], "status": st, "msg": msg}
        finally:
            try: await client.disconnect()
            except Exception: pass
    return worker

def _mute_worker(mute, include_groups):
    word = "Muted" if mute else "Unmuted"
    what = "channels + groups" if include_groups else "channels"
    async def worker(acc):
        client = await get_client(acc)
        try:
            await client.connect()
            if not await client.is_user_authorized():
                return {"account": acc["session_name"], "status": "error", "msg": "Session expired — needs re-login"}
            done, already, failed, note = await mute_account_dialogs(client, mute, include_groups)
            await asave_session(acc["owner"], acc["session_name"], client.session.save())
            total = done + already + failed
            msg = f"{word} {done} {what}" + (f" · {already} already {word.lower()}" if already else "") \
                  + (f" · {failed} failed" if failed else "") + (f" · {note}" if note else "")
            if not total:
                return {"account": acc["session_name"], "status": "success", "msg": f"No {what} joined"}
            st = "success" if not failed and not note else ("partial" if done or already else "error")
            return {"account": acc["session_name"], "status": st, "msg": msg}
        finally:
            try: await client.disconnect()
            except Exception: pass
    return worker

# How each kind of job is rebuilt from its saved spec when the queue resumes it.
async def _rn_refer(jid, accs, sp):
    await run_refer_job(jid, accs, sp["link"], sp["method"], sp["delay"], sp["conc"], sp.get("retries", 0), sp.get("flow"))
async def _rn_channels(jid, accs, sp):
    await run_channel_job(jid, accs, sp["channels"], sp["action"], sp["delay"], sp["conc"], sp.get("retries", 0))
async def _rn_message(jid, accs, sp):
    await run_message_job(jid, accs, sp["target"], sp["text"], sp["delay"], sp["conc"], sp.get("retries", 0))
async def _rn_auto_leave(jid, accs, sp):
    await _run_pool(jid, accs, _auto_leave_worker(sp["count"], sp["delay"]), sp["conc"], sp["delay"])
async def _rn_mute(jid, accs, sp):
    await _run_pool(jid, accs, _mute_worker(sp["mute"], sp["include_groups"]), sp["conc"], sp["delay"], sp.get("retries", 0))
JOB_RUNNERS = {"refer": _rn_refer, "channels": _rn_channels, "message": _rn_message,
               "auto_leave": _rn_auto_leave, "mute": _rn_mute}

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
        tg_send(_oid, f"<b>Access request</b>\n\nName: {name} ({un})\nID: <code>{uid}</code>\n\nOpen the app → Admin → Pending to approve.")
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
        sc, gr, why = health_score(a)
        out.append({"session_name": a["session_name"], "api_id": a["api_id"],
                    "name": a.get("name", ""), "username": a.get("username", ""),
                    "phone": p[:4] + "•••" + p[-3:] if len(p) > 7 else p,
                    "health": a.get("health", "unknown"), "health_detail": a.get("health_detail", ""),
                    "health_checked": a.get("health_checked"),
                    "note": a.get("note", ""), "excluded": bool(a.get("excluded")),
                    "last_used": a.get("last_used"), "created": a.get("created"),
                    "link_finder_default": bool(a.get("link_finder_default")),
                    "score": sc, "grade": gr, "score_notes": why,
                    "st_ok": int(a.get("st_ok") or 0), "st_fail": int(a.get("st_fail") or 0)})
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
        await asyncio.to_thread(job_finish, jid)
        await asyncio.to_thread(alert_dead_accounts, u["id"], _dead)
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
        caption=f"<b>Backup file</b> — {len(out)} account(s)\n\nKeep this safe — it contains login sessions. Use Import in the app to restore.")
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
                    solves += 1; captcha_log.append("Warning: " + str(e)[:80])
        now = loop.time()
        if link_msgs and last_link and now - last_link >= LF_SETTLE:
            break
        if last_reply is None and now - start >= LF_SILENT_MAX:
            break
        await asyncio.sleep(1.5)
    replies = len({k[0] for k in processed})
    return [link_msgs[k] for k in sorted(link_msgs)], replies

# ── Jobs ─────────────────────────────────────────────────────────
def _retries_param(b, default):
    try: r = int(b.get("retries", default))
    except Exception: r = default
    return max(0, min(r, 3))

def _no_accounts_msg(weak):
    return ("No accounts left — the selected ones are dead or scored below your minimum health score." if weak
            else "No usable accounts — all selected accounts are dead. Re-add them first.")

@app.post("/api/refer")
async def refer(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    accs, weak = filter_weak(accs, b.get("min_score"))
    if not accs: raise HTTPException(400, _no_accounts_msg(weak))
    if not parse_bot_link(b.get("bot_link", ""))[0]: raise HTTPException(400, "Invalid bot link.")
    method = b.get("method", "no_captcha")
    if method not in SOLVERS and method not in ("smart", "flow"): raise HTTPException(400, "Unknown captcha type.")
    flow = None
    if method == "flow":
        d = await asyncio.to_thread(lambda: db()["flows"].find_one({"owner": u["id"], "id": str(b.get("flow_id", ""))}, {"_id": 0}))
        if not d: raise HTTPException(400, "Choose a flow first.")
        flow = {"id": d["id"], "name": d.get("name", ""), "steps": d["steps"]}
    conc, delay = speed_params(b, len(accs)); retries = _retries_param(b, 2)
    meta = {"link": b["bot_link"], "method": method, "speed": b.get("speed", "fast"), "concurrency": conc, "retries": retries,
            "skipped_dead": skipped, "skipped_weak": weak}
    if flow: meta["flow"] = flow["name"]
    spec = {"kind": "refer", "accounts": [a["session_name"] for a in accs], "link": b["bot_link"], "method": method,
            "delay": delay, "conc": conc, "retries": retries, "flow": flow}
    jid = job_new(u["id"], "refer", len(accs), meta, spec)
    asyncio.create_task(run_refer_job(jid, accs, b["bot_link"], method, delay, conc, retries, flow))
    return {"job_id": jid}

@app.post("/api/channels/auto-leave")
async def auto_leave(request: Request):
    """Leave N random channels/groups per selected account."""
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    accs, weak = filter_weak(accs, b.get("min_score"))
    if not accs: raise HTTPException(400, _no_accounts_msg(weak))
    count = max(1, min(int(b.get("count", 5)), 3000))
    conc, delay = speed_params(b, len(accs))
    spec = {"kind": "auto_leave", "accounts": [a["session_name"] for a in accs], "count": count, "delay": delay, "conc": conc}
    jid = job_new(u["id"], "auto_leave", len(accs), {"count": count, "speed": b.get("speed", "fast"), "concurrency": conc,
                                                      "skipped_dead": skipped, "skipped_weak": weak}, spec)
    asyncio.create_task(_run_pool(jid, accs, _auto_leave_worker(count, delay), conc, delay))
    return {"job_id": jid}

@app.post("/api/channels/random-leave")
async def random_leave_alias(request: Request):
    return await auto_leave(request)

# ── Mute / unmute every joined channel ───────────────────────────
MUTE_FOREVER = 2**31 - 1   # Telegram's "muted until forever"

def _is_muted(dl):
    """True if this dialog's notifications are currently muted."""
    ns = getattr(getattr(dl, "dialog", None), "notify_settings", None)
    mu = getattr(ns, "mute_until", None)
    if not mu:
        return False
    ts = mu.timestamp() if hasattr(mu, "timestamp") else mu   # Telethon gives a datetime
    return ts > time.time()

async def _set_mute(client, dl, mute):
    peer = InputNotifyPeer(peer=await client.get_input_entity(dl.entity))
    await client(UpdateNotifySettingsRequest(peer=peer, settings=InputPeerNotifySettings(
        mute_until=MUTE_FOREVER if mute else 0)))

async def mute_account_dialogs(client, mute=True, include_groups=False, pause=0.35):
    """Mute (or unmute) every channel — and optionally every group — this account
    is in. Dialogs already in the wanted state are skipped. Returns (done, skipped, failed, note)."""
    dialogs = await client.get_dialogs(limit=None)
    targets = [dl for dl in dialogs if (dl.is_channel and not dl.is_group) or (include_groups and dl.is_group)]
    todo = [dl for dl in targets if _is_muted(dl) != mute]
    done = failed = 0; note = ""
    for dl in todo:
        try:
            await _set_mute(client, dl, mute); done += 1
        except errors.FloodWaitError as e:
            if e.seconds > FLOOD_AUTO_WAIT_MAX:
                note = f"stopped: flood wait {e.seconds}s"; break
            await asyncio.sleep(e.seconds + 1)
            try: await _set_mute(client, dl, mute); done += 1
            except Exception: failed += 1
        except Exception:
            failed += 1
        await asyncio.sleep(pause)
    return done, len(targets) - len(todo), failed, note

@app.post("/api/channels/mute")
async def mute_channels(request: Request):
    """Mute (or unmute) all joined channels on each selected account."""
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"), allow_reserved=True)
    if not accs: raise HTTPException(400, "No usable accounts — all selected accounts are dead. Re-add them first.")
    mute = b.get("mute", True) is not False
    include_groups = bool(b.get("include_groups"))
    conc, delay = speed_params(b, len(accs))
    spec = {"kind": "mute", "accounts": [a["session_name"] for a in accs], "mute": mute, "include_groups": include_groups,
            "delay": delay, "conc": conc}
    jid = job_new(u["id"], "mute", len(accs), {"mute": mute, "include_groups": include_groups,
                  "speed": b.get("speed", "fast"), "concurrency": conc, "skipped_dead": skipped}, spec)
    asyncio.create_task(_run_pool(jid, accs, _mute_worker(mute, include_groups), conc, delay))
    return {"job_id": jid}

@app.post("/api/channels")
async def channels(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    accs, weak = filter_weak(accs, b.get("min_score"))
    chans = [c.strip() for c in b.get("channels", []) if c.strip()]
    if not accs: raise HTTPException(400, _no_accounts_msg(weak))
    if not chans: raise HTTPException(400, "No channels given.")
    conc, delay = speed_params(b, len(accs)); retries = _retries_param(b, 1)
    action = b.get("action", "join")
    spec = {"kind": "channels", "accounts": [a["session_name"] for a in accs], "channels": chans, "action": action,
            "delay": delay, "conc": conc, "retries": retries}
    jid = job_new(u["id"], "channels", len(accs), {"action": action, "channels": chans, "speed": b.get("speed", "fast"), "concurrency": conc,
                                                   "retries": retries, "skipped_dead": skipped, "skipped_weak": weak}, spec)
    asyncio.create_task(run_channel_job(jid, accs, chans, action, delay, conc, retries))
    return {"job_id": jid}

@app.post("/api/message")
async def message(request: Request):
    u = current_user(request)
    b = await request.json()
    accs, skipped = pick_accounts(u["id"], b.get("accounts"), exclude=b.get("exclude"))
    accs, weak = filter_weak(accs, b.get("min_score"))
    if not accs: raise HTTPException(400, _no_accounts_msg(weak))
    if not b.get("target") or not b.get("text"): raise HTTPException(400, "Target and message are required.")
    conc, delay = speed_params(b, len(accs)); retries = _retries_param(b, 1)
    spec = {"kind": "message", "accounts": [a["session_name"] for a in accs], "target": b["target"], "text": b["text"],
            "delay": delay, "conc": conc, "retries": retries}
    jid = job_new(u["id"], "message", len(accs), {"target": b["target"], "speed": b.get("speed", "fast"), "concurrency": conc,
                                                  "retries": retries, "skipped_dead": skipped, "skipped_weak": weak}, spec)
    asyncio.create_task(run_message_job(jid, accs, b["target"], b["text"], delay, conc, retries))
    return {"job_id": jid}

_HIDDEN_JOB_KEYS = ("spec", "heartbeat", "instance", "_id")
def _public_job(j):
    return {k: v for k, v in j.items() if k not in _HIDDEN_JOB_KEYS}

@app.get("/api/jobs/{jid}")
async def job(jid: str, request: Request):
    u = current_user(request)
    j = JOBS.get(jid)
    if not j:
        # not in this server's memory: maybe waiting to be resumed after a restart, or already finished
        j = await asyncio.to_thread(lambda: db()["jobs_live"].find_one({"id": jid}, {"_id": 0}) or db()["jobs"].find_one({"id": jid}, {"_id": 0}))
    if not j: raise HTTPException(404, "Job not found (server may have restarted).")
    if j.get("owner") != u["id"] and u["role"] != "owner": raise HTTPException(403, "Not your job.")
    return _public_job(j)

@app.post("/api/jobs/{jid}/cancel")
async def cancel_job(jid: str, request: Request):
    u = current_user(request)
    j = JOBS.get(jid)
    if not j:
        d = await asyncio.to_thread(lambda: db()["jobs_live"].find_one({"id": jid}, {"_id": 0}))
        if not d: raise HTTPException(404, "Job not found or already finished.")
        if d.get("owner") != u["id"] and u["role"] != "owner": raise HTTPException(403, "Not your job.")
        await asyncio.to_thread(lambda: db()["jobs_live"].update_one({"id": jid}, {"$set": {"cancel": True}}))
        return {"status": "cancelling"}
    if j.get("owner") != u["id"] and u["role"] != "owner": raise HTTPException(403, "Not your job.")
    if j["status"] != "running": return {"status": "already_finished"}
    j["cancel"] = True
    _JOB_DIRTY.add(jid)
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
    weak = sum(1 for a in accs if a.get("health") not in ("dead", "banned") and health_score(a)[2] and health_score(a)[0] < 55)
    return {"total": len(accs), "counts": counts, "needs_attention": needs, "weak": weak, "last_checked": last or None}

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
    return {"jobs": [{k: v for k, v in _public_job(j).items() if k != "results"} for j in live]}

# ── Flow Builder API ─────────────────────────────────────────────
FLOW_MAX_PER_USER = 30

@app.get("/api/flows")
async def flows_list(request: Request):
    u = current_user(request)
    docs = await asyncio.to_thread(lambda: list(db()["flows"].find({"owner": u["id"]}, {"_id": 0}).sort("updated", -1)))
    return {"flows": [{k: v for k, v in d.items() if k != "owner"} for d in docs]}

@app.post("/api/flows")
async def flows_save(request: Request):
    u = current_user(request)
    b = await request.json()
    name = str(b.get("name", "")).strip()[:40]
    if not name: raise HTTPException(400, "Give the flow a name.")
    try: steps = normalize_flow_steps(b.get("steps"))
    except ValueError as e: raise HTTPException(400, str(e))
    fid = str(b.get("id") or "").strip()[:16]
    col = db()["flows"]
    if not fid:
        if await asyncio.to_thread(col.count_documents, {"owner": u["id"]}) >= FLOW_MAX_PER_USER:
            raise HTTPException(400, f"You can keep up to {FLOW_MAX_PER_USER} flows. Delete one first.")
        fid = uuid.uuid4().hex[:8]
    now = int(time.time())
    await asyncio.to_thread(lambda: col.update_one({"owner": u["id"], "id": fid},
        {"$set": {"owner": u["id"], "id": fid, "name": name, "steps": steps, "updated": now}, "$setOnInsert": {"created": now}}, upsert=True))
    return {"id": fid, "name": name, "steps": steps, "updated": now}

@app.delete("/api/flows/{fid}")
async def flows_delete(fid: str, request: Request):
    u = current_user(request)
    await asyncio.to_thread(lambda: db()["flows"].delete_one({"owner": u["id"], "id": fid}))
    return {"status": "success"}

# ── Bot Profiles API ─────────────────────────────────────────────
@app.get("/api/bot-profile")
async def bot_profile(request: Request):
    u = current_user(request)
    link = request.query_params.get("link", "")
    return profile_summary(await asyncio.to_thread(profile_get, u["id"], link))

@app.get("/api/bot-profiles")
async def bot_profiles(request: Request):
    u = current_user(request)
    docs = await asyncio.to_thread(lambda: list(db()["bot_profiles"].find({"owner": u["id"]}, {"_id": 0}).sort("updated", -1).limit(60)))
    return {"profiles": [profile_summary(d) for d in docs]}

@app.post("/api/bot-profiles/delete")
async def bot_profile_delete(request: Request):
    u = current_user(request)
    b = await request.json()
    k = _bot_key(b.get("bot", ""))
    if not k: raise HTTPException(400, "Bot name is required.")
    await asyncio.to_thread(lambda: db()["bot_profiles"].delete_one({"owner": u["id"], "bot": k}))
    return {"status": "success"}

# ── Smart Alerts API ─────────────────────────────────────────────
@app.get("/api/alerts")
async def alerts_get(request: Request):
    u = current_user(request)
    _ALERT_PREF_CACHE.pop(str(u["id"]), None)
    return {"prefs": await asyncio.to_thread(alert_prefs, u["id"]), "kinds": list(ALERT_KINDS)}

@app.post("/api/alerts")
async def alerts_set(request: Request):
    u = current_user(request)
    b = await request.json()
    upd = {k: bool(b[k]) for k in ALERT_KINDS if k in b}
    if upd:
        await asyncio.to_thread(lambda: db()["alert_prefs"].update_one({"owner": str(u["id"])}, {"$set": {"owner": str(u["id"]), **upd}}, upsert=True))
    _ALERT_PREF_CACHE.pop(str(u["id"]), None)
    return {"prefs": await asyncio.to_thread(alert_prefs, u["id"])}

@app.post("/api/alerts/test")
async def alerts_test(request: Request):
    u = current_user(request)
    ok = await asyncio.to_thread(tg_send, u["id"], "<b>Test alert</b>\nSmart Alerts are working. You will get messages like this when a run finishes, "
                                 "an account dies, captchas keep failing, or a run resumes after a restart.")
    return {"sent": bool(ok)}

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
        tg_send(uid, "<b>Access granted!</b>\nYou can now open Turbo Refer. Send /start to the bot.")
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
                    tg_send(oid, f"<b>Database almost full</b>\n\n{mb:.1f} MB of 512 MB used ({pct:.0f}%)\n\nDelete unused accounts or old data soon, or the app will stop saving.")
        except Exception as e:
            print("storage_watch:", e)
        await asyncio.sleep(6 * 3600)

@app.on_event("startup")
async def _startup():
    # default pool is only ~5 threads on a small server; every to_thread() DB call shares it
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=48, thread_name_prefix="db"))
    await asyncio.to_thread(migrate)
    asyncio.create_task(storage_watch())
    asyncio.create_task(job_persist_loop())     # Persistent Job Queue: save running jobs
    asyncio.create_task(job_resume_loop())      # … and pick up jobs a dead server left behind

@app.on_event("shutdown")
async def _shutdown():
    try: await asyncio.to_thread(_persist_jobs_sync)    # last save so the next server resumes from here
    except Exception as e: print("shutdown persist:", e)

# ── Run ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
