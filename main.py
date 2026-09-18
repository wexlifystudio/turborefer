"""
Turbo Refer V2 — Mini App Backend
FastAPI + Telethon + MongoDB + Telegram WebApp auth
"""

import os, re, hmac, json, time, uuid, asyncio, hashlib
from urllib.parse import parse_qsl

import emoji as emoji_lib
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = FastAPI(title="Turbo Refer Mini App")

# ── Config (Render → Environment) ────────────────────────────────
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")              # from @BotFather
OWNER_ID    = str(os.getenv("OWNER_ID", ""))          # your Telegram user id
MONGO_URL   = os.getenv("MONGO_URL", "")
API_SECRET  = os.getenv("API_SECRET", "")             # optional: legacy TBC access
DEV_NOAUTH  = os.getenv("DEV_NOAUTH", "0") == "1"     # 1 = open in browser without Telegram (testing only)
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

def load_accounts():
    try:
        return list(db()["accounts"].find({}, {"_id": 0}))
    except Exception as e:
        print("DB error:", e); return []

def save_account(acc):
    db()["accounts"].update_one({"session_name": acc["session_name"]}, {"$set": acc}, upsert=True)

def delete_account_db(name):
    db()["accounts"].delete_one({"session_name": name})
    db()["sessions"].delete_one({"session_name": name})

def save_session(name, s):
    db()["sessions"].update_one({"session_name": name}, {"$set": {"session_name": name, "session_str": s}}, upsert=True)

def get_session(name):
    d = db()["sessions"].find_one({"session_name": name})
    return d["session_str"] if d else None

def del_session(name):
    db()["sessions"].delete_one({"session_name": name})

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

    user = verify_init_data(init_data)
    if user is None:
        if DEV_NOAUTH:
            return {"id": OWNER_ID or "0", "name": "Dev", "role": "owner"}
        raise HTTPException(401, "Open this app from Telegram.")

    uid = str(user.get("id"))
    name = (user.get("first_name", "") + " " + user.get("last_name", "")).strip() or "User"
    if uid in user_list("banlist"):
        raise HTTPException(403, "You are banned.")
    if OWNER_ID and uid == OWNER_ID:
        return {"id": uid, "name": name, "role": "owner", "username": user.get("username", "")}
    if uid in user_list("whitelist"):
        return {"id": uid, "name": name, "role": "user", "username": user.get("username", "")}
    raise HTTPException(403, "no_access")

def require_owner(request: Request):
    u = current_user(request)
    if u["role"] != "owner":
        raise HTTPException(403, "Owner only.")
    return u

# ── Telethon helpers ─────────────────────────────────────────────
def get_client(acc):
    s = get_session(acc["session_name"])
    return TelegramClient(StringSession(s) if s else StringSession(), acc["api_id"], acc["api_hash"])

def parse_bot_link(link):
    m = re.match(r"https?://t\.me/([A-Za-z0-9_]+)(?:\?start=(.*))?", link.strip())
    return (m.group(1), m.group(2) or "") if m else (None, None)

def pick_accounts(names):
    accs = load_accounts()
    return accs if not names else [a for a in accs if a["session_name"] in names]

# ── Job system (background + live polling) ───────────────────────
JOBS = {}

def job_new(kind, total, meta=None):
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"id": jid, "kind": kind, "status": "running", "total": total,
                 "done": 0, "success": 0, "failed": 0, "results": [],
                 "meta": meta or {}, "started": int(time.time())}
    return jid

def job_push(jid, r):
    j = JOBS[jid]; j["results"].append(r); j["done"] += 1
    if r.get("status") == "success": j["success"] += 1
    else: j["failed"] += 1

def job_finish(jid):
    JOBS[jid]["status"] = "done"; JOBS[jid]["ended"] = int(time.time())
    try: db()["jobs"].insert_one(dict(JOBS[jid]))
    except Exception: pass

# ── Referral workers ─────────────────────────────────────────────
async def _captcha_flow(acc, bot_link, solver):
    client = get_client(acc)
    result = {"account": acc["session_name"], "status": "timeout", "msg": "No captcha response in 20s"}
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        solved = asyncio.Event()

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                r = await solver(event, client, bot_user)
                if r:
                    result.update(r); solved.set()
            except Exception as ex:
                result.update({"status": "error", "msg": str(ex)}); solved.set()

        await client.send_message(bot_user, f"/start {param}".strip())
        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
        save_session(acc["session_name"], client.session.save())
    except Exception as e:
        result.update({"status": "error", "msg": str(e)})
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

SOLVERS = {"no_captcha": None, "emoji": solve_emoji, "math": solve_math, "button": solve_button}

async def refer_plain(acc, bot_link):
    client = get_client(acc)
    try:
        await client.start()
        bot_user, param = parse_bot_link(bot_link)
        if not bot_user: return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        await client.send_message(bot_user, f"/start {param}".strip())
        await asyncio.sleep(2)
        save_session(acc["session_name"], client.session.save())
        return {"account": acc["session_name"], "status": "success", "msg": "Started"}
    except Exception as e:
        return {"account": acc["session_name"], "status": "error", "msg": str(e)}
    finally:
        try: await client.disconnect()
        except Exception: pass

async def run_refer_job(jid, accs, link, method, delay):
    for acc in accs:
        solver = SOLVERS.get(method)
        r = await (refer_plain(acc, link) if solver is None else _captcha_flow(acc, link, solver))
        job_push(jid, r)
        await asyncio.sleep(delay)
    job_finish(jid)

async def run_channel_job(jid, accs, channels, action):
    for acc in accs:
        client = get_client(acc); ok = 0; lines = []
        try:
            await client.start()
            for ch in channels:
                try:
                    if action == "join":
                        await client(JoinChannelRequest(ch))
                    else:
                        await client(LeaveChannelRequest(await client.get_entity(ch)))
                    ok += 1; lines.append(f"✓ {ch}")
                except Exception as e:
                    lines.append(f"✗ {ch}: {str(e)[:60]}")
                await asyncio.sleep(2)
            save_session(acc["session_name"], client.session.save())
            st = "success" if ok == len(channels) else ("partial" if ok else "error")
            job_push(jid, {"account": acc["session_name"], "status": st, "msg": f"{ok}/{len(channels)} · " + " · ".join(lines)})
        except Exception as e:
            job_push(jid, {"account": acc["session_name"], "status": "error", "msg": str(e)})
        finally:
            try: await client.disconnect()
            except Exception: pass
    job_finish(jid)

async def run_message_job(jid, accs, target, text):
    for acc in accs:
        client = get_client(acc)
        try:
            await client.start()
            await client.send_message(target, text)
            save_session(acc["session_name"], client.session.save())
            job_push(jid, {"account": acc["session_name"], "status": "success", "msg": "Sent"})
        except Exception as e:
            job_push(jid, {"account": acc["session_name"], "status": "error", "msg": str(e)})
        finally:
            try: await client.disconnect()
            except Exception: pass
        await asyncio.sleep(2)
    job_finish(jid)

# ── Pages ────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/app", response_class=HTMLResponse)
async def index():
    with open(INDEX_HTML, encoding="utf-8") as f:
        return f.read()

@app.get("/ping")
async def ping():
    return {"ping": "pong"}

# ── Auth ─────────────────────────────────────────────────────────
@app.get("/api/me")
async def me(request: Request):
    try:
        u = current_user(request)
    except HTTPException as e:
        if e.detail == "no_access":
            user = verify_init_data(request.headers.get("x-init-data", "")) or {}
            return JSONResponse({"role": "none", "id": str(user.get("id", "")), "name": user.get("first_name", "")}, 403)
        raise
    return {**u, "accounts": len(load_accounts())}

# ── Accounts ─────────────────────────────────────────────────────
@app.get("/api/accounts")
async def accounts(request: Request):
    current_user(request)
    out = []
    for a in load_accounts():
        p = a.get("phone", "")
        out.append({"session_name": a["session_name"], "api_id": a["api_id"],
                    "name": a.get("name", ""), "username": a.get("username", ""),
                    "phone": p[:4] + "•••" + p[-3:] if len(p) > 7 else p})
    return {"count": len(out), "accounts": out}

@app.post("/api/accounts/request-code")
async def request_code(request: Request):
    current_user(request)
    b = await request.json()
    name, api_id, api_hash, phone = creds(b)
    if not re.match(r"^\+\d{7,15}$", phone):
        return {"status": "error", "message": "Phone must start with + and country code"}
    if any(a["session_name"] == name for a in load_accounts()):
        return {"status": "error", "message": "This number is already added"}
    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()
    try:
        r = await client.send_code_request(phone)
        save_session(name + "_temp", client.session.save())
        return {"status": "code_sent", "phone_code_hash": r.phone_code_hash, "session_name": name, "phone": phone}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/api/accounts/verify-code")
async def verify_code(request: Request):
    current_user(request)
    b = await request.json()
    name, api_id, api_hash, phone = creds(b)
    b["phone"] = phone
    tmp = get_session(name + "_temp")
    client = TelegramClient(StringSession(tmp) if tmp else StringSession(), api_id, api_hash)
    await client.connect()
    try:
        await client.sign_in(phone=b["phone"], code=b["code"], phone_code_hash=b["phone_code_hash"])
        me_ = await client.get_me()
        save_session(name, client.session.save()); del_session(name + "_temp")
        save_account({"session_name": name, "api_id": api_id, "api_hash": api_hash, "phone": b["phone"],
                      "username": me_.username or "", "name": f"{me_.first_name or ''} {me_.last_name or ''}".strip()})
        return {"status": "success", "message": f"Logged in as {me_.first_name}"}
    except errors.SessionPasswordNeededError:
        save_session(name, client.session.save()); del_session(name + "_temp")
        save_account({"session_name": name, "api_id": api_id, "api_hash": api_hash, "phone": b["phone"], "username": "", "name": "pending 2FA"})
        return {"status": "2fa_needed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/api/accounts/verify-2fa")
async def verify_2fa(request: Request):
    current_user(request)
    b = await request.json()
    acc = next((a for a in load_accounts() if a["session_name"] == b["session_name"]), None)
    if not acc: return {"status": "error", "message": "Account not found"}
    client = get_client(acc); await client.connect()
    try:
        await client.sign_in(password=b["password"])
        me_ = await client.get_me()
        save_session(acc["session_name"], client.session.save())
        acc.update({"username": me_.username or "", "name": f"{me_.first_name or ''} {me_.last_name or ''}".strip()})
        save_account(acc)
        return {"status": "success", "message": f"Logged in as {me_.first_name}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.delete("/api/accounts/{name}")
async def delete_account(name: str, request: Request):
    current_user(request)
    delete_account_db(name)
    return {"status": "success"}

# ── Jobs ─────────────────────────────────────────────────────────
@app.post("/api/refer")
async def refer(request: Request):
    current_user(request)
    b = await request.json()
    accs = pick_accounts(b.get("accounts"))
    if not accs: raise HTTPException(400, "No accounts selected.")
    if not parse_bot_link(b.get("bot_link", ""))[0]: raise HTTPException(400, "Invalid bot link.")
    jid = job_new("refer", len(accs), {"link": b["bot_link"], "method": b.get("method", "no_captcha")})
    asyncio.create_task(run_refer_job(jid, accs, b["bot_link"], b.get("method", "no_captcha"), float(b.get("delay", 3))))
    return {"job_id": jid}

@app.post("/api/channels")
async def channels(request: Request):
    current_user(request)
    b = await request.json()
    accs = pick_accounts(b.get("accounts"))
    chans = [c.strip() for c in b.get("channels", []) if c.strip()]
    if not accs: raise HTTPException(400, "No accounts selected.")
    if not chans: raise HTTPException(400, "No channels given.")
    jid = job_new("channels", len(accs), {"action": b.get("action", "join"), "channels": chans})
    asyncio.create_task(run_channel_job(jid, accs, chans, b.get("action", "join")))
    return {"job_id": jid}

@app.post("/api/message")
async def message(request: Request):
    current_user(request)
    b = await request.json()
    accs = pick_accounts(b.get("accounts"))
    if not accs: raise HTTPException(400, "No accounts selected.")
    if not b.get("target") or not b.get("text"): raise HTTPException(400, "Target and message are required.")
    jid = job_new("message", len(accs), {"target": b["target"]})
    asyncio.create_task(run_message_job(jid, accs, b["target"], b["text"]))
    return {"job_id": jid}

@app.get("/api/jobs/{jid}")
async def job(jid: str, request: Request):
    current_user(request)
    j = JOBS.get(jid)
    if not j:
        d = db()["jobs"].find_one({"id": jid}, {"_id": 0})
        if not d: raise HTTPException(404, "Job not found (server may have restarted).")
        return d
    return j

@app.get("/api/jobs")
async def jobs(request: Request):
    current_user(request)
    live = sorted(JOBS.values(), key=lambda x: -x["started"])[:10]
    return {"jobs": [{k: v for k, v in j.items() if k != "results"} for j in live]}

# ── Admin (owner only) ───────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_users(request: Request):
    require_owner(request)
    return {"whitelist": list(db()["whitelist"].find({}, {"_id": 0})),
            "banlist": list(db()["banlist"].find({}, {"_id": 0}))}

@app.post("/api/admin/{kind}")
async def admin_add(kind: str, request: Request):
    require_owner(request)
    if kind not in ("whitelist", "banlist"): raise HTTPException(404)
    b = await request.json(); uid = str(b.get("user_id", "")).strip()
    if not uid.isdigit(): raise HTTPException(400, "User ID must be numbers only.")
    if uid == OWNER_ID: raise HTTPException(400, "That's you.")
    user_add(kind, uid, {"note": b.get("note", "")})
    if kind == "banlist": user_remove("whitelist", uid)
    return {"status": "success"}

@app.delete("/api/admin/{kind}/{uid}")
async def admin_remove(kind: str, uid: str, request: Request):
    require_owner(request)
    if kind not in ("whitelist", "banlist"): raise HTTPException(404)
    user_remove(kind, uid)
    return {"status": "success"}

# ── Run ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
