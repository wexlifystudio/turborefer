"""
Turbo Refer V2 - Backend API
FastAPI + Telethon | Render.com
"""

import os
import json
import asyncio
import re
import emoji as emoji_lib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
from telethon import TelegramClient, events, errors
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest

app = FastAPI()

API_SECRET   = os.getenv("API_SECRET", "changeme")
SESSIONS_DIR = "sessions"
ACCOUNTS_FILE = "accounts.json"

os.makedirs(SESSIONS_DIR, exist_ok=True)

# ── Helpers ──────────────────────────────────────────

def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    with open(ACCOUNTS_FILE) as f:
        return json.load(f)

def save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def check_auth(request: Request):
    secret = request.headers.get("x-api-secret", "")
    if secret != API_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

def get_client(acc):
    path = os.path.join(SESSIONS_DIR, acc["session_name"])
    return TelegramClient(path, acc["api_id"], acc["api_hash"])

def parse_bot_link(link):
    m = re.match(r"https://t\.me/([a-zA-Z0-9_]+)(\?start=(.*))?", link)
    if not m:
        return None, None
    return m.group(1), (m.group(3) or "")

def filter_accs(all_accs, names):
    if not names:
        return all_accs
    return [a for a in all_accs if a["session_name"] in names]

# ── Health ────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "running", "version": "2.1.2"}

@app.get("/ping")
async def ping():
    return {"ping": "pong"}

# ── Accounts ──────────────────────────────────────────

@app.get("/accounts")
async def list_accounts(request: Request):
    check_auth(request)
    accs = load_accounts()
    return {
        "count": len(accs),
        "accounts": [{"session_name": a["session_name"], "api_id": a["api_id"]} for a in accs]
    }

@app.post("/accounts/request-code")
async def request_code(request: Request):
    check_auth(request)
    body = await request.json()
    session_name = body["session_name"]
    api_id       = int(body["api_id"])
    api_hash     = body["api_hash"]
    phone        = body["phone"]

    path = os.path.join(SESSIONS_DIR, session_name)
    client = TelegramClient(path, api_id, api_hash)
    await client.connect()
    try:
        result = await client.send_code_request(phone)
        return {"status": "code_sent", "phone_code_hash": result.phone_code_hash}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/accounts/verify-code")
async def verify_code(request: Request):
    check_auth(request)
    body = await request.json()
    session_name    = body["session_name"]
    api_id          = int(body["api_id"])
    api_hash        = body["api_hash"]
    phone           = body["phone"]
    code            = body["code"]
    phone_code_hash = body["phone_code_hash"]

    path = os.path.join(SESSIONS_DIR, session_name)
    client = TelegramClient(path, api_id, api_hash)
    await client.connect()
    try:
        await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
        me = await client.get_me()
        accs = load_accounts()
        accs = [a for a in accs if a["session_name"] != session_name]
        accs.append({
            "session_name": session_name,
            "api_id": api_id,
            "api_hash": api_hash,
            "phone": phone,
            "username": me.username or "",
            "name": f"{me.first_name or ''} {me.last_name or ''}".strip()
        })
        save_accounts(accs)
        return {"status": "success", "message": f"Logged in as {me.first_name}"}
    except errors.SessionPasswordNeededError:
        # Save account as pending so 2FA can find it
        accs = load_accounts()
        accs = [a for a in accs if a["session_name"] != session_name]
        accs.append({
            "session_name": session_name,
            "api_id": api_id,
            "api_hash": api_hash,
            "phone": phone,
            "username": "",
            "name": "pending_2fa"
        })
        save_accounts(accs)
        return {"status": "2fa_needed", "message": "2FA required"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/accounts/verify-2fa")
async def verify_2fa(request: Request):
    check_auth(request)
    body = await request.json()
    session_name = body["session_name"]
    password     = body["password"]

    accs = load_accounts()
    acc = next((a for a in accs if a["session_name"] == session_name), None)
    if not acc:
        return {"status": "error", "message": "Account not found"}

    client = get_client(acc)
    await client.connect()
    try:
        await client.sign_in(password=password)
        me = await client.get_me()
        return {"status": "success", "message": f"2FA verified for {me.first_name}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.delete("/accounts/{session_name}")
async def delete_account(session_name: str, request: Request):
    check_auth(request)
    accs = load_accounts()
    accs = [a for a in accs if a["session_name"] != session_name]
    save_accounts(accs)
    sf = os.path.join(SESSIONS_DIR, session_name + ".session")
    if os.path.exists(sf):
        os.remove(sf)
    return {"status": "success", "message": f"Deleted {session_name}"}

# ── Referral ──────────────────────────────────────────

async def refer_no_captcha(acc, bot_link):
    client = get_client(acc)
    await client.start()
    try:
        bot_user, start_param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        msg = f"/start {start_param}" if start_param else "/start"
        await client.send_message(bot_user, msg)
        await asyncio.sleep(2)
        return {"account": acc["session_name"], "status": "success", "msg": "Referred"}
    except Exception as e:
        return {"account": acc["session_name"], "status": "error", "msg": str(e)}
    finally:
        await client.disconnect()

async def refer_emoji(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "timeout", "msg": "Timeout"}
    try:
        bot_user, start_param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        msg = f"/start {start_param}" if start_param else "/start"
        await client.send_message(bot_user, msg)
        solved = asyncio.Event()

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                if not event.buttons:
                    return
                raw = event.raw_text or ""
                emojis = [it["emoji"] for it in emoji_lib.emoji_list(raw)]
                if not emojis:
                    return
                for row in event.buttons:
                    for btn in row:
                        txt = getattr(btn, "text", "") or ""
                        for e in emojis:
                            if e in txt:
                                await btn.click()
                                result.update({"status": "success", "msg": f"Solved: {e}"})
                                solved.set()
                                return
            except Exception as ex:
                result.update({"status": "error", "msg": str(ex)})
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
    except Exception as e:
        result.update({"status": "error", "msg": str(e)})
    finally:
        await client.disconnect()
    return result

async def refer_math(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "timeout", "msg": "Timeout"}
    try:
        bot_user, start_param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        msg = f"/start {start_param}" if start_param else "/start"
        await client.send_message(bot_user, msg)
        solved = asyncio.Event()

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                raw = event.raw_text or ""
                m = re.search(r"(\d+)\s*([+\-*/×÷])\s*(\d+)", raw)
                if not m:
                    return
                a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                if op == "+":         ans = a + b
                elif op == "-":       ans = a - b
                elif op in ("*","×"): ans = a * b
                elif op in ("/","÷") and b != 0: ans = a // b
                else: return

                if event.buttons:
                    for row in event.buttons:
                        for btn in row:
                            if str(ans) in (getattr(btn, "text", "") or ""):
                                await btn.click()
                                result.update({"status": "success", "msg": f"Math: {a}{op}{b}={ans}"})
                                solved.set()
                                return
                await client.send_message(bot_user, str(ans))
                result.update({"status": "success", "msg": f"Sent: {ans}"})
                solved.set()
            except Exception as ex:
                result.update({"status": "error", "msg": str(ex)})
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
    except Exception as e:
        result.update({"status": "error", "msg": str(e)})
    finally:
        await client.disconnect()
    return result

async def refer_button(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "timeout", "msg": "Timeout"}
    try:
        bot_user, start_param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        msg = f"/start {start_param}" if start_param else "/start"
        await client.send_message(bot_user, msg)
        solved = asyncio.Event()

        @client.on(events.NewMessage(from_users=bot_user))
        async def handler(event):
            try:
                if not event.buttons:
                    return
                await event.buttons[0][0].click()
                result.update({"status": "success", "msg": "Button clicked"})
                solved.set()
            except Exception as ex:
                result.update({"status": "error", "msg": str(ex)})
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
    except Exception as e:
        result.update({"status": "error", "msg": str(e)})
    finally:
        await client.disconnect()
    return result

@app.post("/refer")
async def run_referral(request: Request):
    check_auth(request)
    body     = await request.json()
    bot_link = body["bot_link"]
    method   = body["method"]
    names    = body.get("accounts")

    all_accs = load_accounts()
    selected = filter_accs(all_accs, names)
    if not selected:
        return {"status": "error", "message": "No accounts"}

    results = []
    for acc in selected:
        if method == "no_captcha": r = await refer_no_captcha(acc, bot_link)
        elif method == "emoji":    r = await refer_emoji(acc, bot_link)
        elif method == "math":     r = await refer_math(acc, bot_link)
        elif method == "button":   r = await refer_button(acc, bot_link)
        else: r = {"account": acc["session_name"], "status": "error", "msg": "Unknown method"}
        results.append(r)
        await asyncio.sleep(3)

    success = sum(1 for r in results if r["status"] == "success")
    return {"status": "done", "total": len(results), "success": success,
            "failed": len(results) - success, "results": results}

# ── Join / Leave ──────────────────────────────────────

@app.post("/channels")
async def join_leave(request: Request):
    check_auth(request)
    body     = await request.json()
    channels = body["channels"]
    action   = body["action"]
    names    = body.get("accounts")

    all_accs = load_accounts()
    selected = filter_accs(all_accs, names)
    if not selected:
        return {"status": "error", "message": "No accounts"}

    results = []
    for acc in selected:
        client = get_client(acc)
        await client.start()
        ch_results = []
        try:
            for ch in channels:
                ch = ch.strip()
                try:
                    if action == "join":
                        await client(JoinChannelRequest(ch))
                        ch_results.append({"channel": ch, "status": "Joined"})
                    else:
                        entity = await client.get_entity(ch)
                        await client(LeaveChannelRequest(entity))
                        ch_results.append({"channel": ch, "status": "Left"})
                    await asyncio.sleep(2)
                except Exception as e:
                    ch_results.append({"channel": ch, "status": f"Error: {e}"})
        finally:
            await client.disconnect()
        results.append({"account": acc["session_name"], "channels": ch_results})

    return {"status": "done", "results": results}

# ── Send Message ──────────────────────────────────────

@app.post("/message")
async def send_message(request: Request):
    check_auth(request)
    body    = await request.json()
    target  = body["target"]
    message = body["message"]
    names   = body.get("accounts")

    all_accs = load_accounts()
    selected = filter_accs(all_accs, names)
    if not selected:
        return {"status": "error", "message": "No accounts"}

    results = []
    for acc in selected:
        client = get_client(acc)
        await client.start()
        try:
            await client.send_message(target, message)
            results.append({"account": acc["session_name"], "status": "Sent"})
        except Exception as e:
            results.append({"account": acc["session_name"], "status": f"Error: {e}"})
        finally:
            await client.disconnect()
        await asyncio.sleep(2)

    return {"status": "done", "results": results}

# ── Run ───────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
        
