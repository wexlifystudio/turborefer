"""
╔══════════════════════════════════════════╗
║   TURBO REFER V2 - Backend API Server   ║
║   FastAPI + Telethon | For Render.com   ║
╚══════════════════════════════════════════╝
"""

import os
import json
import asyncio
import re
import emoji
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from telethon import TelegramClient, events, errors
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest
from telethon.tl.types import PeerChannel
import uvicorn

app = FastAPI(title="Turbo Refer Backend")

# ─── CONFIG (from environment variables) ────────────────────────
API_SECRET  = os.getenv("API_SECRET", "change_this_secret")   # TBC bot থেকে এই key পাঠাবে
SESSIONS_DIR = "sessions"
ACCOUNTS_FILE = "accounts.json"

os.makedirs(SESSIONS_DIR, exist_ok=True)

# ─── MODELS ─────────────────────────────────────────────────────

class AccountAdd(BaseModel):
    session_name: str
    api_id: int
    api_hash: str
    phone: str
    code: Optional[str] = None
    phone_code_hash: Optional[str] = None

class ReferRequest(BaseModel):
    bot_link: str
    method: str           # "no_captcha" | "emoji" | "math" | "button"
    accounts: Optional[List[str]] = None   # session names, None = all

class JoinLeaveRequest(BaseModel):
    channels: List[str]
    action: str           # "join" | "leave"
    accounts: Optional[List[str]] = None

class MessageRequest(BaseModel):
    target: str
    message: str
    accounts: Optional[List[str]] = None   # None = all

# ─── HELPERS ────────────────────────────────────────────────────

def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    with open(ACCOUNTS_FILE) as f:
        return json.load(f)

def save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def auth_check(x_api_secret: str):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

def get_client(acc: dict) -> TelegramClient:
    path = os.path.join(SESSIONS_DIR, acc["session_name"])
    return TelegramClient(path, acc["api_id"], acc["api_hash"])

def parse_bot_link(bot_link: str):
    match = re.match(r"https://t\.me/([a-zA-Z0-9_]+)(\?start=(.*))?", bot_link)
    if not match:
        return None, None
    return match.group(1), (match.group(3) or "")

def filter_accounts(all_accs, names):
    if not names:
        return all_accs
    return [a for a in all_accs if a["session_name"] in names]

# ─── HEALTH CHECK ───────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "🟢 Turbo Refer Backend Running", "version": "2.1.2"}

@app.get("/ping")
async def ping():
    return {"ping": "pong"}

# ─── ACCOUNTS ───────────────────────────────────────────────────

@app.get("/accounts")
async def list_accounts(x_api_secret: str = Header(...)):
    auth_check(x_api_secret)
    accs = load_accounts()
    return {
        "count": len(accs),
        "accounts": [{"session_name": a["session_name"], "api_id": a["api_id"]} for a in accs]
    }

@app.post("/accounts/request-code")
async def request_code(data: AccountAdd, x_api_secret: str = Header(...)):
    """Step 1: Phone number দিলে OTP পাঠাবে"""
    auth_check(x_api_secret)
    path = os.path.join(SESSIONS_DIR, data.session_name)
    client = TelegramClient(path, data.api_id, data.api_hash)
    await client.connect()
    try:
        result = await client.send_code_request(data.phone)
        return {
            "status": "code_sent",
            "phone_code_hash": result.phone_code_hash,
            "message": f"✅ OTP sent to {data.phone}"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/accounts/verify-code")
async def verify_code(data: AccountAdd, x_api_secret: str = Header(...)):
    """Step 2: OTP দিলে login সম্পন্ন করবে"""
    auth_check(x_api_secret)
    path = os.path.join(SESSIONS_DIR, data.session_name)
    client = TelegramClient(path, data.api_id, data.api_hash)
    await client.connect()
    try:
        await client.sign_in(
            phone=data.phone,
            code=data.code,
            phone_code_hash=data.phone_code_hash
        )
        me = await client.get_me()
        # Save account
        accs = load_accounts()
        accs = [a for a in accs if a["session_name"] != data.session_name]
        accs.append({
            "session_name": data.session_name,
            "api_id": data.api_id,
            "api_hash": data.api_hash,
            "phone": data.phone,
            "username": me.username or "",
            "name": f"{me.first_name or ''} {me.last_name or ''}".strip()
        })
        save_accounts(accs)
        return {
            "status": "success",
            "message": f"✅ Logged in as {me.first_name} (@{me.username})"
        }
    except errors.SessionPasswordNeededError:
        return {"status": "2fa_needed", "message": "⚠️ 2FA password required"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.post("/accounts/verify-2fa")
async def verify_2fa(
    session_name: str,
    password: str,
    x_api_secret: str = Header(...)
):
    """2FA password verify"""
    auth_check(x_api_secret)
    accs = load_accounts()
    acc = next((a for a in accs if a["session_name"] == session_name), None)
    if not acc:
        return {"status": "error", "message": "Account not found"}
    client = get_client(acc)
    await client.connect()
    try:
        await client.sign_in(password=password)
        me = await client.get_me()
        return {"status": "success", "message": f"✅ 2FA verified for {me.first_name}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        await client.disconnect()

@app.delete("/accounts/{session_name}")
async def delete_account(session_name: str, x_api_secret: str = Header(...)):
    auth_check(x_api_secret)
    accs = load_accounts()
    accs = [a for a in accs if a["session_name"] != session_name]
    save_accounts(accs)
    # Delete session file
    sf = os.path.join(SESSIONS_DIR, session_name + ".session")
    if os.path.exists(sf):
        os.remove(sf)
    return {"status": "success", "message": f"✅ Account '{session_name}' deleted"}

# ─── REFERRAL ───────────────────────────────────────────────────

async def do_refer_no_captcha(acc, bot_link):
    client = get_client(acc)
    await client.start()
    try:
        bot_user, start_param = parse_bot_link(bot_link)
        if not bot_user:
            return {"account": acc["session_name"], "status": "error", "msg": "Invalid link"}
        msg = f"/start {start_param}" if start_param else "/start"
        await client.send_message(bot_user, msg)
        await asyncio.sleep(2)
        return {"account": acc["session_name"], "status": "success", "msg": "✅ Referred"}
    except Exception as e:
        return {"account": acc["session_name"], "status": "error", "msg": str(e)}
    finally:
        await client.disconnect()

async def do_refer_emoji(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "pending", "msg": ""}
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
                target_emojis = [it["emoji"] for it in emoji.emoji_list(raw)]
                if not target_emojis:
                    return
                for row in event.buttons:
                    for button in row:
                        btn_text = getattr(button, "text", "") or ""
                        for e in target_emojis:
                            if e in btn_text:
                                await button.click()
                                result["status"] = "success"
                                result["msg"] = f"✅ Emoji captcha solved: {e}"
                                solved.set()
                                return
            except Exception as ex:
                result["status"] = "error"
                result["msg"] = str(ex)
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            result["status"] = "timeout"
            result["msg"] = "⚠️ Captcha timeout"

    except Exception as e:
        result["status"] = "error"
        result["msg"] = str(e)
    finally:
        await client.disconnect()
    return result

async def do_refer_math(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "pending", "msg": ""}
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
                # Math pattern detect: e.g. "2 + 3 = ?"
                match = re.search(r"(\d+)\s*([+\-*/×÷])\s*(\d+)\s*[=?]", raw)
                if match:
                    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
                    if op in ("+"):   ans = a + b
                    elif op in ("-"): ans = a - b
                    elif op in ("*", "×"): ans = a * b
                    elif op in ("/", "÷") and b != 0: ans = a // b
                    else: return

                    # Try buttons first
                    if event.buttons:
                        for row in event.buttons:
                            for btn in row:
                                if str(ans) in (getattr(btn, "text", "") or ""):
                                    await btn.click()
                                    result["status"] = "success"
                                    result["msg"] = f"✅ Math solved: {a}{op}{b}={ans}"
                                    solved.set()
                                    return
                    # Otherwise send as text
                    await client.send_message(bot_user, str(ans))
                    result["status"] = "success"
                    result["msg"] = f"✅ Math answered: {ans}"
                    solved.set()
            except Exception as ex:
                result["status"] = "error"
                result["msg"] = str(ex)
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            result["status"] = "timeout"
            result["msg"] = "⚠️ Math captcha timeout"

    except Exception as e:
        result["status"] = "error"
        result["msg"] = str(e)
    finally:
        await client.disconnect()
    return result

async def do_refer_button(acc, bot_link):
    client = get_client(acc)
    await client.start()
    result = {"account": acc["session_name"], "status": "pending", "msg": ""}
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
                # Click first available button
                await event.buttons[0][0].click()
                result["status"] = "success"
                result["msg"] = "✅ Button clicked"
                solved.set()
            except Exception as ex:
                result["status"] = "error"
                result["msg"] = str(ex)
                solved.set()

        try:
            await asyncio.wait_for(solved.wait(), timeout=20)
        except asyncio.TimeoutError:
            result["status"] = "timeout"
            result["msg"] = "⚠️ Button click timeout"

    except Exception as e:
        result["status"] = "error"
        result["msg"] = str(e)
    finally:
        await client.disconnect()
    return result

@app.post("/refer")
async def run_referral(data: ReferRequest, x_api_secret: str = Header(...)):
    auth_check(x_api_secret)
    all_accs = load_accounts()
    selected = filter_accounts(all_accs, data.accounts)
    if not selected:
        return {"status": "error", "message": "No accounts found"}

    results = []
    for acc in selected:
        if data.method == "no_captcha":
            r = await do_refer_no_captcha(acc, data.bot_link)
        elif data.method == "emoji":
            r = await do_refer_emoji(acc, data.bot_link)
        elif data.method == "math":
            r = await do_refer_math(acc, data.bot_link)
        elif data.method == "button":
            r = await do_refer_button(acc, data.bot_link)
        else:
            r = {"account": acc["session_name"], "status": "error", "msg": "Unknown method"}
        results.append(r)
        await asyncio.sleep(3)   # Anti-ban delay

    success = sum(1 for r in results if r["status"] == "success")
    return {
        "status": "done",
        "total": len(results),
        "success": success,
        "failed": len(results) - success,
        "results": results
    }

# ─── JOIN / LEAVE ───────────────────────────────────────────────

@app.post("/channels")
async def join_leave(data: JoinLeaveRequest, x_api_secret: str = Header(...)):
    auth_check(x_api_secret)
    all_accs = load_accounts()
    selected = filter_accounts(all_accs, data.accounts)
    if not selected:
        return {"status": "error", "message": "No accounts found"}

    results = []
    for acc in selected:
        client = get_client(acc)
        await client.start()
        acc_results = []
        try:
            for ch in data.channels:
                ch = ch.strip()
                try:
                    if data.action == "join":
                        await client(JoinChannelRequest(ch))
                        acc_results.append({"channel": ch, "status": "✅ Joined"})
                    elif data.action == "leave":
                        entity = await client.get_entity(ch)
                        await client(LeaveChannelRequest(entity))
                        acc_results.append({"channel": ch, "status": "✅ Left"})
                    await asyncio.sleep(2)
                except Exception as e:
                    acc_results.append({"channel": ch, "status": f"❌ {str(e)}"})
        finally:
            await client.disconnect()
        results.append({"account": acc["session_name"], "channels": acc_results})

    return {"status": "done", "results": results}

# ─── SEND MESSAGE ───────────────────────────────────────────────

@app.post("/message")
async def send_message(data: MessageRequest, x_api_secret: str = Header(...)):
    auth_check(x_api_secret)
    all_accs = load_accounts()
    selected = filter_accounts(all_accs, data.accounts)
    if not selected:
        return {"status": "error", "message": "No accounts found"}

    results = []
    for acc in selected:
        client = get_client(acc)
        await client.start()
        try:
            await client.send_message(data.target, data.message)
            results.append({"account": acc["session_name"], "status": "✅ Sent"})
        except Exception as e:
            results.append({"account": acc["session_name"], "status": f"❌ {str(e)}"})
        finally:
            await client.disconnect()
        await asyncio.sleep(2)

    return {"status": "done", "results": results}

# ─── RUN ────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
