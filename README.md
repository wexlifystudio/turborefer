# ⚡ Turbo Refer V2 — Backend API

Telegram Auto-Refer System Backend for Render.com

## 🚀 Deploy to Render

1. Upload this folder to GitHub
2. Connect GitHub repo to Render
3. Set environment variables:
   - `API_SECRET` = your secret key (same as TBC bot)
4. Deploy as **Web Service**

## 📋 Environment Variables

| Key | Value |
|-----|-------|
| `API_SECRET` | any secret string |
| `PORT` | 8000 (auto-set by Render) |

## 🔗 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/ping` | GET | Ping check |
| `/accounts` | GET | List accounts |
| `/accounts/request-code` | POST | Send OTP |
| `/accounts/verify-code` | POST | Verify OTP |
| `/accounts/{name}` | DELETE | Delete account |
| `/refer` | POST | Run referral |
| `/channels` | POST | Join/Leave channels |
| `/message` | POST | Send message |
