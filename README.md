# ⚡ Turbo Refer — Telegram Mini App

## Render Environment Variables
| Key | Value |
|-----|-------|
| BOT_TOKEN | Your bot token from @BotFather |
| OWNER_ID | Your Telegram user ID (numbers) |
| MONGO_URL | MongoDB Atlas connection string |
| API_SECRET | (optional) legacy secret for TBC access |
| DEFAULT_API_ID | (optional) override built-in API ID |
| DEFAULT_API_HASH | (optional) override built-in API hash |

Start command: `python main.py`

## Connect the app to your bot (BotFather)
1. `/mybots` → your bot → **Bot Settings** → **Menu Button** → **Configure menu button**
2. Send your Render URL: `https://turborefer.onrender.com`
3. Give it a title: `Open Turbo Refer`

## Endpoints
GET /api/me · GET/POST/DELETE /api/accounts · POST /api/refer · POST /api/channels · POST /api/message · GET /api/jobs/{id} · /api/admin/*
