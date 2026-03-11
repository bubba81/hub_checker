# HubChecker Dashboard — Vercel Deployment Guide
### hub-checker.vercel.app

---

## Step 1 — Get a free Neon Postgres database

1. Go to **https://neon.tech** and sign up (free)
2. Click **New Project** → name it `hubchecker`
3. Once created, go to **Dashboard → Connection Details**
4. Copy the **Connection string** — it looks like:
   ```
   postgresql://alex:AbcDef123@ep-cool-darkness-123456.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
5. Save this as your `DATABASE_URL`

The database tables are **created automatically** on first request — no manual SQL needed.

---

## Step 2 — Create a Discord OAuth App

1. Go to **https://discord.com/developers/applications**
2. Click **New Application** → name it `HubChecker`
3. Go to **OAuth2 → General**
4. Copy your **Client ID** and **Client Secret**
5. Under **Redirects**, add exactly:
   ```
   https://hub-checker.vercel.app/callback
   ```
6. Save changes

---

## Step 3 — Deploy to Vercel

### Option A: GitHub (recommended)

1. Push this folder to a GitHub repo
2. Go to **https://vercel.com** → **Add New Project** → import your repo
3. Vercel will auto-detect the `vercel.json` config
4. Under **Environment Variables**, add all variables from `.env.example`:

| Variable | Value |
|----------|-------|
| `SECRET_KEY` | Any random 32+ char string |
| `DISCORD_CLIENT_ID` | From Discord developer portal |
| `DISCORD_CLIENT_SECRET` | From Discord developer portal |
| `DISCORD_REDIRECT_URI` | `https://hub-checker.vercel.app/callback` |
| `ALLOWED_USER_IDS` | `1300155466193702974,1075384554120040559` |
| `DATABASE_URL` | Your Neon connection string |

5. Click **Deploy** — done!

### Option B: Vercel CLI

```bash
npm install -g vercel
cd hubchecker-vercel
vercel
# Follow prompts, then set env vars:
vercel env add SECRET_KEY
vercel env add DISCORD_CLIENT_ID
vercel env add DISCORD_CLIENT_SECRET
vercel env add DISCORD_REDIRECT_URI
vercel env add ALLOWED_USER_IDS
vercel env add DATABASE_URL
vercel --prod
```

---

## Step 4 — Add the C++ integration

Include `hubchecker_api.h` in `HubChecker_merged.cpp`. The URL is already set to `https://hub-checker.vercel.app`.

Add these 4 calls inside `main()`:

```cpp
#include "hubchecker_api.h"

int main() {
    // 1. Register the scan at startup
    DashboardStart(desktopNameStr, hostnameStr, usernameStr, osVersionStr);

    // 2. Before each scan phase (use phaseIndex 0-28, matching SCAN_PHASES in index.py)
    DashboardProgress(0, "Initializing", 2);
    // ... scan work ...
    DashboardProgress(1, "USN Journal Scan", 8, "Scanning journal...");
    // ... etc for each phase

    // 3. When a suspicious finding is detected
    DashboardFinding("Signature Alert", "alert",
        "[Prefetch] xeno.exe — Cheat Signature | Path: C:\\Users\\...");

    // 4. At the very end
    DashboardComplete();
}
```

---

## File Structure

```
hubchecker-vercel/
├── api/
│   └── index.py          ← Flask app (Vercel entrypoint)
├── templates/
│   ├── dashboard.html    ← Main dashboard
│   ├── view_scan.html    ← Scan detail / progress view
│   └── unauthorized.html ← Access denied page
├── hubchecker_api.h      ← C++ integration header
├── requirements.txt      ← Python dependencies
├── vercel.json           ← Vercel routing config
└── .env.example          ← Environment variable template
```

---

## Adding More Authorized Users

In Vercel dashboard → Settings → Environment Variables → edit `ALLOWED_USER_IDS`:
```
1300155466193702974,1075384554120040559,NEW_USER_ID_HERE
```
Then redeploy (or it takes effect on next cold start).

To find someone's Discord user ID: Enable Developer Mode in Discord settings, then right-click their name → Copy User ID.
