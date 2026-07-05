Emerald Mail Alpha 3.0 - Emerald Account Suite

This package turns Emerald Mail into an Emerald Account workspace.

Included services:
- Emerald Mail
- Emerald Drive
- Emerald Docs Online
- Emerald Sheets Online
- Emerald Forms Online
- Emerald Media Player Online
- Emerald Storage Online
- Emerald Admin Console

Backend:
- Uses the existing Emerald Mail Worker login/session system.
- Adds Drive/Storage APIs to the Worker.
- Drive metadata is stored in D1 table: drive_files.
- Drive file content is stored in the existing R2 binding: MAIL_RAW.
- Drive activity is stored in D1 table: drive_activity.

Deploy:
1. Upload the whole frontend folder to GitHub Pages.
2. Replace your Cloudflare Worker with worker/emerald-mail-worker.js.
3. Run:
   https://emerald-mail-router.wyatt-monroe2013.workers.dev/api/setup?admin_key=YOUR_ADMIN_KEY
4. Sign into index.html with an Emerald Mail account.

Required existing Worker bindings:
- DB
- MAIL_RAW

Required existing Worker variables/secrets:
- ALLOWED_DOMAIN
- FROM_NAME
- SESSION_DAYS
- FIREBASE_PROJECT_ID
- RESEND_API_KEY
- EMERALD_MAIL_ADMIN_KEY
- GOOGLE_CLIENT_EMAIL
- GOOGLE_PRIVATE_KEY
