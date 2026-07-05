Emerald Mail package

Files included:
- emerald-mail.html (updated full-screen frontend, no version label, Worker URL built in)
- emerald-mail-worker.js (current Resend + Firestore worker)
- emerald-mail-logo.png (Emerald Mail logo)

Worker URL built into frontend:
https://emerald-mail-router.wyatt-monroe2013.workers.dev

Do you need to edit the worker for this frontend?
No, not just for this UI update.
This frontend uses the same API endpoints as your current Resend worker.
If your current worker is already deployed and working, you only need to replace the frontend file and add the logo file.

If you want to use the included worker file anyway:
- It expects the same bindings, variables, and secrets as your current Resend Firestore worker.
- It is functionally the same backend style you were already using.

How to use:
1. Upload emerald-mail.html to your site/app.
2. Keep emerald-mail-logo.png in the same folder as emerald-mail.html.
3. If needed, deploy emerald-mail-worker.js to Cloudflare Workers.
