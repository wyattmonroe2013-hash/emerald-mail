# Emerald Account Alpha 3.0 Architecture

Emerald Mail accounts remain in Firestore collection `EmeraldMail`.

Mail uses D1, R2, Resend, and Cloudflare Email Routing.

Drive uses D1 table `drive_files`, D1 table `drive_activity`, and R2 file objects.

Docs, Sheets, Forms, Media, Storage, and Admin are connected through the same Emerald Mail session.
