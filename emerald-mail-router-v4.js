/*
EMERALD MAIL ROUTER v4
Receiving + inbox + compose + replies + attachments

Works with:
support@mail.monroecorp.org -> Cloudflare Email Routing -> Send to Worker

Required bindings:
DB       -> D1 database: emerald_mail
MAIL_RAW -> R2 bucket: emerald-mail-raw

Required variables/secrets:
ALLOWED_DOMAIN       = mail.monroecorp.org
EMERALD_MAIL_API_KEY = your private Emerald Mail key

Optional sending setup:
Option A: EMAIL binding named EMAIL
Option B: CF_ACCOUNT_ID variable + CF_EMAIL_API_TOKEN secret

Important:
For receiving, this Worker converts message.raw to ArrayBuffer before R2 storage.
That fixes: "Provided readable stream must have a known length".
*/

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const BASE_COLUMNS = [
  ["message_id", "TEXT"],
  ["in_reply_to", "TEXT"],
  ["references_header", "TEXT"],
  ["text_preview", "TEXT"],
  ["html_preview", "TEXT"],
  ["cc", "TEXT"],
  ["bcc", "TEXT"],
  ["attachments_json", "TEXT"]
];

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS
    }
  });
}

function normalize(value) {
  return String(value || "").trim();
}

function normalizeEmail(value) {
  return normalize(value).toLowerCase();
}

function safeKeyPart(value) {
  return String(value || "").replace(/[^a-zA-Z0-9@._-]/g, "_");
}

function getToken(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();

  const url = new URL(request.url);
  return url.searchParams.get("key") || "";
}

function isAuthorized(request, env) {
  return Boolean(env.EMERALD_MAIL_API_KEY && getToken(request) === env.EMERALD_MAIL_API_KEY);
}

function requireAuth(request, env) {
  if (!isAuthorized(request, env)) {
    return json({ ok: false, error: "Unauthorized" }, 401);
  }

  return null;
}

function getHeader(headers, name) {
  return headers.get(name) || headers.get(name.toLowerCase()) || headers.get(name.toUpperCase()) || "";
}

function getSubject(message) {
  return getHeader(message.headers, "Subject") || "(No subject)";
}

function validDomainEmail(email, allowedDomain) {
  return normalizeEmail(email).endsWith("@" + normalizeEmail(allowedDomain));
}

function splitRecipients(value) {
  if (Array.isArray(value)) {
    return value.map(normalize).filter(Boolean);
  }

  return String(value || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);
}

function makeMessageId(from) {
  const domain = String(from || "").split("@")[1] || "emerald.local";
  return `<${crypto.randomUUID()}@${domain}>`;
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .trim();
}

function previewText(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 300);
}

async function ensureSchema(env) {
  if (!env.DB) throw new Error("Missing D1 binding named DB.");

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS mail_messages (
      id TEXT PRIMARY KEY,
      mailbox TEXT NOT NULL,
      recipient TEXT NOT NULL,
      sender TEXT NOT NULL,
      subject TEXT,
      received_at TEXT NOT NULL,
      raw_r2_key TEXT NOT NULL,
      raw_size INTEGER DEFAULT 0,
      read INTEGER DEFAULT 0,
      starred INTEGER DEFAULT 0,
      folder TEXT DEFAULT 'inbox'
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_mailbox_received
    ON mail_messages (mailbox, received_at DESC)
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_folder
    ON mail_messages (mailbox, folder)
  `).run();

  const info = await env.DB.prepare(`PRAGMA table_info(mail_messages)`).all();
  const existing = new Set((info.results || []).map(col => col.name));

  for (const [name, type] of BASE_COLUMNS) {
    if (!existing.has(name)) {
      await env.DB.prepare(`ALTER TABLE mail_messages ADD COLUMN ${name} ${type}`).run();
    }
  }

  return true;
}

async function saveIncomingEmail(message, env) {
  await ensureSchema(env);

  const allowedDomain = normalizeEmail(env.ALLOWED_DOMAIN);
  const recipient = normalizeEmail(message.to);
  const sender = normalizeEmail(message.from);
  const subject = getSubject(message);

  console.log("Emerald Mail incoming:", {
    from: sender,
    to: recipient,
    subject,
    allowedDomain
  });

  if (!allowedDomain) {
    throw new Error("Missing ALLOWED_DOMAIN variable.");
  }

  if (!recipient.endsWith("@" + allowedDomain)) {
    message.setReject("Emerald Mail does not accept this recipient domain.");
    return;
  }

  if (!env.MAIL_RAW) {
    throw new Error("Missing R2 binding named MAIL_RAW.");
  }

  const id = crypto.randomUUID();
  const receivedAt = new Date().toISOString();
  const rawKey = `raw/${safeKeyPart(recipient)}/${receivedAt.replace(/[:.]/g, "-")}-${id}.eml`;

  const messageId = getHeader(message.headers, "Message-ID");
  const inReplyTo = getHeader(message.headers, "In-Reply-To");
  const referencesHeader = getHeader(message.headers, "References");

  const rawEmailBuffer = await new Response(message.raw).arrayBuffer();

  await env.MAIL_RAW.put(rawKey, rawEmailBuffer, {
    httpMetadata: {
      contentType: "message/rfc822"
    },
    customMetadata: {
      recipient,
      sender,
      subject
    }
  });

  console.log("Emerald Mail saved to R2:", rawKey);

  await env.DB.prepare(`
    INSERT INTO mail_messages
    (
      id,
      mailbox,
      recipient,
      sender,
      subject,
      received_at,
      raw_r2_key,
      raw_size,
      read,
      starred,
      folder,
      message_id,
      in_reply_to,
      references_header,
      text_preview,
      html_preview,
      cc,
      bcc,
      attachments_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'inbox', ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    recipient,
    recipient,
    sender,
    subject,
    receivedAt,
    rawKey,
    rawEmailBuffer.byteLength,
    messageId,
    inReplyTo,
    referencesHeader,
    "",
    "",
    "",
    "",
    "[]"
  ).run();

  console.log("Emerald Mail saved to D1:", id);
}

async function listMessages(request, env) {
  await ensureSchema(env);

  const url = new URL(request.url);
  const mailbox = normalizeEmail(url.searchParams.get("mailbox"));
  const folder = normalize(url.searchParams.get("folder") || "inbox");

  if (!mailbox) {
    return json({ ok: false, error: "Missing mailbox." }, 400);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      mailbox,
      recipient,
      sender,
      subject,
      received_at,
      raw_size,
      read,
      starred,
      folder,
      message_id,
      in_reply_to,
      references_header,
      text_preview,
      html_preview,
      cc,
      bcc,
      attachments_json
    FROM mail_messages
    WHERE mailbox = ? AND folder = ?
    ORDER BY received_at DESC
    LIMIT 150
  `).bind(mailbox, folder).all();

  return json({
    ok: true,
    mailbox,
    folder,
    messages: result.results || []
  });
}

async function getRawMessage(request, env) {
  await ensureSchema(env);

  const url = new URL(request.url);
  const id = normalize(url.searchParams.get("id"));

  if (!id) {
    return json({ ok: false, error: "Missing message id." }, 400);
  }

  const row = await env.DB.prepare(`
    SELECT raw_r2_key
    FROM mail_messages
    WHERE id = ?
  `).bind(id).first();

  if (!row) {
    return json({ ok: false, error: "Message not found in D1." }, 404);
  }

  const object = await env.MAIL_RAW.get(row.raw_r2_key);

  if (!object) {
    return json({ ok: false, error: "Raw email not found in R2." }, 404);
  }

  return new Response(object.body, {
    headers: {
      "Content-Type": "message/rfc822",
      ...CORS_HEADERS
    }
  });
}

async function markRead(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const id = normalize(body.id);

  if (!id) {
    return json({ ok: false, error: "Missing message id." }, 400);
  }

  await env.DB.prepare(`
    UPDATE mail_messages
    SET read = 1
    WHERE id = ?
  `).bind(id).run();

  return json({ ok: true });
}

async function moveToTrash(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const id = normalize(body.id);

  if (!id) {
    return json({ ok: false, error: "Missing message id." }, 400);
  }

  await env.DB.prepare(`
    UPDATE mail_messages
    SET folder = 'trash'
    WHERE id = ?
  `).bind(id).run();

  return json({ ok: true });
}

function buildRawSentEmail({ from, to, cc, bcc, subject, text, html, headers, messageId }) {
  const lines = [];

  lines.push(`Message-ID: ${messageId}`);
  lines.push(`From: ${from}`);
  lines.push(`To: ${Array.isArray(to) ? to.join(", ") : to}`);
  if (cc && splitRecipients(cc).length) lines.push(`Cc: ${Array.isArray(cc) ? cc.join(", ") : cc}`);
  if (bcc && splitRecipients(bcc).length) lines.push(`Bcc: ${Array.isArray(bcc) ? bcc.join(", ") : bcc}`);
  lines.push(`Subject: ${subject}`);
  lines.push(`Date: ${new Date().toUTCString()}`);

  for (const [key, value] of Object.entries(headers || {})) {
    if (value) lines.push(`${key}: ${value}`);
  }

  lines.push("MIME-Version: 1.0");

  if (html) {
    lines.push(`Content-Type: text/html; charset="UTF-8"`);
    lines.push("");
    lines.push(html);
  } else {
    lines.push(`Content-Type: text/plain; charset="UTF-8"`);
    lines.push("");
    lines.push(text || "");
  }

  return lines.join("\r\n");
}

async function storeSentMessage(env, payload, sendResult) {
  await ensureSchema(env);

  const id = crypto.randomUUID();
  const receivedAt = new Date().toISOString();
  const from = normalizeEmail(payload.from);
  const toString = splitRecipients(payload.to).join(", ");
  const ccString = splitRecipients(payload.cc).join(", ");
  const bccString = splitRecipients(payload.bcc).join(", ");
  const messageId =
    sendResult?.messageId ||
    sendResult?.result?.messageId ||
    payload.headers?.["Message-ID"] ||
    makeMessageId(from);

  const raw = buildRawSentEmail({
    from,
    to: toString,
    cc: ccString,
    bcc: bccString,
    subject: payload.subject,
    text: payload.text,
    html: payload.html,
    headers: payload.headers || {},
    messageId
  });

  const rawKey = `sent/${safeKeyPart(from)}/${receivedAt.replace(/[:.]/g, "-")}-${id}.eml`;
  const rawBuffer = new TextEncoder().encode(raw);

  await env.MAIL_RAW.put(rawKey, rawBuffer, {
    httpMetadata: {
      contentType: "message/rfc822"
    },
    customMetadata: {
      sender: from,
      recipient: toString,
      subject: payload.subject || "(No subject)"
    }
  });

  await env.DB.prepare(`
    INSERT INTO mail_messages
    (
      id,
      mailbox,
      recipient,
      sender,
      subject,
      received_at,
      raw_r2_key,
      raw_size,
      read,
      starred,
      folder,
      message_id,
      in_reply_to,
      references_header,
      text_preview,
      html_preview,
      cc,
      bcc,
      attachments_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'sent', ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    from,
    toString,
    from,
    payload.subject || "(No subject)",
    receivedAt,
    rawKey,
    rawBuffer.byteLength,
    messageId,
    payload.headers?.["In-Reply-To"] || "",
    payload.headers?.["References"] || "",
    previewText(payload.text || stripHtml(payload.html || "")),
    payload.html || "",
    ccString,
    bccString,
    JSON.stringify(payload.attachments || [])
  ).run();

  return { id, messageId };
}

async function sendEmail(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const allowedDomain = normalizeEmail(env.ALLOWED_DOMAIN);

  const from = normalizeEmail(body.from);
  const to = splitRecipients(body.to);
  const cc = splitRecipients(body.cc);
  const bcc = splitRecipients(body.bcc);
  const subject = normalize(body.subject);
  const text = String(body.text || "");
  const html = String(body.html || "");
  const headers = body.headers && typeof body.headers === "object" ? body.headers : {};
  const attachments = Array.isArray(body.attachments) ? body.attachments : [];

  if (!from || !to.length || !subject || (!text && !html)) {
    return json({
      ok: false,
      error: "Missing from, to, subject, or message body."
    }, 400);
  }

  if (!validDomainEmail(from, allowedDomain)) {
    return json({
      ok: false,
      error: "Sender must use @" + allowedDomain
    }, 400);
  }

  const messageId = headers["Message-ID"] || makeMessageId(from);

  const payload = {
    from,
    to,
    subject,
    headers: {
      ...headers,
      "Message-ID": messageId
    }
  };

  if (text) payload.text = text;
  if (html) payload.html = html;
  if (cc.length) payload.cc = cc;
  if (bcc.length) payload.bcc = bcc;
  if (attachments.length) payload.attachments = attachments;

  let sendResult = null;

  if (env.EMAIL && typeof env.EMAIL.send === "function") {
    sendResult = await env.EMAIL.send(payload);
  } else {
    if (!env.CF_ACCOUNT_ID || !env.CF_EMAIL_API_TOKEN) {
      return json({
        ok: false,
        error: "Email Sending is not configured. Add an EMAIL binding, or add CF_ACCOUNT_ID and CF_EMAIL_API_TOKEN."
      }, 501);
    }

    const response = await fetch(
      "https://api.cloudflare.com/client/v4/accounts/" +
      env.CF_ACCOUNT_ID +
      "/email/sending/send",
      {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + env.CF_EMAIL_API_TOKEN,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }
    );

    sendResult = await response.json().catch(() => ({}));

    if (!response.ok || sendResult.success === false) {
      return json({
        ok: false,
        error: "Cloudflare Email Sending failed.",
        details: sendResult.errors || sendResult
      }, 500);
    }
  }

  const stored = await storeSentMessage(env, { ...payload, text, html, attachments }, sendResult || { messageId });

  return json({
    ok: true,
    messageId: stored.messageId,
    storedId: stored.id
  });
}

async function debugLatest(env) {
  await ensureSchema(env);

  const result = await env.DB.prepare(`
    SELECT id, mailbox, recipient, sender, subject, received_at, raw_r2_key, folder, message_id
    FROM mail_messages
    ORDER BY received_at DESC
    LIMIT 20
  `).all();

  return json({
    ok: true,
    messages: result.results || []
  });
}

async function debugD1Test(env) {
  await ensureSchema(env);

  const id = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO mail_messages
    (
      id,
      mailbox,
      recipient,
      sender,
      subject,
      received_at,
      raw_r2_key,
      raw_size,
      read,
      starred,
      folder,
      message_id,
      in_reply_to,
      references_header,
      text_preview,
      html_preview,
      cc,
      bcc,
      attachments_json
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'inbox', ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    "support@mail.monroecorp.org",
    "support@mail.monroecorp.org",
    "debug@example.com",
    "Emerald Mail D1 test",
    new Date().toISOString(),
    "debug/no-r2-object.eml",
    0,
    makeMessageId("debug@example.com"),
    "",
    "",
    "D1 test preview",
    "",
    "",
    "",
    "[]"
  ).run();

  return json({
    ok: true,
    inserted: id
  });
}

async function debugR2Test(env) {
  const key = `debug/${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;

  await env.MAIL_RAW.put(
    key,
    "Emerald Mail R2 test created at " + new Date().toISOString(),
    {
      httpMetadata: {
        contentType: "text/plain"
      }
    }
  );

  return json({
    ok: true,
    key
  });
}

export default {
  async email(message, env, ctx) {
    try {
      await saveIncomingEmail(message, env);
    } catch (error) {
      console.error("Emerald Mail email handler failed:", {
        message: error && error.message,
        stack: error && error.stack
      });

      throw error;
    }
  },

  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return json({ ok: true });
    }

    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/api/health") {
      return json({
        ok: true,
        service: "Emerald Mail Router v4",
        allowedDomain: env.ALLOWED_DOMAIN || null,
        hasDBBinding: Boolean(env.DB),
        hasR2Binding: Boolean(env.MAIL_RAW),
        hasApiKeySecret: Boolean(env.EMERALD_MAIL_API_KEY),
        hasEmailSendBinding: Boolean(env.EMAIL),
        hasRestSendingVars: Boolean(env.CF_ACCOUNT_ID && env.CF_EMAIL_API_TOKEN),
        time: new Date().toISOString()
      });
    }

    const authError = requireAuth(request, env);
    if (authError) return authError;

    try {
      if (url.pathname === "/api/setup" && request.method === "GET") {
        await ensureSchema(env);
        return json({ ok: true, message: "Schema checked and upgraded." });
      }

      if (url.pathname === "/api/messages" && request.method === "GET") {
        return await listMessages(request, env);
      }

      if (url.pathname === "/api/message/raw" && request.method === "GET") {
        return await getRawMessage(request, env);
      }

      if (url.pathname === "/api/message/read" && request.method === "POST") {
        return await markRead(request, env);
      }

      if (url.pathname === "/api/message/delete" && request.method === "POST") {
        return await moveToTrash(request, env);
      }

      if (url.pathname === "/api/send" && request.method === "POST") {
        return await sendEmail(request, env);
      }

      if (url.pathname === "/api/debug/latest" && request.method === "GET") {
        return await debugLatest(env);
      }

      if (url.pathname === "/api/debug/d1-test" && request.method === "GET") {
        return await debugD1Test(env);
      }

      if (url.pathname === "/api/debug/r2-test" && request.method === "GET") {
        return await debugR2Test(env);
      }

      return json({
        ok: false,
        error: "Endpoint not found.",
        endpoints: [
          "GET /api/health",
          "GET /api/setup?key=API_KEY",
          "GET /api/messages?mailbox=support@mail.monroecorp.org&folder=inbox",
          "GET /api/message/raw?id=MESSAGE_ID",
          "POST /api/message/read",
          "POST /api/message/delete",
          "POST /api/send",
          "GET /api/debug/latest?key=API_KEY",
          "GET /api/debug/d1-test?key=API_KEY",
          "GET /api/debug/r2-test?key=API_KEY"
        ]
      }, 404);
    } catch (error) {
      console.error("Emerald Mail fetch failed:", {
        message: error && error.message,
        stack: error && error.stack
      });

      return json({
        ok: false,
        error: error && error.message ? error.message : "Worker error."
      }, 500);
    }
  }
};
