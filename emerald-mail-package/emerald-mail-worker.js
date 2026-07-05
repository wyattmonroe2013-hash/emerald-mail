/*
=========================================================
EMERALD MAIL V6 FIRESTORE AUTH WORKER
Cloudflare Worker + Email Routing + D1 + R2 + Resend + Firestore

What this version does:
- Stores Emerald Mail account records in Firestore collection: EmeraldMail
- Stores account passwords as plain SHA-256 hashes in Firestore field: passwordHash
- Uses Cloudflare D1 for sessions, login audit, and mail message index
- Uses Cloudflare R2 for raw .eml files
- Uses Resend for outbound sending
- Uses Cloudflare Email Routing for inbound receiving

Recommended mailbox examples:
support@mail.monroecorp.org
admin@mail.monroecorp.org
security@mail.monroecorp.org

Required Cloudflare bindings:
DB       -> D1 database: emerald_mail
MAIL_RAW -> R2 bucket: emerald-mail-raw

Required Worker variables:
ALLOWED_DOMAIN     = mail.monroecorp.org
FROM_NAME          = Emerald Mail
SESSION_DAYS       = 7
FIREBASE_PROJECT_ID = your Firebase/Google Cloud project ID

Required Worker secrets:
RESEND_API_KEY          = your Resend API key
EMERALD_MAIL_ADMIN_KEY  = your private V6 admin key
GOOGLE_CLIENT_EMAIL     = service account client_email
GOOGLE_PRIVATE_KEY      = service account private_key

Firestore collection:
EmeraldMail

Firestore document ID:
lowercase email address, for example:
support@mail.monroecorp.org

Firestore account fields:
address
displayName
fromName
signature
passwordHash
enabled
canSend
canReceive
isAdmin
createdAt
updatedAt

Important:
You requested SHA-256 hashes in Firestore. This Worker follows that.
For stronger production security later, upgrade passwordHash to salted PBKDF2/Argon2.
=========================================================
*/

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Authorization, Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const FIRESTORE_COLLECTION = "EmeraldMail";

const MESSAGE_EXTRA_COLUMNS = [
  ["message_id", "TEXT"],
  ["in_reply_to", "TEXT"],
  ["references_header", "TEXT"],
  ["text_preview", "TEXT"],
  ["html_preview", "TEXT"],
  ["cc", "TEXT"],
  ["bcc", "TEXT"],
  ["attachments_json", "TEXT"],
  ["provider", "TEXT"],
  ["provider_message_id", "TEXT"]
];

let GOOGLE_TOKEN_CACHE = {
  accessToken: "",
  expiresAtMs: 0
};

/* =========================================================
   BASIC HELPERS
========================================================= */

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

function nowIso() {
  return new Date().toISOString();
}

function addDaysIso(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function getSessionDays(env) {
  const value = Number(env.SESSION_DAYS || 7);
  return Number.isFinite(value) && value > 0 ? value : 7;
}

function splitRecipients(value) {
  if (Array.isArray(value)) {
    return value.map(normalize).filter(Boolean);
  }

  return String(value || "")
    .split(",")
    .map(part => part.trim())
    .filter(Boolean);
}

function validDomainEmail(email, allowedDomain) {
  return normalizeEmail(email).endsWith("@" + normalizeEmail(allowedDomain));
}

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || "";

  if (auth.startsWith("Bearer ")) {
    return auth.slice("Bearer ".length).trim();
  }

  return "";
}

function getAdminKey(request) {
  const url = new URL(request.url);
  const auth = request.headers.get("Authorization") || "";

  if (auth.startsWith("Admin ")) {
    return auth.slice("Admin ".length).trim();
  }

  return (
    url.searchParams.get("admin_key") ||
    url.searchParams.get("key") ||
    ""
  );
}

function requireAdmin(request, env) {
  if (!env.EMERALD_MAIL_ADMIN_KEY) {
    return json({
      ok: false,
      error: "Missing EMERALD_MAIL_ADMIN_KEY secret."
    }, 500);
  }

  if (getAdminKey(request) !== env.EMERALD_MAIL_ADMIN_KEY) {
    return json({
      ok: false,
      error: "Unauthorized admin request."
    }, 401);
  }

  return null;
}

function getHeader(headers, name) {
  return (
    headers.get(name) ||
    headers.get(name.toLowerCase()) ||
    headers.get(name.toUpperCase()) ||
    ""
  );
}

function getSubject(message) {
  return getHeader(message.headers, "Subject") || "(No subject)";
}

function makeMessageId(from) {
  const domain = String(from || "").split("@")[1] || "emerald.local";
  return `<${crypto.randomUUID()}@${domain}>`;
}

function previewText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 300);
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

function encodeHeaderValue(value) {
  return String(value || "").replace(/\r/g, "").replace(/\n/g, "");
}

/* =========================================================
   CRYPTO HELPERS
========================================================= */

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  const array = new Uint8Array(bytes);

  for (let i = 0; i < array.length; i++) {
    binary += String.fromCharCode(array[i]);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlEncodeText(value) {
  return bytesToBase64Url(new TextEncoder().encode(String(value || "")));
}

function randomBase64Url(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value || ""));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(hash);
}

async function sha256Base64Url(value) {
  const data = new TextEncoder().encode(String(value || ""));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToBase64Url(hash);
}

function constantTimeEqual(a, b) {
  const left = String(a || "");
  const right = String(b || "");

  if (left.length !== right.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < left.length; i++) {
    result |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }

  return result === 0;
}

/* =========================================================
   GOOGLE SERVICE ACCOUNT / FIRESTORE REST
========================================================= */

function pemToArrayBuffer(pem) {
  /*
    Accepts any of these common Cloudflare secret paste formats:

    1. Clean PEM:
       -----BEGIN PRIVATE KEY-----
       ...
       -----END PRIVATE KEY-----

    2. JSON escaped PEM:
       -----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n

    3. Quoted JSON field value:
       "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

    4. Accidentally pasted whole service account JSON.
       In that case, this extracts the private_key field.
  */
  let value = String(pem || "").trim();

  if (!value) {
    throw new Error("GOOGLE_PRIVATE_KEY is empty.");
  }

  // If the whole service account JSON was pasted, extract private_key.
  if (value.startsWith("{")) {
    try {
      const parsed = JSON.parse(value);
      if (parsed.private_key) {
        value = String(parsed.private_key);
      }
    } catch {
      const match = value.match(/"private_key"\s*:\s*"([\s\S]*?)"\s*,\s*"client_email"/);
      if (match && match[1]) {
        value = match[1];
      }
    }
  }

  // If only the quoted private_key JSON value was pasted, remove wrapping quotes.
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  // Remove a trailing comma if copied from JSON.
  value = value.replace(/,\s*$/, "");

  // Convert escaped newlines from JSON into real newlines.
  value = value.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n");

  // If quotes remain after removing a trailing comma, remove them again.
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  // Extract the body between PEM markers.
  const pemMatch = value.match(
    /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/
  );

  if (!pemMatch) {
    throw new Error(
      "GOOGLE_PRIVATE_KEY must include -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----."
    );
  }

  const base64 = pemMatch[1].replace(/[^A-Za-z0-9+/=]/g, "");

  if (!base64) {
    throw new Error("GOOGLE_PRIVATE_KEY base64 body is empty.");
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

async function signJwtRS256(unsignedJwt, privateKeyPem) {
  const keyData = pemToArrayBuffer(privateKeyPem);

  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsignedJwt)
  );

  return bytesToBase64Url(signature);
}

async function getGoogleAccessToken(env) {
  if (GOOGLE_TOKEN_CACHE.accessToken && GOOGLE_TOKEN_CACHE.expiresAtMs > Date.now() + 60000) {
    return GOOGLE_TOKEN_CACHE.accessToken;
  }

  if (!env.GOOGLE_CLIENT_EMAIL || !env.GOOGLE_PRIVATE_KEY) {
    throw new Error("Missing GOOGLE_CLIENT_EMAIL or GOOGLE_PRIVATE_KEY secret.");
  }

  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const claim = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };

  const unsignedJwt =
    base64UrlEncodeText(JSON.stringify(header)) +
    "." +
    base64UrlEncodeText(JSON.stringify(claim));

  const signedJwt = unsignedJwt + "." + await signJwtRS256(unsignedJwt, env.GOOGLE_PRIVATE_KEY);

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body:
      "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" +
      "&assertion=" +
      encodeURIComponent(signedJwt)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.access_token) {
    throw new Error("Google OAuth token request failed: " + JSON.stringify(data));
  }

  GOOGLE_TOKEN_CACHE = {
    accessToken: data.access_token,
    expiresAtMs: Date.now() + (Number(data.expires_in || 3600) * 1000)
  };

  return data.access_token;
}

function firestoreDocPath(env, address = "") {
  if (!env.FIREBASE_PROJECT_ID) {
    throw new Error("Missing FIREBASE_PROJECT_ID variable.");
  }

  const base =
    `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}` +
    `/databases/(default)/documents/${FIRESTORE_COLLECTION}`;

  if (!address) return base;

  return base + "/" + encodeURIComponent(normalizeEmail(address));
}

function firestoreValue(value) {
  if (typeof value === "boolean") {
    return { booleanValue: value };
  }

  if (typeof value === "number") {
    return { integerValue: String(Math.trunc(value)) };
  }

  if (value instanceof Date) {
    return { timestampValue: value.toISOString() };
  }

  return { stringValue: String(value ?? "") };
}

function jsToFirestoreDocument(data) {
  const fields = {};

  for (const [key, value] of Object.entries(data)) {
    fields[key] = firestoreValue(value);
  }

  return { fields };
}

function readFirestoreField(fields, key, fallback = "") {
  const field = fields?.[key];

  if (!field) return fallback;
  if ("stringValue" in field) return field.stringValue;
  if ("booleanValue" in field) return field.booleanValue;
  if ("integerValue" in field) return Number(field.integerValue);
  if ("doubleValue" in field) return Number(field.doubleValue);
  if ("timestampValue" in field) return field.timestampValue;
  if ("nullValue" in field) return null;

  return fallback;
}

function firestoreDocToAccount(doc) {
  if (!doc || !doc.fields) return null;

  const f = doc.fields;

  const account = {
    id: doc.name ? doc.name.split("/").pop() : normalizeEmail(readFirestoreField(f, "address", "")),
    address: normalizeEmail(readFirestoreField(f, "address", "")),
    display_name: readFirestoreField(f, "displayName", readFirestoreField(f, "display_name", "")),
    from_name: readFirestoreField(f, "fromName", readFirestoreField(f, "from_name", "")),
    signature: readFirestoreField(f, "signature", ""),
    password_hash: String(
      readFirestoreField(f, "passwordHash", readFirestoreField(f, "password_hash", ""))
    ).toLowerCase(),
    enabled: readFirestoreField(f, "enabled", true) !== false,
    can_send: readFirestoreField(f, "canSend", readFirestoreField(f, "can_send", true)) !== false,
    can_receive: readFirestoreField(f, "canReceive", readFirestoreField(f, "can_receive", true)) !== false,
    is_admin: readFirestoreField(f, "isAdmin", readFirestoreField(f, "is_admin", false)) === true,
    created_at: readFirestoreField(f, "createdAt", readFirestoreField(f, "created_at", "")),
    updated_at: readFirestoreField(f, "updatedAt", readFirestoreField(f, "updated_at", ""))
  };

  if (!account.display_name) account.display_name = account.address;
  if (!account.from_name) account.from_name = account.display_name || "Emerald Mail";

  return account;
}

function accountToFirestoreData(account) {
  return {
    address: normalizeEmail(account.address),
    displayName: account.display_name || account.displayName || normalizeEmail(account.address),
    fromName: account.from_name || account.fromName || account.display_name || account.displayName || "Emerald Mail",
    signature: account.signature || "",
    passwordHash: String(account.password_hash || account.passwordHash || "").toLowerCase(),
    enabled: account.enabled !== false,
    canSend: account.can_send !== false && account.canSend !== false,
    canReceive: account.can_receive !== false && account.canReceive !== false,
    isAdmin: account.is_admin === true || account.isAdmin === true,
    createdAt: account.created_at || account.createdAt || nowIso(),
    updatedAt: nowIso()
  };
}

async function firestoreFetch(env, url, options = {}) {
  const token = await getGoogleAccessToken(env);

  const response = await fetch(url, {
    ...options,
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  return {
    response,
    data
  };
}

async function getAccount(env, address) {
  const url = firestoreDocPath(env, address);
  const { response, data } = await firestoreFetch(env, url);

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error("Firestore account lookup failed: " + JSON.stringify(data));
  }

  return firestoreDocToAccount(data);
}

async function getActiveAccount(env, address) {
  const account = await getAccount(env, address);

  if (!account || !account.enabled) {
    return null;
  }

  return account;
}

async function writeAccount(env, account) {
  const address = normalizeEmail(account.address);
  const url = firestoreDocPath(env, address);
  const data = accountToFirestoreData(account);

  const result = await firestoreFetch(env, url, {
    method: "PATCH",
    body: JSON.stringify(jsToFirestoreDocument(data))
  });

  if (!result.response.ok) {
    throw new Error("Firestore account write failed: " + JSON.stringify(result.data));
  }

  return firestoreDocToAccount(result.data);
}

async function listAccounts(env) {
  const url = firestoreDocPath(env);
  const { response, data } = await firestoreFetch(env, url);

  if (response.status === 404) {
    return [];
  }

  if (!response.ok) {
    throw new Error("Firestore account list failed: " + JSON.stringify(data));
  }

  return (data.documents || []).map(firestoreDocToAccount).filter(Boolean);
}

function publicAccount(account) {
  if (!account) return null;

  return {
    id: account.id,
    address: account.address,
    display_name: account.display_name,
    from_name: account.from_name,
    signature: account.signature || "",
    enabled: Boolean(account.enabled),
    can_send: Boolean(account.can_send),
    can_receive: Boolean(account.can_receive),
    is_admin: Boolean(account.is_admin),
    created_at: account.created_at,
    updated_at: account.updated_at
  };
}

/* =========================================================
   D1 SCHEMA
========================================================= */

async function ensureSchema(env) {
  if (!env.DB) {
    throw new Error("Missing D1 binding named DB.");
  }

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

  const tableInfo = await env.DB.prepare(`PRAGMA table_info(mail_messages)`).all();
  const existingColumns = new Set((tableInfo.results || []).map(column => column.name));

  for (const [columnName, columnType] of MESSAGE_EXTRA_COLUMNS) {
    if (!existingColumns.has(columnName)) {
      await env.DB.prepare(`
        ALTER TABLE mail_messages ADD COLUMN ${columnName} ${columnType}
      `).run();
    }
  }

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS mail_sessions (
      token_hash TEXT PRIMARY KEY,
      account_address TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_mail_sessions_account
    ON mail_sessions (account_address)
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS mail_login_audit (
      id TEXT PRIMARY KEY,
      address TEXT NOT NULL,
      success INTEGER DEFAULT 0,
      reason TEXT,
      created_at TEXT NOT NULL
    )
  `).run();

  return true;
}

/* =========================================================
   SESSION HELPERS
========================================================= */

async function auditLogin(env, address, success, reason) {
  await ensureSchema(env);

  await env.DB.prepare(`
    INSERT INTO mail_login_audit (id, address, success, reason, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    normalizeEmail(address),
    success ? 1 : 0,
    reason || "",
    nowIso()
  ).run();
}

async function createSession(env, accountAddress) {
  await ensureSchema(env);

  const token = randomBase64Url(48);
  const tokenHash = await sha256Base64Url(token);

  await env.DB.prepare(`
    INSERT INTO mail_sessions (token_hash, account_address, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(
    tokenHash,
    normalizeEmail(accountAddress),
    nowIso(),
    addDaysIso(getSessionDays(env))
  ).run();

  return token;
}

async function getSessionAccount(request, env) {
  await ensureSchema(env);

  const token = getBearerToken(request);

  if (!token) {
    return null;
  }

  const tokenHash = await sha256Base64Url(token);

  const session = await env.DB.prepare(`
    SELECT *
    FROM mail_sessions
    WHERE token_hash = ?
  `).bind(tokenHash).first();

  if (!session) {
    return null;
  }

  if (new Date(session.expires_at).getTime() < Date.now()) {
    await env.DB.prepare(`
      DELETE FROM mail_sessions
      WHERE token_hash = ?
    `).bind(tokenHash).run();

    return null;
  }

  const account = await getActiveAccount(env, session.account_address);

  if (!account) {
    return null;
  }

  return {
    tokenHash,
    session,
    account
  };
}

async function requireSession(request, env) {
  const session = await getSessionAccount(request, env);

  if (!session) {
    return {
      error: json({
        ok: false,
        error: "Invalid or expired session."
      }, 401)
    };
  }

  return {
    session,
    account: session.account
  };
}

/* =========================================================
   AUTH ENDPOINTS
========================================================= */

async function login(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const address = normalizeEmail(body.address);
  const password = String(body.password || "");

  if (!address || !password) {
    return json({
      ok: false,
      error: "Email address and password are required."
    }, 400);
  }

  const account = await getActiveAccount(env, address);

  if (!account) {
    await auditLogin(env, address, false, "account_not_found_or_disabled");

    return json({
      ok: false,
      error: "Invalid email or password."
    }, 401);
  }

  if (!account.password_hash) {
    await auditLogin(env, address, false, "missing_password_hash");

    return json({
      ok: false,
      error: "Account password hash is missing."
    }, 500);
  }

  const enteredHash = (await sha256Hex(password)).toLowerCase();

  if (!constantTimeEqual(enteredHash, account.password_hash.toLowerCase())) {
    await auditLogin(env, address, false, "bad_password");

    return json({
      ok: false,
      error: "Invalid email or password."
    }, 401);
  }

  await auditLogin(env, address, true, "ok");

  const token = await createSession(env, account.address);

  return json({
    ok: true,
    token,
    account: publicAccount(account)
  });
}

async function logout(request, env) {
  await ensureSchema(env);

  const token = getBearerToken(request);

  if (token) {
    const tokenHash = await sha256Base64Url(token);

    await env.DB.prepare(`
      DELETE FROM mail_sessions
      WHERE token_hash = ?
    `).bind(tokenHash).run();
  }

  return json({ ok: true });
}

async function me(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  return json({
    ok: true,
    account: publicAccount(required.account)
  });
}

/* =========================================================
   ADMIN ENDPOINTS
========================================================= */

async function adminListAccounts(env) {
  const accounts = await listAccounts(env);

  return json({
    ok: true,
    accounts: accounts.map(publicAccount)
  });
}

async function adminCreateAccount(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const address = normalizeEmail(body.address);
  const allowedDomain = normalizeEmail(env.ALLOWED_DOMAIN);
  const displayName = normalize(body.display_name || body.displayName || address);
  const fromName = normalize(body.from_name || body.fromName || displayName || env.FROM_NAME || "Emerald Mail");
  const signature = String(body.signature || "");
  const password = String(body.password || "");

  const canSend = body.can_send === false || body.can_send === 0 ? false : true;
  const canReceive = body.can_receive === false || body.can_receive === 0 ? false : true;
  const isAdmin = body.is_admin === true || body.is_admin === 1 ? true : false;

  if (!address || !password) {
    return json({
      ok: false,
      error: "Address and password are required."
    }, 400);
  }

  if (!validDomainEmail(address, allowedDomain)) {
    return json({
      ok: false,
      error: "Address must use @" + allowedDomain
    }, 400);
  }

  if (password.length < 8) {
    return json({
      ok: false,
      error: "Password must be at least 8 characters."
    }, 400);
  }

  const existing = await getAccount(env, address);

  if (existing) {
    return json({
      ok: false,
      error: "Account already exists in Firestore."
    }, 409);
  }

  const passwordHash = await sha256Hex(password);
  const createdAt = nowIso();

  const account = await writeAccount(env, {
    address,
    display_name: displayName,
    from_name: fromName,
    signature,
    password_hash: passwordHash,
    enabled: true,
    can_send: canSend,
    can_receive: canReceive,
    is_admin: isAdmin,
    created_at: createdAt,
    updated_at: createdAt
  });

  return json({
    ok: true,
    account: publicAccount(account),
    firestoreCollection: FIRESTORE_COLLECTION,
    passwordHashMode: "sha256"
  });
}

async function adminUpdateAccount(request, env) {
  const body = await request.json().catch(() => ({}));
  const address = normalizeEmail(body.address);

  if (!address) {
    return json({
      ok: false,
      error: "Address is required."
    }, 400);
  }

  const existing = await getAccount(env, address);

  if (!existing) {
    return json({
      ok: false,
      error: "Account not found in Firestore."
    }, 404);
  }

  const updated = {
    ...existing,
    display_name: body.display_name !== undefined ? normalize(body.display_name) : existing.display_name,
    from_name: body.from_name !== undefined ? normalize(body.from_name) : existing.from_name,
    signature: body.signature !== undefined ? String(body.signature) : existing.signature,
    enabled: body.enabled !== undefined ? Boolean(body.enabled) : existing.enabled,
    can_send: body.can_send !== undefined ? Boolean(body.can_send) : existing.can_send,
    can_receive: body.can_receive !== undefined ? Boolean(body.can_receive) : existing.can_receive,
    is_admin: body.is_admin !== undefined ? Boolean(body.is_admin) : existing.is_admin,
    password_hash: existing.password_hash,
    created_at: existing.created_at || nowIso(),
    updated_at: nowIso()
  };

  const account = await writeAccount(env, updated);

  return json({
    ok: true,
    account: publicAccount(account)
  });
}

async function adminSetPassword(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const address = normalizeEmail(body.address);
  const password = String(body.password || "");

  if (!address || !password) {
    return json({
      ok: false,
      error: "Address and new password are required."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      ok: false,
      error: "Password must be at least 8 characters."
    }, 400);
  }

  const existing = await getAccount(env, address);

  if (!existing) {
    return json({
      ok: false,
      error: "Account not found in Firestore."
    }, 404);
  }

  const passwordHash = await sha256Hex(password);

  const account = await writeAccount(env, {
    ...existing,
    password_hash: passwordHash,
    updated_at: nowIso()
  });

  await env.DB.prepare(`
    DELETE FROM mail_sessions
    WHERE account_address = ?
  `).bind(address).run();

  return json({
    ok: true,
    message: "Password changed in Firestore and existing sessions were removed.",
    account: publicAccount(account)
  });
}

async function adminDisableAccount(request, env) {
  await ensureSchema(env);

  const body = await request.json().catch(() => ({}));
  const address = normalizeEmail(body.address);
  const enabled = body.enabled === true || body.enabled === 1;

  if (!address) {
    return json({
      ok: false,
      error: "Address is required."
    }, 400);
  }

  const existing = await getAccount(env, address);

  if (!existing) {
    return json({
      ok: false,
      error: "Account not found in Firestore."
    }, 404);
  }

  const account = await writeAccount(env, {
    ...existing,
    enabled,
    updated_at: nowIso()
  });

  if (!enabled) {
    await env.DB.prepare(`
      DELETE FROM mail_sessions
      WHERE account_address = ?
    `).bind(address).run();
  }

  return json({
    ok: true,
    enabled,
    account: publicAccount(account)
  });
}

/* =========================================================
   USER ACCOUNT SETTINGS
========================================================= */

async function updateOwnSignature(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  const body = await request.json().catch(() => ({}));
  const signature = String(body.signature || "");

  const account = await writeAccount(env, {
    ...required.account,
    signature,
    updated_at: nowIso()
  });

  return json({
    ok: true,
    signature,
    account: publicAccount(account)
  });
}

/* =========================================================
   INBOUND EMAIL HANDLER
========================================================= */

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

  const account = await getActiveAccount(env, recipient);

  if (!account || !account.can_receive) {
    message.setReject("Emerald Mail account does not exist or cannot receive mail.");
    return;
  }

  const id = crypto.randomUUID();
  const receivedAt = nowIso();
  const rawKey =
    `raw/${safeKeyPart(recipient)}/${receivedAt.replace(/[:.]/g, "-")}-${id}.eml`;

  const messageId = getHeader(message.headers, "Message-ID");
  const inReplyTo = getHeader(message.headers, "In-Reply-To");
  const referencesHeader = getHeader(message.headers, "References");

  /*
    R2 requires a known-length body. Convert the raw stream into ArrayBuffer.
  */
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
      attachments_json,
      provider,
      provider_message_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'inbox', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    "[]",
    "cloudflare-routing",
    ""
  ).run();

  console.log("Emerald Mail saved to D1:", id);
}

/* =========================================================
   MAIL READ / LIST / DELETE
========================================================= */

async function listMessages(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  await ensureSchema(env);

  const url = new URL(request.url);
  const folder = normalize(url.searchParams.get("folder") || "inbox");
  const mailbox = normalizeEmail(required.account.address);

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
      attachments_json,
      provider,
      provider_message_id
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
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  await ensureSchema(env);

  const url = new URL(request.url);
  const id = normalize(url.searchParams.get("id"));
  const mailbox = normalizeEmail(required.account.address);

  if (!id) {
    return json({
      ok: false,
      error: "Missing message id."
    }, 400);
  }

  const row = await env.DB.prepare(`
    SELECT raw_r2_key
    FROM mail_messages
    WHERE id = ? AND mailbox = ?
  `).bind(id, mailbox).first();

  if (!row) {
    return json({
      ok: false,
      error: "Message not found for this account."
    }, 404);
  }

  const object = await env.MAIL_RAW.get(row.raw_r2_key);

  if (!object) {
    return json({
      ok: false,
      error: "Raw email not found in R2."
    }, 404);
  }

  return new Response(object.body, {
    headers: {
      "Content-Type": "message/rfc822",
      ...CORS_HEADERS
    }
  });
}

async function markRead(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  const body = await request.json().catch(() => ({}));
  const id = normalize(body.id);
  const mailbox = normalizeEmail(required.account.address);

  if (!id) {
    return json({
      ok: false,
      error: "Missing message id."
    }, 400);
  }

  await env.DB.prepare(`
    UPDATE mail_messages
    SET read = 1
    WHERE id = ? AND mailbox = ?
  `).bind(id, mailbox).run();

  return json({ ok: true });
}

async function moveToTrash(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  const body = await request.json().catch(() => ({}));
  const id = normalize(body.id);
  const mailbox = normalizeEmail(required.account.address);

  if (!id) {
    return json({
      ok: false,
      error: "Missing message id."
    }, 400);
  }

  await env.DB.prepare(`
    UPDATE mail_messages
    SET folder = 'trash'
    WHERE id = ? AND mailbox = ?
  `).bind(id, mailbox).run();

  return json({ ok: true });
}

/* =========================================================
   RESEND SENDING
========================================================= */

function convertAttachmentsForResend(attachments) {
  if (!Array.isArray(attachments)) return [];

  return attachments
    .filter(file => file && file.filename && file.content)
    .map(file => {
      const item = {
        filename: file.filename,
        content: file.content
      };

      if (file.content_id) {
        item.contentId = file.content_id;
      }

      return item;
    });
}

function buildSimpleRawEmail({
  from,
  to,
  cc,
  bcc,
  subject,
  text,
  html,
  headers,
  messageId
}) {
  const lines = [];

  lines.push(`Message-ID: ${encodeHeaderValue(messageId)}`);
  lines.push(`From: ${encodeHeaderValue(from)}`);
  lines.push(`To: ${encodeHeaderValue(Array.isArray(to) ? to.join(", ") : to)}`);

  if (cc && splitRecipients(cc).length) {
    lines.push(`Cc: ${encodeHeaderValue(Array.isArray(cc) ? cc.join(", ") : cc)}`);
  }

  if (bcc && splitRecipients(bcc).length) {
    lines.push(`Bcc: ${encodeHeaderValue(Array.isArray(bcc) ? bcc.join(", ") : bcc)}`);
  }

  lines.push(`Subject: ${encodeHeaderValue(subject)}`);
  lines.push(`Date: ${new Date().toUTCString()}`);

  for (const [key, value] of Object.entries(headers || {})) {
    if (!value) continue;

    const safeKey = String(key).replace(/[^A-Za-z0-9-]/g, "");
    if (!safeKey) continue;

    const lower = safeKey.toLowerCase();

    if (
      lower === "message-id" ||
      lower === "from" ||
      lower === "to" ||
      lower === "cc" ||
      lower === "bcc" ||
      lower === "subject" ||
      lower === "date"
    ) {
      continue;
    }

    lines.push(`${safeKey}: ${encodeHeaderValue(value)}`);
  }

  lines.push("MIME-Version: 1.0");

  if (html) {
    lines.push('Content-Type: text/html; charset="UTF-8"');
    lines.push("");
    lines.push(html);
  } else {
    lines.push('Content-Type: text/plain; charset="UTF-8"');
    lines.push("");
    lines.push(text || "");
  }

  return lines.join("\r\n");
}

async function storeSentMessage(env, account, payload, resendData, messageId) {
  await ensureSchema(env);

  if (!env.MAIL_RAW) {
    throw new Error("Missing R2 binding named MAIL_RAW.");
  }

  const id = crypto.randomUUID();
  const receivedAt = nowIso();
  const from = normalizeEmail(account.address);
  const toString = splitRecipients(payload.to).join(", ");
  const ccString = splitRecipients(payload.cc).join(", ");
  const bccString = splitRecipients(payload.bcc).join(", ");
  const subject = payload.subject || "(No subject)";
  const providerId = resendData?.id || "";

  const rawEmail = buildSimpleRawEmail({
    from,
    to: toString,
    cc: ccString,
    bcc: bccString,
    subject,
    text: payload.text || "",
    html: payload.html || "",
    headers: payload.headers || {},
    messageId
  });

  const rawBuffer = new TextEncoder().encode(rawEmail);
  const rawKey =
    `sent/${safeKeyPart(from)}/${receivedAt.replace(/[:.]/g, "-")}-${id}.eml`;

  await env.MAIL_RAW.put(rawKey, rawBuffer, {
    httpMetadata: {
      contentType: "message/rfc822"
    },
    customMetadata: {
      sender: from,
      recipient: toString,
      subject
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
      attachments_json,
      provider,
      provider_message_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 'sent', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    from,
    toString,
    from,
    subject,
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
    JSON.stringify(payload.originalAttachments || []),
    "resend",
    providerId
  ).run();

  return {
    id,
    rawKey,
    providerId
  };
}

async function sendEmail(request, env) {
  const required = await requireSession(request, env);
  if (required.error) return required.error;

  const account = required.account;

  if (!account.can_send) {
    return json({
      ok: false,
      error: "This account is not allowed to send email."
    }, 403);
  }

  if (!env.RESEND_API_KEY) {
    return json({
      ok: false,
      error: "Missing RESEND_API_KEY secret."
    }, 501);
  }

  const allowedDomain = normalizeEmail(env.ALLOWED_DOMAIN);
  const from = normalizeEmail(account.address);

  if (!validDomainEmail(from, allowedDomain)) {
    return json({
      ok: false,
      error: "Sender must use @" + allowedDomain
    }, 400);
  }

  const body = await request.json().catch(() => ({}));
  const to = splitRecipients(body.to);
  const cc = splitRecipients(body.cc);
  const bcc = splitRecipients(body.bcc);
  const subject = normalize(body.subject);
  const text = String(body.text || "");
  const html = String(body.html || "");
  const headers = body.headers && typeof body.headers === "object" ? body.headers : {};
  const originalAttachments = Array.isArray(body.attachments) ? body.attachments : [];

  if (!to.length || !subject || (!text && !html)) {
    return json({
      ok: false,
      error: "To, subject, and message body are required."
    }, 400);
  }

  const messageId = headers["Message-ID"] || makeMessageId(from);
  const fromName = normalize(account.from_name || env.FROM_NAME || "Emerald Mail");
  const resendAttachments = convertAttachmentsForResend(originalAttachments);

  const resendPayload = {
    from: `${fromName} <${from}>`,
    to,
    subject,
    headers: {
      ...headers,
      "Message-ID": messageId
    }
  };

  if (text) resendPayload.text = text;
  if (html) resendPayload.html = html;
  if (cc.length) resendPayload.cc = cc;
  if (bcc.length) resendPayload.bcc = bcc;
  if (resendAttachments.length) resendPayload.attachments = resendAttachments;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + env.RESEND_API_KEY,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(resendPayload)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Resend send failed:", data);

    return json({
      ok: false,
      error: "Resend failed to send the email.",
      details: data
    }, 500);
  }

  const stored = await storeSentMessage(
    env,
    account,
    {
      from,
      to,
      cc,
      bcc,
      subject,
      text,
      html,
      headers: resendPayload.headers,
      originalAttachments
    },
    data,
    messageId
  );

  return json({
    ok: true,
    provider: "resend",
    messageId: data.id || messageId,
    storedId: stored.id,
    rawKey: stored.rawKey
  });
}

/* =========================================================
   DEBUG
========================================================= */

async function debugLatest(request, env) {
  const adminError = requireAdmin(request, env);
  if (adminError) return adminError;

  await ensureSchema(env);

  const result = await env.DB.prepare(`
    SELECT
      id,
      mailbox,
      recipient,
      sender,
      subject,
      received_at,
      raw_r2_key,
      folder,
      message_id,
      provider,
      provider_message_id
    FROM mail_messages
    ORDER BY received_at DESC
    LIMIT 20
  `).all();

  return json({
    ok: true,
    messages: result.results || []
  });
}

/* =========================================================
   ROUTER
========================================================= */

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
        service: "Emerald Mail V6 Firestore Auth",
        allowedDomain: env.ALLOWED_DOMAIN || null,
        fromName: env.FROM_NAME || "Emerald Mail",
        firestoreCollection: FIRESTORE_COLLECTION,
        firebaseProjectId: env.FIREBASE_PROJECT_ID || null,
        hasDBBinding: Boolean(env.DB),
        hasR2Binding: Boolean(env.MAIL_RAW),
        hasResendApiKey: Boolean(env.RESEND_API_KEY),
        hasAdminKey: Boolean(env.EMERALD_MAIL_ADMIN_KEY),
        hasGoogleClientEmail: Boolean(env.GOOGLE_CLIENT_EMAIL),
        hasGooglePrivateKey: Boolean(env.GOOGLE_PRIVATE_KEY),
        passwordHashing: "SHA-256 hex in Firestore",
        time: nowIso()
      });
    }

    try {
      if (url.pathname === "/api/setup" && request.method === "GET") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        await ensureSchema(env);

        return json({
          ok: true,
          message: "Emerald Mail V6 Firestore schema checked and upgraded.",
          firestoreCollection: FIRESTORE_COLLECTION
        });
      }

      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        return await login(request, env);
      }

      if (url.pathname === "/api/auth/logout" && request.method === "POST") {
        return await logout(request, env);
      }

      if (url.pathname === "/api/auth/me" && request.method === "GET") {
        return await me(request, env);
      }

      if (url.pathname === "/api/account/signature" && request.method === "POST") {
        return await updateOwnSignature(request, env);
      }

      if (url.pathname === "/api/admin/accounts" && request.method === "GET") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        return await adminListAccounts(env);
      }

      if (url.pathname === "/api/admin/accounts/create" && request.method === "POST") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        return await adminCreateAccount(request, env);
      }

      if (url.pathname === "/api/admin/accounts/update" && request.method === "POST") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        return await adminUpdateAccount(request, env);
      }

      if (url.pathname === "/api/admin/accounts/password" && request.method === "POST") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        return await adminSetPassword(request, env);
      }

      if (url.pathname === "/api/admin/accounts/disable" && request.method === "POST") {
        const adminError = requireAdmin(request, env);
        if (adminError) return adminError;

        return await adminDisableAccount(request, env);
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
        return await debugLatest(request, env);
      }

      return json({
        ok: false,
        error: "Endpoint not found.",
        endpoints: [
          "GET  /api/health",
          "GET  /api/setup?admin_key=ADMIN_KEY",
          "POST /api/auth/login",
          "POST /api/auth/logout",
          "GET  /api/auth/me",
          "GET  /api/messages?folder=inbox",
          "GET  /api/message/raw?id=MESSAGE_ID",
          "POST /api/message/read",
          "POST /api/message/delete",
          "POST /api/send",
          "POST /api/account/signature",
          "GET  /api/admin/accounts?admin_key=ADMIN_KEY",
          "POST /api/admin/accounts/create?admin_key=ADMIN_KEY",
          "POST /api/admin/accounts/update?admin_key=ADMIN_KEY",
          "POST /api/admin/accounts/password?admin_key=ADMIN_KEY",
          "POST /api/admin/accounts/disable?admin_key=ADMIN_KEY"
        ]
      }, 404);
    } catch (error) {
      console.error("Emerald Mail V6 Firestore fetch failed:", {
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
