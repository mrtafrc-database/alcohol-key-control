const encoder = new TextEncoder();
const ITERATIONS = 100000;
function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
function hex(bytes) {
  return Array.from(
    new Uint8Array(bytes),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}
async function sameSecret(a, b) {
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);
  const x = new Uint8Array(left);
  const y = new Uint8Array(right);
  let difference = 0;
  for (let i = 0; i < x.length; i++) {
    difference |= x[i] ^ y[i];
  }
  return difference === 0;
}
async function hashPassword(password, pepper) {
  const pepperKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const pepperedPassword = await crypto.subtle.sign(
    "HMAC",
    pepperKey,
    encoder.encode(password)
  );
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    pepperedPassword,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: ITERATIONS
    },
    passwordKey,
    256
  );
  return JSON.stringify({
    version: 1,
    algorithm: "pbkdf2-sha256+hmac-pepper",
    iterations: ITERATIONS,
    salt: hex(salt),
    hash: hex(derived)
  });
}
async function readSmallJson(request) {
  if (!request.body) throw new Error("INVALID_BODY");
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8192) {
        await reader.cancel();
        throw new Error("INVALID_BODY");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(bytes));
  } finally {
    reader.releaseLock();
  }
}
function setupPage() {
  const nonce = crypto.randomUUID();
  const html = `<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>สร้างบัญชีเริ่มต้น</title>
  <style nonce="${nonce}">
    body {
      font-family: system-ui, sans-serif;
      background: #f3f6f8;
      color: #17323b;
      margin: 0;
      padding: 24px;
    }
    main {
      max-width: 460px;
      margin: 30px auto;
      padding: 28px;
      background: white;
      border-radius: 16px;
    }
    h1 { font-size: 24px; }
    label { display: block; margin-top: 18px; }
    input, button {
      box-sizing: border-box;
      width: 100%;
      padding: 12px;
      margin-top: 7px;
      border-radius: 8px;
      border: 1px solid #b7c7ce;
      font-size: 16px;
    }
    button {
      margin-top: 24px;
      background: #007b80;
      color: white;
      cursor: pointer;
    }
    button:disabled { opacity: .55; cursor: wait; }
    #message { white-space: pre-wrap; margin-top: 18px; }
    small { color: #536b75; }
  </style>
</head>
<body>
<main>
  <h1>สร้างบัญชีเริ่มต้น</h1>
  <p>สร้าง admin, store และ trw_trd ครั้งเดียว</p>
  <form id="setup-form">
    <label for="token">ADMIN_SETUP_TOKEN</label>
    <input id="token" type="password" required
      autocomplete="off" spellcheck="false">
    <small>ใช้ค่าจาก Secret ที่คุณเก็บไว้</small>
    <label for="admin-password">รหัสผ่านของ admin</label>
    <input id="admin-password" type="password" required
      minlength="16" maxlength="128" autocomplete="new-password">
    <label for="store-password">รหัสผ่านของ store</label>
    <input id="store-password" type="password" required
      minlength="16" maxlength="128" autocomplete="new-password">
    <label for="trw-password">รหัสผ่านของ trw_trd</label>
    <input id="trw-password" type="password" required
      minlength="16" maxlength="128" autocomplete="new-password">
    <button id="submit" type="submit">สร้าง 3 บัญชี</button>
  </form>
  <div id="message" role="status"></div>
</main>
<script nonce="${nonce}">
  const form = document.getElementById("setup-form");
  const button = document.getElementById("submit");
  const message = document.getElementById("message");
  form.addEventListener("submit", async event => {
    event.preventDefault();
    button.disabled = true;
    message.textContent = "กำลังสร้างบัญชี กรุณารอสักครู่...";
    try {
      const response = await fetch("/api/setup", {
        method: "POST",
        credentials: "omit",
        headers: {
          "Content-Type": "application/json",
          "X-Setup-Token":
            document.getElementById("token").value.trim()
        },
        body: JSON.stringify({
          admin: document.getElementById("admin-password").value,
          store: document.getElementById("store-password").value,
          trw_trd: document.getElementById("trw-password").value
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "สร้างบัญชีไม่สำเร็จ");
      }
      form.reset();
      form.hidden = true;
      message.textContent =
        "สร้าง admin, store และ trw_trd สำเร็จแล้ว\\n" +
        "กลับไป Cloudflare แล้วลบ ADMIN_SETUP_TOKEN";
    } catch (error) {
      message.textContent = error.message;
      button.disabled = false;
    }
  });
</script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'none'; " +
        `script-src 'nonce-${nonce}'; ` +
        `style-src 'nonce-${nonce}'; ` +
        "connect-src 'self'; " +
        "form-action 'self'; " +
        "base-uri 'none'; " +
        "frame-ancestors 'none'"
    }
  });
}
async function handleSetup(request, env, url) {
  if (!env.ADMIN_SETUP_TOKEN || !env.AUTH_PEPPER) {
    return json({
      ok: false,
      error: "Setup ปิดอยู่ หรือยังตั้งค่า Secret ไม่ครบ"
    }, 403);
  }
  const existing = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).first();
  if (Number(existing.total) !== 0) {
    return json({
      ok: false,
      error: "มีบัญชีในระบบแล้ว ไม่อนุญาตให้ Setup ซ้ำ"
    }, 409);
  }
  if (request.method === "GET" && url.pathname === "/setup") {
    return setupPage();
  }
  if (request.method !== "POST" || url.pathname !== "/api/setup") {
    return json({ ok: false, error: "Method not allowed" }, 405);
  }
  if (request.headers.get("Origin") !== url.origin) {
    return json({ ok: false, error: "Origin ไม่ถูกต้อง" }, 403);
  }
  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.split(";")[0].trim() !== "application/json") {
    return json({ ok: false, error: "ต้องส่ง JSON" }, 415);
  }
  const token = request.headers.get("X-Setup-Token") || "";
  if (
    token.length > 256 ||
    !(await sameSecret(token, env.ADMIN_SETUP_TOKEN))
  ) {
    return json({ ok: false, error: "Setup Token ไม่ถูกต้อง" }, 403);
  }
  let body;
  try {
    body = await readSmallJson(request);
  } catch {
    return json({ ok: false, error: "ข้อมูลไม่ถูกต้องหรือใหญ่เกินไป" }, 400);
  }
  if (!body || typeof body !== "object") {
    return json({ ok: false, error: "ข้อมูลไม่ถูกต้อง" }, 400);
  }
  const definitions = [
    { username: "admin", displayName: "Admin", role: "Admin" },
    { username: "store", displayName: "Store", role: "Operator" },
    { username: "trw_trd", displayName: "TRW/TRD", role: "Operator" }
  ];
  const passwords = definitions.map(user => body[user.username]);
  if (passwords.some(password =>
    typeof password !== "string" ||
    password.length < 16 ||
    password.length > 128
  )) {
    return json({
      ok: false,
      error: "รหัสผ่านทุกบัญชีต้องยาว 16–128 ตัว"
    }, 400);
  }
  if (new Set(passwords).size !== 3) {
    return json({
      ok: false,
      error: "กรุณาใช้รหัสผ่านต่างกันสำหรับทั้ง 3 บัญชี"
    }, 400);
  }
  const now = new Date().toISOString();
  const users = [];
  // Hash sequentially to keep resource usage predictable.
  for (const definition of definitions) {
    users.push({
      id: crypto.randomUUID(),
      username: definition.username,
      displayName: definition.displayName,
      role: definition.role,
      passwordHash: await hashPassword(
        body[definition.username],
        env.AUTH_PEPPER
      )
    });
  }
  // One SQL statement inserts all three users.
  // Recheck emptiness inside the write to prevent concurrent setup.
  const insertUsers = env.DB.prepare(`
    INSERT INTO users (
      user_id, username, display_name, password_hash,
      role, active, must_change_password, session_version,
      created_at, updated_at
    )
    SELECT
      json_extract(value, '$.id'),
      json_extract(value, '$.username'),
      json_extract(value, '$.displayName'),
      json_extract(value, '$.passwordHash'),
      json_extract(value, '$.role'),
      1, 1, 1, ?, ?
    FROM json_each(?)
    WHERE NOT EXISTS (SELECT 1 FROM users)
  `).bind(now, now, JSON.stringify(users));
  const insertAudit = env.DB.prepare(`
    INSERT INTO audit_log (
      audit_id, actor_user_id, action,
      entity_type, entity_id, details_json, created_at
    )
    SELECT ?, ?, 'INITIAL_USERS_CREATED',
      'System', 'initial-setup', ?, ?
    WHERE EXISTS (
      SELECT 1 FROM users WHERE user_id = ?
    )
  `).bind(
    crypto.randomUUID(),
    users[0].id,
    JSON.stringify({ usernames: users.map(user => user.username) }),
    now,
    users[0].id
  );
  const results = await env.DB.batch([insertUsers, insertAudit]);
  if (Number(results[0].meta.changes) !== 3) {
    return json({
      ok: false,
      error: "มีการสร้างบัญชีแล้ว ไม่อนุญาตให้ Setup ซ้ำ"
    }, 409);
  }
  return json({
    ok: true,
    created: users.map(user => user.username)
  }, 201);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (!env.DB) {
        return json({ ok: false, error: "D1 binding DB is missing" }, 503);
      }
      if (request.method === "GET" && url.pathname === "/health") {
        const migration = await env.DB.prepare(
          "SELECT MAX(version) AS version FROM schema_migrations"
        ).first();
        if (Number(migration?.version) !== 1) {
          return json({
            ok: false,
            error: "Unexpected database schema version"
          }, 503);
        }
        return json({
          ok: true,
          service: "alcohol-key-control-api",
          database: "connected",
          schemaVersion: 1
        });
      }
      if (url.pathname === "/setup" || url.pathname === "/api/setup") {
        return await handleSetup(request, env, url);
      }
      return json({ ok: false, error: "Not found" }, 404);
    } catch {
      // Never log submitted passwords or setup tokens.
      console.error("Worker request failed");
      return json({
        ok: false,
        error: "ระบบทำรายการไม่สำเร็จ กรุณาตรวจ Worker Logs"
      }, 500);
    }
  }
};
