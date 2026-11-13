function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function now() {
  return new Date().toISOString();
}

function id() {
  return crypto.randomUUID();
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function getUserByUsername(env, username) {
  return await env.DB.prepare(`
    SELECT user_id, username, display_name, role, active
    FROM users
    WHERE username = ? COLLATE NOCASE
    LIMIT 1
  `).bind(username).first();
}

async function handleSetup(request, env) {
  if (request.method !== "POST") {
    return json({
      ok: false,
      error: "ส่งข้อมูลด้วย POST เท่านั้น"
    }, 405);
  }

  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).first();

  if (Number(count?.total || 0) > 0) {
    return json({
      ok: false,
      error: "มีบัญชีอยู่แล้ว"
    }, 409);
  }

  const body = await readJson(request);

  if (!body || typeof body !== "object") {
    return json({
      ok: false,
      error: "ข้อมูลไม่ถูกต้อง"
    }, 400);
  }

  const accounts = [
    {
      username: "admin",
      password: body.admin_password,
      displayName: "Admin",
      role: "Admin"
    },
    {
      username: "store",
      password: body.store_password,
      displayName: "Store",
      role: "Operator"
    },
    {
      username: "trw_trd",
      password: body.trw_trd_password,
      displayName: "TRW/TRD",
      role: "Operator"
    }
  ];

  for (const account of accounts) {
    if (
      typeof account.password !== "string" ||
      account.password.trim() === ""
    ) {
      return json({
        ok: false,
        error: "กรุณาระบุรหัสผ่านให้ครบทั้ง 3 บัญชี"
      }, 400);
    }
  }

  const createdAt = now();

  const statements = accounts.map(account =>
    env.DB.prepare(`
      INSERT INTO users (
        user_id,
        username,
        display_name,
        password_hash,
        role,
        active,
        must_change_password,
        session_version,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, 1, 0, 1, ?, ?)
    `).bind(
      id(),
      account.username,
      account.displayName,
      account.password,
      account.role,
      createdAt,
      createdAt
    )
  );

  try {
    await env.DB.batch(statements);
  } catch (error) {
    console.error("Initial account setup failed");

    return json({
      ok: false,
      error: "สร้างบัญชีไม่สำเร็จ"
    }, 500);
  }

  return json({
    ok: true,
    message: "สร้างบัญชี admin, store และ trw_trd แล้ว"
  }, 201);
}

async function handleLogin(request, env) {
  if (request.method !== "POST") {
    return json({
      ok: false,
      error: "ส่งข้อมูลด้วย POST เท่านั้น"
    }, 405);
  }

  const body = await readJson(request);

  if (
    !body ||
    typeof body.username !== "string" ||
    typeof body.password !== "string"
  ) {
    return json({
      ok: false,
      error: "กรุณาระบุ username และ password"
    }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT
      user_id,
      username,
      display_name,
      password_hash,
      role,
      active
    FROM users
    WHERE username = ? COLLATE NOCASE
    LIMIT 1
  `).bind(body.username.trim()).first();

  if (!user || Number(user.active) !== 1) {
    return json({
      ok: false,
      error: "Username หรือ Password ไม่ถูกต้อง"
    }, 401);
  }

  if (user.password_hash !== body.password) {
    return json({
      ok: false,
      error: "Username หรือ Password ไม่ถูกต้อง"
    }, 401);
  }

  return json({
    ok: true,
    user: {
      userId: user.user_id,
      username: user.username,
      displayName: user.display_name,
      role: user.role
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (!env.DB) {
        return json({
          ok: false,
          error: "D1 binding DB is missing"
        }, 503);
      }

      if (request.method === "GET" && url.pathname === "/health") {
        const migration = await env.DB.prepare(`
          SELECT MAX(version) AS version
          FROM schema_migrations
        `).first();

        return json({
          ok: true,
          service: "alcohol-key-control-api",
          database: "connected",
          schemaVersion: Number(migration?.version || 0)
        });
      }

      if (url.pathname === "/api/setup") {
        return await handleSetup(request, env);
      }

      if (url.pathname === "/api/login") {
        return await handleLogin(request, env);
      }

      return json({
        ok: false,
        error: "Not found"
      }, 404);
    } catch (error) {
      console.error("Worker request failed");

      return json({
        ok: false,
        error: "ระบบทำรายการไม่สำเร็จ"
      }, 500);
    }
  }
};
