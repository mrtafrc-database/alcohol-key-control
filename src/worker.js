function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
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
async function handleInspections(request, env) {
  if (request.method === "GET") {
    const result = await env.DB.prepare(`
      SELECT
        i.inspection_id,
        i.employee_gid,
        i.employee_name,
        i.department,
        i.first_tested_at,
        i.last_tested_at,
        i.test_status,
        i.attempt_count,
        i.notes,
        a.attempt_no,
        a.result_mg_l,
        a.decision,
        a.notes AS attempt_notes
      FROM inspections i
      LEFT JOIN inspection_attempts a
        ON a.inspection_id = i.inspection_id
       AND a.attempt_no = i.attempt_count
      ORDER BY i.updated_at DESC
      LIMIT 100
    `).all();
    return json({
      ok: true,
      inspections: result.results || []
    });
  }
  if (request.method !== "POST") {
    return json({
      ok: false,
      error: "ส่งข้อมูลด้วย GET หรือ POST เท่านั้น"
    }, 405);
  }
  const body = await readJson(request);
  if (!body || typeof body !== "object") {
    return json({
      ok: false,
      error: "ข้อมูลไม่ถูกต้อง"
    }, 400);
  }
  const employeeGid = String(body.employee_gid || "").trim();
  const employeeName = String(body.employee_name || "").trim();
  const department = String(body.department || "").trim();
  const recordedBy = String(body.recorded_by || "").trim();
  const notes = String(body.notes || "");
  const decision = String(body.decision || "");
  const resultMgL = Number(body.result_mg_l);
  if (!employeeGid || !employeeName || !department || !recordedBy) {
    return json({
      ok: false,
      error: "กรุณากรอก GID ชื่อ แผนก และผู้บันทึกให้ครบ"
    }, 400);
  }
  if (!Number.isFinite(resultMgL) || resultMgL < 0) {
    return json({
      ok: false,
      error: "ค่าแอลกอฮอล์ต้องเป็นตัวเลขตั้งแต่ 0 ขึ้นไป"
    }, 400);
  }
  if (!["Passed", "NotPassed"].includes(decision)) {
    return json({
      ok: false,
      error: "กรุณาเลือก Passed หรือ NotPassed"
    }, 400);
  }
  const recorder = await env.DB.prepare(`
    SELECT user_id
    FROM users
    WHERE user_id = ?
      AND active = 1
  `).bind(recordedBy).first();
  if (!recorder) {
    return json({
      ok: false,
      error: "ไม่พบผู้บันทึกหรือผู้บันทึกถูกปิดใช้งาน"
    }, 400);
  }
  const inspectionId = crypto.randomUUID();
  const attemptId = crypto.randomUUID();
  const testedAt = new Date().toISOString();
  const testStatus =
    decision === "Passed" ? "Passed" : "Awaiting2";
  const inspection = env.DB.prepare(`
    INSERT INTO inspections (
      inspection_id,
      employee_gid,
      employee_name,
      department,
      first_tested_at,
      last_tested_at,
      test_status,
      attempt_count,
      planned_vehicle_ids_json,
      notes,
      version,
      created_by,
      created_at,
      updated_by,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, '[]', ?, 1, ?, ?, ?, ?)
  `).bind(
    inspectionId,
    employeeGid,
    employeeName,
    department,
    testedAt,
    testedAt,
    testStatus,
    notes,
    recordedBy,
    testedAt,
    recordedBy,
    testedAt
  );
  const attempt = env.DB.prepare(`
    INSERT INTO inspection_attempts (
      attempt_id,
      inspection_id,
      attempt_no,
      tested_at,
      result_mg_l,
      decision,
      rule_version,
      notes,
      recorded_by,
      recorded_at
    )
    VALUES (?, ?, 1, ?, ?, ?, 'zero-only-v1', ?, ?, ?)
  `).bind(
    attemptId,
    inspectionId,
    testedAt,
    resultMgL,
    decision,
    notes,
    recordedBy,
    testedAt
  );
  try {
    await env.DB.batch([inspection, attempt]);
  } catch (error) {
    console.error("Inspection creation failed");
    return json({
      ok: false,
      error: "บันทึกการตรวจไม่สำเร็จ ตรวจสอบว่าค่าแอลกอฮอล์กับผลตัดสินสอดคล้องกัน"
    }, 400);
  }
  return json({
    ok: true,
    inspection_id: inspectionId,
    attempt_no: 1,
    test_status: testStatus
  }, 201);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

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

      if (url.pathname === "/api/inspections") {
  return await handleInspections(request, env);
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
