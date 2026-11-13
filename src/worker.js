const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: CORS_HEADERS
  });
}

function now() {
  return new Date().toISOString();
}

function newId() {
  return crypto.randomUUID();
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* -----------------------------
   Login
----------------------------- */

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

  const username = body.username.trim();

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
  `).bind(username).first();

  if (!user || Number(user.active) !== 1) {
    return json({
      ok: false,
      error: "Username หรือ Password ไม่ถูกต้อง"
    }, 401);
  }

  /*
    ระบบแบบง่ายตามที่ตกลงกัน:
    password_hash เก็บรหัสผ่านตรง ๆ ใน D1
  */
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

/* -----------------------------
   Inspections
----------------------------- */

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
      error: "รองรับเฉพาะ GET และ POST"
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

  if (!employeeGid) {
    return json({
      ok: false,
      error: "กรุณาระบุ Employee GID"
    }, 400);
  }

  if (!employeeName) {
    return json({
      ok: false,
      error: "กรุณาระบุชื่อพนักงาน"
    }, 400);
  }

  if (!department) {
    return json({
      ok: false,
      error: "กรุณาระบุแผนก"
    }, 400);
  }

  if (!recordedBy) {
    return json({
      ok: false,
      error: "ไม่พบผู้บันทึก"
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

  /*
    ตาราง D1 ปัจจุบันใช้กฎ zero-only-v1:
    ค่า 0 ต้อง Passed
    ค่ามากกว่า 0 ต้อง NotPassed
  */
  if (resultMgL === 0 && decision !== "Passed") {
    return json({
      ok: false,
      error: "ถ้าค่าแอลกอฮอล์เป็น 0 ต้องเลือก Passed"
    }, 400);
  }

  if (resultMgL > 0 && decision !== "NotPassed") {
    return json({
      ok: false,
      error: "ถ้าค่าแอลกอฮอล์มากกว่า 0 ต้องเลือก NotPassed"
    }, 400);
  }

  const recorder = await env.DB.prepare(`
    SELECT user_id
    FROM users
    WHERE user_id = ?
      AND active = 1
    LIMIT 1
  `).bind(recordedBy).first();

  if (!recorder) {
    return json({
      ok: false,
      error: "ไม่พบผู้บันทึกหรือผู้บันทึกถูกปิดใช้งาน"
    }, 400);
  }

  const inspectionId = newId();
  const attemptId = newId();
  const timestamp = now();

  const inspectionStatus =
    decision === "Passed" ? "Passed" : "Awaiting2";

  const inspectionStatement = env.DB.prepare(`
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
    VALUES (
      ?, ?, ?, ?, ?, ?, ?, 1, '[]', ?, 1, ?, ?, ?, ?
    )
  `).bind(
    inspectionId,
    employeeGid,
    employeeName,
    department,
    timestamp,
    timestamp,
    inspectionStatus,
    notes,
    recordedBy,
    timestamp,
    recordedBy,
    timestamp
  );

  const attemptStatement = env.DB.prepare(`
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
    VALUES (
      ?, ?, 1, ?, ?, ?, 'zero-only-v1', ?, ?, ?
    )
  `).bind(
    attemptId,
    inspectionId,
    timestamp,
    resultMgL,
    decision,
    notes,
    recordedBy,
    timestamp
  );

  try {
    await env.DB.batch([
      inspectionStatement,
      attemptStatement
    ]);
  } catch (error) {
    console.error("Inspection insert failed");

    return json({
      ok: false,
      error: "บันทึกการตรวจไม่สำเร็จ"
    }, 500);
  }

  return json({
    ok: true,
    inspection_id: inspectionId,
    attempt_no: 1,
    test_status: inspectionStatus
  }, 201);
}

/* -----------------------------
   Worker
----------------------------- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    if (!env.DB) {
      return json({
        ok: false,
        error: "D1 binding DB is missing"
      }, 503);
    }

    try {
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

      if (url.pathname === "/api/login") {
        return await handleLogin(request, env);
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
