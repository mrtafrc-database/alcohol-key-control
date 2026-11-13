const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
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

async function activeUser(env, userId) {
  return await env.DB.prepare(`
    SELECT user_id, username, display_name, role
    FROM users
    WHERE user_id = ? AND active = 1
    LIMIT 1
  `).bind(userId).first();
}

/* Login */

async function login(request, env) {
  if (request.method !== "POST") {
    return json({ ok: false, error: "ส่งข้อมูลด้วย POST เท่านั้น" }, 405);
  }

  const body = await readJson(request);

  if (!body?.username || typeof body.password !== "string") {
    return json({
      ok: false,
      error: "กรุณาระบุ Username และ Password"
    }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT user_id, username, display_name,
           password_hash, role, active
    FROM users
    WHERE username = ? COLLATE NOCASE
    LIMIT 1
  `).bind(String(body.username).trim()).first();

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

/* Inspections */

async function inspections(request, env, url) {
  const parts = url.pathname.split("/");
  const inspectionId = parts[3] || null;

  if (request.method === "GET") {
    if (inspectionId) {
      const inspection = await env.DB.prepare(`
        SELECT *
        FROM inspections
        WHERE inspection_id = ?
      `).bind(inspectionId).first();

      if (!inspection) {
        return json({ ok: false, error: "ไม่พบรายการตรวจ" }, 404);
      }

      const attempts = await env.DB.prepare(`
        SELECT *
        FROM inspection_attempts
        WHERE inspection_id = ?
        ORDER BY attempt_no
      `).bind(inspectionId).all();

      const handovers = await env.DB.prepare(`
        SELECT *
        FROM key_handovers
        WHERE inspection_id = ?
        ORDER BY handed_over_at DESC
      `).bind(inspectionId).all();

      return json({
        ok: true,
        inspection,
        attempts: attempts.results || [],
        handovers: handovers.results || []
      });
    }

    const search = String(url.searchParams.get("search") || "").trim();
    const like = `%${search}%`;

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
        a.decision
      FROM inspections i
      LEFT JOIN inspection_attempts a
        ON a.inspection_id = i.inspection_id
       AND a.attempt_no = i.attempt_count
      WHERE
        ? = ''
        OR i.employee_gid LIKE ?
        OR i.employee_name LIKE ?
        OR i.department LIKE ?
      ORDER BY i.updated_at DESC
      LIMIT 200
    `).bind(search, like, like, like).all();

    return json({
      ok: true,
      inspections: result.results || []
    });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "Method ไม่ถูกต้อง" }, 405);
  }

  const body = await readJson(request);

  if (inspectionId) {
    return addAttempt(request, env, inspectionId, body);
  }

  const employeeGid = String(body?.employee_gid || "").trim();
  const employeeName = String(body?.employee_name || "").trim();
  const department = String(body?.department || "").trim();
  const recordedBy = String(body?.recorded_by || "").trim();

  const resultMgL = Number(body?.result_mg_l);
  const decision = String(body?.decision || "");
  const notes = String(body?.notes || "");

  if (!employeeGid || !employeeName || !department || !recordedBy) {
    return json({
      ok: false,
      error: "กรุณากรอก GID ชื่อ แผนก และผู้บันทึกให้ครบ"
    }, 400);
  }

  const user = await activeUser(env, recordedBy);

  if (!user) {
    return json({
      ok: false,
      error: "ไม่พบผู้บันทึก"
    }, 400);
  }

  const validation = validateResult(resultMgL, decision);

  if (validation) {
    return json({ ok: false, error: validation }, 400);
  }

  const inspectionIdNew = id();
  const attemptId = id();
  const timestamp = now();
  const status = decision === "Passed" ? "Passed" : "Awaiting2";

  const inspection = env.DB.prepare(`
    INSERT INTO inspections (
      inspection_id, employee_gid, employee_name, department,
      first_tested_at, last_tested_at, test_status,
      attempt_count, planned_vehicle_ids_json, notes,
      version, created_by, created_at, updated_by, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, '[]', ?, 1, ?, ?, ?, ?)
  `).bind(
    inspectionIdNew,
    employeeGid,
    employeeName,
    department,
    timestamp,
    timestamp,
    status,
    notes,
    recordedBy,
    timestamp,
    recordedBy,
    timestamp
  );

  const attempt = env.DB.prepare(`
    INSERT INTO inspection_attempts (
      attempt_id, inspection_id, attempt_no, tested_at,
      result_mg_l, decision, rule_version, notes,
      recorded_by, recorded_at
    )
    VALUES (?, ?, 1, ?, ?, ?, 'zero-only-v1', ?, ?, ?)
  `).bind(
    attemptId,
    inspectionIdNew,
    timestamp,
    resultMgL,
    decision,
    notes,
    recordedBy,
    timestamp
  );

  try {
    await env.DB.batch([inspection, attempt]);
  } catch {
    return json({
      ok: false,
      error: "บันทึกรายการตรวจไม่สำเร็จ"
    }, 500);
  }

  return json({
    ok: true,
    inspection_id: inspectionIdNew,
    attempt_no: 1,
    test_status: status
  }, 201);
}

function validateResult(value, decision) {
  if (!Number.isFinite(value) || value < 0) {
    return "ค่าแอลกอฮอล์ต้องเป็นตัวเลขตั้งแต่ 0 ขึ้นไป";
  }

  if (!["Passed", "NotPassed"].includes(decision)) {
    return "กรุณาเลือก Passed หรือ NotPassed";
  }

  if (value === 0 && decision !== "Passed") {
    return "ค่า 0 ต้องเลือก Passed";
  }

  if (value > 0 && decision !== "NotPassed") {
    return "ค่ามากกว่า 0 ต้องเลือก NotPassed";
  }

  return null;
}

async function addAttempt(request, env, inspectionId, body) {
  const inspection = await env.DB.prepare(`
    SELECT *
    FROM inspections
    WHERE inspection_id = ?
  `).bind(inspectionId).first();

  if (!inspection) {
    return json({ ok: false, error: "ไม่พบรายการตรวจ" }, 404);
  }

  if (Number(inspection.attempt_count) >= 3) {
    return json({
      ok: false,
      error: "รายการนี้ตรวจครบ 3 ครั้งแล้ว"
    }, 400);
  }

  const recordedBy = String(body?.recorded_by || "").trim();
  const user = await activeUser(env, recordedBy);

  if (!user) {
    return json({ ok: false, error: "ไม่พบผู้บันทึก" }, 400);
  }

  const resultMgL = Number(body?.result_mg_l);
  const decision = String(body?.decision || "");
  const notes = String(body?.notes || "");

  const validation = validateResult(resultMgL, decision);

  if (validation) {
    return json({ ok: false, error: validation }, 400);
  }

  const attemptNo = Number(inspection.attempt_count) + 1;
  const timestamp = now();

  let status = "Failed";

  if (decision === "Passed") {
    status = "Passed";
  } else if (attemptNo === 2) {
    status = "Awaiting3";
  }

  const attempt = env.DB.prepare(`
    INSERT INTO inspection_attempts (
      attempt_id, inspection_id, attempt_no, tested_at,
      result_mg_l, decision, rule_version, notes,
      recorded_by, recorded_at
    )
    VALUES (?, ?, ?, ?, ?, ?, 'zero-only-v1', ?, ?, ?)
  `).bind(
    id(),
    inspectionId,
    attemptNo,
    timestamp,
    resultMgL,
    decision,
    notes,
    recordedBy,
    timestamp
  );

  const update = env.DB.prepare(`
    UPDATE inspections
    SET
      last_tested_at = ?,
      test_status = ?,
      attempt_count = ?,
      notes = ?,
      version = version + 1,
      updated_by = ?,
      updated_at = ?
    WHERE inspection_id = ?
  `).bind(
    timestamp,
    status,
    attemptNo,
    notes,
    recordedBy,
    timestamp,
    inspectionId
  );

  try {
    await env.DB.batch([attempt, update]);
  } catch {
    return json({
      ok: false,
      error: "บันทึก Attempt ไม่สำเร็จ"
    }, 500);
  }

  return json({
    ok: true,
    inspection_id: inspectionId,
    attempt_no: attemptNo,
    test_status: status
  });
}

/* Vehicles */

async function vehicles(request, env, url) {
  if (request.method === "GET") {
    const result = await env.DB.prepare(`
      SELECT *
      FROM vehicles
      ORDER BY active DESC, plate
    `).all();

    return json({
      ok: true,
      vehicles: result.results || []
    });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "Method ไม่ถูกต้อง" }, 405);
  }

  const body = await readJson(request);
  const plate = String(body?.plate || "").trim();
  const vehicleName = String(body?.vehicle_name || "").trim();
  const createdBy = String(body?.created_by || "").trim();

  if (!plate || !createdBy) {
    return json({
      ok: false,
      error: "กรุณาระบุทะเบียนรถและผู้บันทึก"
    }, 400);
  }

  if (!await activeUser(env, createdBy)) {
    return json({ ok: false, error: "ไม่พบผู้บันทึก" }, 400);
  }

  try {
    await env.DB.prepare(`
      INSERT INTO vehicles (
        vehicle_id, plate, vehicle_name, active,
        created_by, created_at, updated_at
      )
      VALUES (?, ?, ?, 1, ?, ?, ?)
    `).bind(
      id(),
      plate,
      vehicleName,
      createdBy,
      now(),
      now()
    ).run();
  } catch {
    return json({
      ok: false,
      error: "เพิ่มรถไม่สำเร็จ อาจมีข้อมูลซ้ำ"
    }, 400);
  }

  return json({ ok: true }, 201);
}

/* Key handovers and returns */

async function handovers(request, env) {
  if (request.method === "GET") {
    const result = await env.DB.prepare(`
      SELECT *
      FROM key_handovers
      ORDER BY handed_over_at DESC
      LIMIT 200
    `).all();

    return json({
      ok: true,
      handovers: result.results || []
    });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "Method ไม่ถูกต้อง" }, 405);
  }

  const body = await readJson(request);

  const inspectionId = String(body?.inspection_id || "");
  const vehicleId = String(body?.vehicle_id || "");
  const handedOverBy = String(body?.handed_over_by || "");
  const notes = String(body?.notes || "");

  const inspector = await activeUser(env, handedOverBy);

  if (!inspector) {
    return json({ ok: false, error: "ไม่พบผู้ส่งมอบ" }, 400);
  }

  const vehicle = await env.DB.prepare(`
    SELECT *
    FROM vehicles
    WHERE vehicle_id = ? AND active = 1
  `).bind(vehicleId).first();

  if (!vehicle) {
    return json({
      ok: false,
      error: "ไม่พบรถหรือรถถูกปิดใช้งาน"
    }, 400);
  }

  const inspection = await env.DB.prepare(`
    SELECT *
    FROM inspections
    WHERE inspection_id = ?
  `).bind(inspectionId).first();

  if (!inspection) {
    return json({ ok: false, error: "ไม่พบรายการตรวจ" }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT handover_id
    FROM key_handovers
    WHERE vehicle_id = ? AND status = 'Borrowed'
    LIMIT 1
  `).bind(vehicleId).first();

  if (existing) {
    return json({
      ok: false,
      error: "รถคันนี้ถูกยืมกุญแจอยู่แล้ว"
    }, 400);
  }

  try {
    await env.DB.prepare(`
      INSERT INTO key_handovers (
        handover_id, inspection_id, vehicle_id,
        plate_snapshot, vehicle_name_snapshot,
        handed_over_at, handed_over_by, status, notes
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Borrowed', ?)
    `).bind(
      id(),
      inspectionId,
      vehicleId,
      vehicle.plate,
      vehicle.vehicle_name,
      now(),
      handedOverBy,
      notes
    ).run();
  } catch {
    return json({
      ok: false,
      error: "ส่งมอบกุญแจไม่สำเร็จ"
    }, 400);
  }

  return json({ ok: true }, 201);
}

async function returns(request, env) {
  if (request.method !== "POST") {
    return json({ ok: false, error: "Method ไม่ถูกต้อง" }, 405);
  }

  const body = await readJson(request);

  const handoverId = String(body?.handover_id || "");
  const returnedByGid = String(body?.returned_by_gid || "").trim();
  const returnedByName = String(body?.returned_by_name || "").trim();
  const returnedByDepartment =
    String(body?.returned_by_department || "").trim();
  const receivedBy = String(body?.received_by || "").trim();
  const notes = String(body?.notes || "");

  if (!handoverId || !returnedByGid || !returnedByName || !receivedBy) {
    return json({
      ok: false,
      error: "กรุณากรอกข้อมูลการคืนกุญแจให้ครบ"
    }, 400);
  }

  if (!await activeUser(env, receivedBy)) {
    return json({ ok: false, error: "ไม่พบผู้รับคืน" }, 400);
  }

  const handover = await env.DB.prepare(`
    SELECT *
    FROM key_handovers
    WHERE handover_id = ? AND status = 'Borrowed'
  `).bind(handoverId).first();

  if (!handover) {
    return json({
      ok: false,
      error: "ไม่พบรายการยืมกุญแจที่ยังไม่คืน"
    }, 400);
  }

  try {
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO key_returns (
          return_id, handover_id,
          returned_by_gid, returned_by_name,
          returned_by_department, returned_at,
          received_by, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id(),
        handoverId,
        returnedByGid,
        returnedByName,
        returnedByDepartment,
        now(),
        receivedBy,
        notes
      ),
      env.DB.prepare(`
        UPDATE key_handovers
        SET status = 'Returned'
        WHERE handover_id = ?
      `).bind(handoverId)
    ]);
  } catch {
    return json({
      ok: false,
      error: "บันทึกการคืนกุญแจไม่สำเร็จ"
    }, 400);
  }

  return json({ ok: true });
}

/* Main Worker */

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
        return await login(request, env);
      }

      if (url.pathname === "/api/inspections" ||
          url.pathname.startsWith("/api/inspections/")) {
        return await inspections(request, env, url);
      }

      if (url.pathname === "/api/vehicles") {
        return await vehicles(request, env, url);
      }

      if (url.pathname === "/api/handovers") {
        return await handovers(request, env);
      }

      if (url.pathname === "/api/returns") {
        return await returns(request, env);
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
