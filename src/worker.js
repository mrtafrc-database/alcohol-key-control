/*
 * Alcohol Test & Key Control
 * Cloudflare Worker + D1
 *
 * Required D1 binding: DB
 * Required schema migration: version 2, manual-v1
 *
 * No Supabase, setup token or additional secrets.
 */
const ALLOWED_ORIGINS = new Set([
  "https://mrtafrc-database.github.io"
]);
const SESSION_HOURS = 12;
const PASSWORD_ITERATIONS = 100000;
const encoder = new TextEncoder();
class AppError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}
const uuid = () => crypto.randomUUID();
const timestamp = () => new Date().toISOString();
function text(value, label, max = 200, required = true) {
  if (value === undefined || value === null) value = "";
  if (typeof value !== "string") {
    throw new AppError(`${label} ต้องเป็นข้อความ`);
  }
  const result = value.trim();
  if ((required && !result) || result.length > max) {
    throw new AppError(`ตรวจสอบ ${label} ความยาวไม่เกิน ${max} ตัวอักษร`);
  }
  return result;
}
function employee(value) {
  if (!value || typeof value !== "object") {
    throw new AppError("กรุณากรอกข้อมูลพนักงาน");
  }
  const gid = text(value.gid, "GID", 80);
  if (!/^[A-Za-z0-9_.-]+$/.test(gid)) {
    throw new AppError("GID ใช้ตัวอักษร ตัวเลข จุด ขีดกลาง หรือขีดล่าง");
  }
  return {
    gid,
    name: text(value.name, "ชื่อพนักงาน"),
    department: text(value.department, "แผนก")
  };
}
function isoDate(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new AppError("กรุณาระบุวันเวลาตรวจ");
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new AppError("วันเวลาตรวจไม่ถูกต้อง");
  }
  return date.toISOString();
}
function decisionResult(data) {
  if (!["Passed", "NotPassed"].includes(data.decision)) {
    throw new AppError("กรุณาเลือกผ่าน หรือไม่ผ่าน");
  }
  if (
    data.result === undefined ||
    data.result === null ||
    !["number", "string"].includes(typeof data.result) ||
    String(data.result).trim() === ""
  ) {
    throw new AppError("กรุณากรอกผลตรวจ");
  }
  const result = Number(data.result);
  if (!Number.isFinite(result) || result < 0 || result > 100000) {
    throw new AppError("ผลตรวจต้องเป็นตัวเลขตั้งแต่ 0 ถึง 100000 mg/L");
  }
  if (data.decision === "Passed" && result !== 0) {
    throw new AppError(
      "ผลตรวจมากกว่า 0 mg/L ไม่สามารถเลือกผ่านได้ กรุณาเลือกไม่ผ่าน"
    );
  }
  return {
    result,
    decision: data.decision,
    testedAt: isoDate(data.testedAt),
    notes: text(data.notes, "หมายเหตุ", 2000, false)
  };
}
function vehicleIds(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 30) {
    throw new AppError("เลือกรถได้ไม่เกิน 30 คัน");
  }
  const ids = value.map(id => text(id, "Vehicle ID", 80));
  if (new Set(ids).size !== ids.length) {
    throw new AppError("เลือกรถซ้ำ กรุณาตรวจรายการ");
  }
  return ids;
}
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function base64ToBytes(value) {
  return Uint8Array.from(atob(value), ch => ch.charCodeAt(0));
}
async function sha256(value) {
  const buffer = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
function equalString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}
async function derivePassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    key,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}
async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await derivePassword(
    password,
    salt,
    PASSWORD_ITERATIONS
  );
  return [
    "pbkdf2",
    PASSWORD_ITERATIONS,
    bytesToBase64(salt),
    derived
  ].join("$");
}
async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  if (!stored.startsWith("pbkdf2$")) {
    // Compatibility only for existing plaintext accounts.
    return equalString(password, stored);
  }
  try {
    const [prefix, iterationText, saltText, expected] = stored.split("$");
    const iterations = Number(iterationText);
    if (
      prefix !== "pbkdf2" ||
      !Number.isInteger(iterations) ||
      iterations < 10000 ||
      iterations > 100000
    ) {
      return false;
    }
    const actual = await derivePassword(
      password,
      base64ToBytes(saltText),
      iterations
    );
    return equalString(actual, expected);
  } catch {
    return false;
  }
}
function passwordValue(value) {
  if (
    typeof value !== "string" ||
    value.length < 8 ||
    value.length > 128
  ) {
    throw new AppError("รหัสผ่านต้องมี 8–128 ตัวอักษร");
  }
  return value;
}
function publicUser(user) {
  return {
    userId: user.user_id,
    username: user.username,
    displayName: user.display_name,
    role: user.role,
    mustChangePassword: Boolean(user.must_change_password)
  };
}
async function all(db, sql, ...args) {
  const result = await db.prepare(sql).bind(...args).all();
  return result.results || [];
}
function statement(db, sql, ...args) {
  return db.prepare(sql).bind(...args);
}
function auditStatement(db, user, action, entityType, entityId, details = {}) {
  return statement(
    db,
    `INSERT INTO audit_log
      (audit_id, actor_user_id, action, entity_type, entity_id,
       details_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    uuid(),
    user.user_id,
    action,
    entityType,
    entityId,
    JSON.stringify(details),
    timestamp()
  );
}
async function authenticated(request, db, data) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";
  if (!token || token.length > 300) {
    throw new AppError("SESSION_EXPIRED: กรุณาเข้าสู่ระบบ", 401);
  }
  const tokenHash = await sha256(token);
  const user = await db.prepare(
    `SELECT u.*, s.token_hash AS current_token_hash
     FROM sessions s
     JOIN users u ON u.user_id = s.user_id
     WHERE s.token_hash = ?
       AND s.revoked_at IS NULL
       AND s.expires_at > ?
       AND s.session_version = u.session_version
       AND u.active = 1`
  ).bind(tokenHash, timestamp()).first();
  if (!user) {
    throw new AppError("SESSION_EXPIRED: กรุณาเข้าสู่ระบบใหม่", 401);
  }
  if (
    user.must_change_password &&
    !["changePassword", "logout"].includes(data.action)
  ) {
    throw new AppError("CHANGE_PASSWORD: เปลี่ยนรหัสผ่านก่อนใช้งาน", 403);
  }
  return user;
}
function requireAdmin(user) {
  if (user.role !== "Admin") {
    throw new AppError("เฉพาะ Admin เท่านั้น", 403);
  }
}
async function mutationContext(db, user, action, data) {
  const requestId = text(data.requestId, "Request ID", 120);
  const payload = { ...data };
  delete payload.token;
  delete payload.refreshView;
  delete payload.viewFilter;
  const hash = await sha256(JSON.stringify({ action, payload }));
  const existing = await db.prepare(
    `SELECT request_hash, response_json
     FROM mutation_requests
     WHERE user_id = ? AND request_id = ?`
  ).bind(user.user_id, requestId).first();
  if (existing && existing.request_hash !== hash) {
    throw new AppError(
      "Request ID นี้ถูกใช้กับข้อมูลอื่นแล้ว กรุณาเปิดหน้าต่างใหม่",
      409
    );
  }
  return {
    requestId,
    hash,
    cached: existing ? JSON.parse(existing.response_json) : null
  };
}
async function commitMutation(
  db,
  user,
  action,
  context,
  statements,
  output
) {
  if (context.cached) return context.cached;
  const responseText = JSON.stringify(output);
  statements.push(statement(
    db,
    `INSERT INTO mutation_requests
      (user_id, request_id, action, request_hash, response_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    user.user_id,
    context.requestId,
    action,
    context.hash,
    responseText,
    timestamp()
  ));
  try {
    // D1 batch executes the statements as one transaction.
    await db.batch(statements);
    return output;
  } catch (error) {
    const existing = await db.prepare(
      `SELECT request_hash, response_json
       FROM mutation_requests
       WHERE user_id = ? AND request_id = ?`
    ).bind(user.user_id, context.requestId).first();
    if (existing && existing.request_hash === context.hash) {
      return JSON.parse(existing.response_json);
    }
    const message = String(error.message || error);
    if (
      /UNIQUE|ATTEMPT_SEQUENCE|INSPECTION_NOT_AWAITING/i.test(message)
    ) {
      throw new AppError(
        "ข้อมูลเปลี่ยนแล้ว หรือรถยังไม่คืนกุญแจ กรุณารีเฟรชและตรวจรายการ",
        409
      );
    }
    if (/ZERO_PASS_REQUIRED/i.test(message)) {
      throw new AppError(
        "ผลตรวจต้องเป็น 0 mg/L เท่านั้นจึงเลือกผ่านได้",
        409
      );
    }
    if (/KEY_HANDOVER_NOT_ALLOWED/i.test(message)) {
      throw new AppError(
        "มอบกุญแจไม่ได้: ตรวจผลล่าสุดและรายการเบิกรถ",
        409
      );
    }
    if (/VEHICLE_INACTIVE/i.test(message)) {
      throw new AppError("รถถูกปิดใช้งาน กรุณาเลือกใหม่", 409);
    }
    throw error;
  }
}
async function loadVehicles(db, activeOnly = true) {
  return all(
    db,
    `SELECT
       v.vehicle_id AS VehicleID,
       v.plate AS Plate,
       v.vehicle_name AS VehicleName,
       v.owner_department AS OwnerDepartment,
       v.active AS Active,
       EXISTS (
         SELECT 1 FROM key_handovers h
         WHERE h.vehicle_id = v.vehicle_id
           AND h.status = 'Borrowed'
       ) AS Borrowed
     FROM vehicles v
     ${activeOnly ? "WHERE v.active = 1" : ""}
     ORDER BY
       CASE WHEN TRIM(v.owner_department) = '' THEN 1 ELSE 0 END,
       v.owner_department COLLATE NOCASE,
       v.plate COLLATE NOCASE`
  );
}
async function bootstrap(db, user) {
  const vehicles = await loadVehicles(db);
  return {
    user: publicUser(user),
    vehicles: vehicles.map(v => ({
      ...v,
      Active: Boolean(v.Active),
      Borrowed: Boolean(v.Borrowed)
    }))
  };
}
async function mainHistory(db, data) {
  const page = Math.max(1, Math.min(1000000, Number(data.page) || 1));
  const search = text(data.search, "คำค้นหา", 200, false);
  const status = text(data.status, "สถานะ", 30, false);
  const clauses = [];
  const args = [];
  if (search) {
    const term = `%${search.replace(/[\\%_]/g, ch => "\\" + ch)}%`;
    clauses.push(`(
      i.employee_gid LIKE ? ESCAPE '\\'
      OR i.employee_name LIKE ? ESCAPE '\\'
      OR i.department LIKE ? ESCAPE '\\'
      OR i.notes LIKE ? ESCAPE '\\'
      OR h.plate_snapshot LIKE ? ESCAPE '\\'
      OR h.vehicle_name_snapshot LIKE ? ESCAPE '\\'
      OR EXISTS (
        SELECT 1 FROM inspection_attempts sa
        WHERE sa.inspection_id = i.inspection_id
          AND sa.notes LIKE ? ESCAPE '\\'
      )
    )`);
    args.push(term, term, term, term, term, term, term);
  }
  if (status === "Awaiting") {
    clauses.push("i.test_status IN ('Awaiting2', 'Awaiting3')");
  } else if (["Passed", "Failed", "Legacy"].includes(status)) {
    clauses.push("i.test_status = ?");
    args.push(status);
  } else if (["Borrowed", "Returned"].includes(status)) {
    clauses.push("h.status = ?");
    args.push(status);
  } else if (status === "NoKey") {
    clauses.push(
      "h.handover_id IS NULL AND json_array_length(i.planned_vehicle_ids_json) = 0"
    );
  } else if (status && status !== "NotIssued") {
    throw new AppError("สถานะตัวกรองไม่ถูกต้อง");
  }
  if (status === "NotIssued") {
    clauses.push(
      "h.handover_id IS NULL AND json_array_length(i.planned_vehicle_ids_json) > 0"
    );
  }
  const from = `
    FROM inspections i
    LEFT JOIN key_handovers h ON h.inspection_id = i.inspection_id
    LEFT JOIN key_returns kr ON kr.handover_id = h.handover_id
    LEFT JOIN users hu ON hu.user_id = h.handed_over_by
    LEFT JOIN users ru ON ru.user_id = kr.received_by
  `;
  const where = clauses.length ? "WHERE " + clauses.join(" AND ") : "";
  const count = await db.prepare(
    `SELECT COUNT(*) AS total ${from} ${where}`
  ).bind(...args).first();
  const rows = await all(
    db,
    `SELECT
       i.inspection_id AS RecordID,
       i.employee_gid AS EmployeeID,
       i.employee_name AS EmployeeName,
       i.department AS Department,
       i.first_tested_at AS TestedAt,
       i.last_tested_at AS LastAttemptAt,
       i.test_status AS TestStatus,
       i.attempt_count AS AttemptCount,
       i.planned_vehicle_ids_json AS PlannedVehicleIDs,
       i.notes AS Notes,
       i.version AS Version,
       h.handover_id AS DetailID,
       h.vehicle_id AS VehicleID,
       h.plate_snapshot AS Plate,
       h.vehicle_name_snapshot AS VehicleName,
       h.handed_over_at AS BorrowedAt,
       hu.display_name AS HandoverByName,
       kr.returned_at AS ReturnedAt,
       ru.display_name AS ReceivedByName,
       kr.returned_by_gid AS ReturnedByGID,
       kr.returned_by_name AS ReturnedByName,
       kr.returned_by_department AS ReturnedByDepartment,
       kr.notes AS ReturnNotes,
       CASE
         WHEN h.handover_id IS NOT NULL THEN h.status
         WHEN json_array_length(i.planned_vehicle_ids_json) > 0
           THEN 'NotIssued'
         ELSE 'NoKey'
       END AS KeyStatus
     ${from}
     ${where}
     ORDER BY i.first_tested_at DESC, i.inspection_id DESC,
              h.handed_over_at DESC, h.handover_id
     LIMIT 50 OFFSET ?`,
    ...args,
    (page - 1) * 50
  );
  const inspectionIds = [...new Set(rows.map(r => r.RecordID))];
  const grouped = new Map();
  if (inspectionIds.length) {
    const placeholders = inspectionIds.map(() => "?").join(",");
    const attempts = await all(
      db,
      `SELECT
         a.inspection_id AS RecordID,
         a.attempt_no AS AttemptNo,
         a.result_mg_l AS Result,
         a.decision AS Decision,
         a.tested_at AS TestedAt,
         a.notes AS Notes,
         a.recorded_by AS RecordedBy,
         u.display_name AS RecordedByName,
         a.recorded_at AS RecordedAt,
         a.rule_version AS RuleVersion
       FROM inspection_attempts a
       JOIN users u ON u.user_id = a.recorded_by
       WHERE a.inspection_id IN (${placeholders})
       ORDER BY a.attempt_no`,
      ...inspectionIds
    );
    for (const attempt of attempts) {
      if (!grouped.has(attempt.RecordID)) grouped.set(attempt.RecordID, []);
      grouped.get(attempt.RecordID).push(attempt);
    }
  }
  for (const row of rows) {
    row.Attempts = grouped.get(row.RecordID) || [];
  }
  return {
    rows,
    total: count?.total || 0,
    page,
    pageSize: 50
  };
}
async function selectedVehicles(db, ids, requireAvailable) {
  if (!ids.length) return [];
  const placeholders = ids.map(() => "?").join(",");
  const rows = await all(
    db,
    `SELECT v.*,
       EXISTS (
         SELECT 1 FROM key_handovers h
         WHERE h.vehicle_id = v.vehicle_id AND h.status = 'Borrowed'
       ) AS borrowed
     FROM vehicles v
     WHERE v.vehicle_id IN (${placeholders})`,
    ...ids
  );
  const byId = new Map(rows.map(v => [v.vehicle_id, v]));
  return ids.map(id => {
    const vehicle = byId.get(id);
    if (!vehicle || !vehicle.active) {
      throw new AppError("รถที่เลือกไม่มีอยู่ หรือถูกปิดใช้งาน", 409);
    }
    if (requireAvailable && vehicle.borrowed) {
      throw new AppError(
        `รถ ${vehicle.plate} ยังไม่คืนกุญแจ กรุณาเลือกใหม่`,
        409
      );
    }
    return vehicle;
  });
}
function handoverStatements(db, user, inspectionId, vehicles, notes = "") {
  const statements = [];
  for (const vehicle of vehicles) {
    const id = uuid();
    statements.push(statement(
      db,
      `INSERT INTO key_handovers
       (handover_id, inspection_id, vehicle_id, plate_snapshot,
        vehicle_name_snapshot, handed_over_at, handed_over_by,
        status, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Borrowed', ?)`,
      id,
      inspectionId,
      vehicle.vehicle_id,
      vehicle.plate,
      vehicle.vehicle_name,
      timestamp(),
      user.user_id,
      notes
    ));
    statements.push(auditStatement(
      db,
      user,
      "handoverKey",
      "key_handovers",
      id,
      {
        inspectionId,
        vehicleId: vehicle.vehicle_id,
        plate: vehicle.plate
      }
    ));
  }
  return statements;
}
async function inspect(db, user, data, isRetest) {
  const action = isRetest ? "submitAttempt" : "startInspection";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const input = decisionResult(data);
  const ids = vehicleIds(data.vehicleIds);
  const pass = input.decision === "Passed";
  const vehicles = await selectedVehicles(db, ids, pass);
  const statements = [];
  const createdAt = timestamp();
  let inspectionId;
  let attemptNo;
  let record;
  if (isRetest) {
    inspectionId = text(data.recordId, "Record ID", 100);
    record = await db.prepare(
      "SELECT * FROM inspections WHERE inspection_id = ?"
    ).bind(inspectionId).first();
    if (!record) throw new AppError("ไม่พบรายการตรวจ", 404);
    attemptNo = record.attempt_count + 1;
    if (
      attemptNo > 3 ||
      record.test_status !== "Awaiting" + attemptNo ||
      Number(data.attemptNo) !== attemptNo ||
      Number(data.version) !== record.version
    ) {
      throw new AppError(
        "รายการเปลี่ยนแล้ว หรือไม่อยู่ในขั้นตอนตรวจซ้ำ กรุณารีเฟรช",
        409
      );
    }
    if (input.testedAt < record.last_tested_at) {
      throw new AppError("เวลาตรวจซ้ำต้องไม่ก่อนเวลาตรวจครั้งก่อน");
    }
  } else {
    inspectionId = uuid();
    attemptNo = 1;
  }
  const status = pass
    ? "Passed"
    : attemptNo < 3
      ? "Awaiting" + (attemptNo + 1)
      : "Failed";
  if (!isRetest) {
    const person = employee(data.employee);
    statements.push(statement(
      db,
      `INSERT INTO inspections
       (inspection_id, employee_gid, employee_name, department,
        first_tested_at, last_tested_at, test_status, attempt_count,
        planned_vehicle_ids_json, notes, version,
        created_by, created_at, updated_by, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, ?, ?, ?)`,
      inspectionId,
      person.gid,
      person.name,
      person.department,
      input.testedAt,
      input.testedAt,
      status,
      JSON.stringify(ids),
      input.notes,
      user.user_id,
      createdAt,
      user.user_id,
      createdAt
    ));
  }
  statements.push(statement(
    db,
    `INSERT INTO inspection_attempts
     (attempt_id, inspection_id, attempt_no, tested_at, result_mg_l,
      decision, rule_version, notes, recorded_by, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, 'manual-v1', ?, ?, ?)`,
    uuid(),
    inspectionId,
    attemptNo,
    input.testedAt,
    input.result,
    input.decision,
    input.notes,
    user.user_id,
    createdAt
  ));
  if (isRetest) {
    statements.push(statement(
      db,
      `UPDATE inspections
       SET last_tested_at = ?, test_status = ?, attempt_count = ?,
           planned_vehicle_ids_json = ?, version = version + 1,
           updated_by = ?, updated_at = ?
       WHERE inspection_id = ? AND version = ?`,
      input.testedAt,
      status,
      attemptNo,
      JSON.stringify(ids),
      user.user_id,
      createdAt,
      inspectionId,
      record.version
    ));
  }
  statements.push(auditStatement(
    db,
    user,
    action,
    "inspections",
    inspectionId,
    {
      attemptNo,
      result: input.result,
      decision: input.decision,
      ruleVersion: "manual-v1",
      vehicleIds: ids
    }
  ));
  if (pass && vehicles.length) {
    statements.push(...handoverStatements(
      db,
      user,
      inspectionId,
      vehicles,
      input.notes
    ));
  }
  return commitMutation(
    db,
    user,
    action,
    context,
    statements,
    {
      recordId: inspectionId,
      attemptNo,
      testStatus: status,
      message: pass
        ? vehicles.length
          ? `บันทึกผลผ่าน และมอบกุญแจ ${vehicles.length} คันแล้ว`
          : "บันทึกผลผ่านแล้ว — ไม่เบิกกุญแจ"
        : attemptNo < 3
          ? `บันทึกไม่ผ่าน — รอตรวจครั้งที่ ${attemptNo + 1}`
          : "บันทึกไม่ผ่าน — จบการตรวจครั้งที่ 3"
    }
  );
}
async function returnKey(db, user, data) {
  const action = "returnKey";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const id = text(data.detailId, "Handover ID", 100);
  const person = employee(data.returnedBy);
  const notes = text(data.notes, "หมายเหตุ", 2000, false);
  const handover = await db.prepare(
    "SELECT * FROM key_handovers WHERE handover_id = ?"
  ).bind(id).first();
  if (!handover) throw new AppError("ไม่พบรายการเบิกกุญแจ", 404);
  if (handover.status !== "Borrowed") {
    throw new AppError("กุญแจรายการนี้คืนแล้ว กรุณารีเฟรช", 409);
  }
  const returnId = uuid();
  const returnedAt = timestamp();
  return commitMutation(
    db,
    user,
    action,
    context,
    [
      statement(
        db,
        `INSERT INTO key_returns
         (return_id, handover_id, returned_by_gid, returned_by_name,
          returned_by_department, returned_at, received_by, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        returnId,
        id,
        person.gid,
        person.name,
        person.department,
        returnedAt,
        user.user_id,
        notes
      ),
      statement(
        db,
        `UPDATE key_handovers SET status = 'Returned'
         WHERE handover_id = ? AND status = 'Borrowed'`,
        id
      ),
      auditStatement(
        db,
        user,
        action,
        "key_returns",
        returnId,
        { handoverId: id, returnedByGid: person.gid }
      )
    ],
    { message: `รับคืนกุญแจ ${handover.plate_snapshot} แล้ว` }
  );
}
async function handoverKey(db, user, data) {
  const action = "handoverKey";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const id = text(data.recordId, "Record ID", 100);
  const ids = vehicleIds(data.vehicleIds);
  const notes = text(data.notes, "หมายเหตุ", 2000, false);
  if (!ids.length) throw new AppError("กรุณาเลือกรถ");
  const record = await db.prepare(
    "SELECT * FROM inspections WHERE inspection_id = ?"
  ).bind(id).first();
  if (!record) throw new AppError("ไม่พบรายการตรวจ", 404);
  if (record.test_status !== "Passed") {
    throw new AppError("ต้องผ่านการตรวจก่อนมอบกุญแจ", 409);
  }
  const latest = await db.prepare(
    `SELECT result_mg_l, decision
     FROM inspection_attempts
     WHERE inspection_id = ? AND attempt_no = ?`
  ).bind(id, record.attempt_count).first();
  if (
    !latest ||
    latest.decision !== "Passed" ||
    Number(latest.result_mg_l) !== 0
  ) {
    throw new AppError(
      "ผลตรวจล่าสุดต้องเป็น 0 mg/L และผ่าน จึงมอบกุญแจได้",
      409
    );
  }
  let planned;
  try {
    planned = JSON.parse(record.planned_vehicle_ids_json || "[]");
  } catch {
    throw new AppError("ข้อมูลรายการเบิกรถไม่ถูกต้อง", 409);
  }
  if (!Array.isArray(planned) || !planned.length) {
    throw new AppError("รายการนี้ไม่มีการเบิกรถ ไม่สามารถมอบกุญแจได้", 409);
  }
  if (ids.some(vehicleId => !planned.includes(vehicleId))) {
    throw new AppError("มอบได้เฉพาะรถที่อยู่ในรายการเบิกนี้", 409);
  }
  const alreadyIssued = await all(
    db,
    "SELECT vehicle_id FROM key_handovers WHERE inspection_id = ?",
    id
  );
  const issuedIds = new Set(alreadyIssued.map(v => v.vehicle_id));
  if (ids.some(vehicleId => issuedIds.has(vehicleId))) {
    throw new AppError(
      "รถนี้เคยเบิกในรายการตรวจนี้แล้ว หากเบิกใหม่ให้สร้างรายการตรวจใหม่",
      409
    );
  }
  const vehicles = await selectedVehicles(db, ids, true);
  return commitMutation(
    db,
    user,
    action,
    context,
    handoverStatements(db, user, id, vehicles, notes),
    { message: `มอบกุญแจ ${vehicles.length} คันแล้ว` }
  );
}
async function adminData(db, user) {
  requireAdmin(user);
  const [vehicles, users, audit] = await Promise.all([
    loadVehicles(db, false),
    all(
      db,
      `SELECT username AS Username, display_name AS DisplayName,
              role AS Role, active AS Active
       FROM users ORDER BY username COLLATE NOCASE`
    ),
    all(
      db,
      `SELECT a.created_at AS Timestamp, u.display_name AS Actor,
              a.action AS Action, a.entity_type AS EntityType,
              a.entity_id AS EntityID, a.details_json AS DetailsJSON
       FROM audit_log a
       JOIN users u ON u.user_id = a.actor_user_id
       ORDER BY a.created_at DESC LIMIT 100`
    )
  ]);
  return {
    vehicles: vehicles.map(v => ({
      ...v,
      Active: Boolean(v.Active),
      Borrowed: Boolean(v.Borrowed)
    })),
    users: users.map(u => ({ ...u, Active: Boolean(u.Active) })),
    audit
  };
}
async function saveVehicle(db, user, data) {
  requireAdmin(user);
  const action = "saveVehicle";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const id = text(data.vehicleId, "Vehicle ID", 80);
  const plate = text(data.plate, "ทะเบียนรถ", 100);
  const name = text(data.vehicleName, "ชื่อรถ");
  const ownerDepartment = text(
    data.ownerDepartment,
    "แผนกเจ้าของรถ",
    80,
    false
  );
  const active = data.active === true ? 1 : 0;
  const at = timestamp();
  return commitMutation(
    db,
    user,
    action,
    context,
    [
      statement(
        db,
        `INSERT INTO vehicles
         (vehicle_id, plate, vehicle_name, owner_department, active,
          created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(vehicle_id) DO UPDATE SET
           plate = excluded.plate,
           vehicle_name = excluded.vehicle_name,
           owner_department = excluded.owner_department,
           active = excluded.active,
           updated_at = excluded.updated_at`,
        id,
        plate,
        name,
        ownerDepartment,
        active,
        user.user_id,
        at,
        at
      ),
      auditStatement(
        db,
        user,
        action,
        "vehicles",
        id,
        {
          plate,
          vehicleName: name,
          ownerDepartment,
          active: Boolean(active)
        }
      )
    ],
    { message: "บันทึกข้อมูลรถแล้ว" }
  );
}
async function saveUser(db, user, data) {
  requireAdmin(user);
  const action = "saveUser";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const username = text(data.username, "Username", 80);
  const displayName = text(data.displayName, "ชื่อแสดงผล");
  const role = data.role;
  if (!/^[A-Za-z0-9_.-]+$/.test(username)) {
    throw new AppError("Username ใช้ภาษาอังกฤษ ตัวเลข จุด ขีดกลาง หรือขีดล่าง");
  }
  if (!["Admin", "Operator"].includes(role)) {
    throw new AppError("Role ต้องเป็น Admin หรือ Operator");
  }
  const active = data.active === true ? 1 : 0;
  const existing = await db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).bind(username).first();
  if (
    existing?.user_id === user.user_id &&
    (!active || role !== "Admin")
  ) {
    throw new AppError("ไม่สามารถปิดหรือถอดสิทธิ์ Admin ของบัญชีที่กำลังใช้");
  }
  const hasPassword = typeof data.password === "string" &&
    data.password.length > 0;
  if (!existing && !hasPassword) {
    throw new AppError("บัญชีใหม่ต้องระบุรหัสผ่านเริ่มต้น");
  }
  const hash = hasPassword
    ? await passwordHash(passwordValue(data.password))
    : existing.password_hash;
  const id = existing?.user_id || uuid();
  const at = timestamp();
  const mustChange = hasPassword
    ? 1
    : existing?.must_change_password || 0;
  const version = (existing?.session_version || 0) + 1;
  return commitMutation(
    db,
    user,
    action,
    context,
    [
      statement(
        db,
        `INSERT INTO users
         (user_id, username, display_name, password_hash, role,
          active, must_change_password, session_version,
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(username) DO UPDATE SET
           display_name = excluded.display_name,
           password_hash = excluded.password_hash,
           role = excluded.role,
           active = excluded.active,
           must_change_password = excluded.must_change_password,
           session_version = excluded.session_version,
           updated_at = excluded.updated_at`,
        id,
        username,
        displayName,
        hash,
        role,
        active,
        mustChange,
        version,
        existing?.created_at || at,
        at
      ),
      auditStatement(
        db,
        user,
        action,
        "users",
        id,
        {
          username,
          role,
          active: Boolean(active),
          passwordReset: hasPassword
        }
      )
    ],
    { message: "บันทึกบัญชีผู้ใช้แล้ว — Session เดิมของบัญชีนี้ถูกยกเลิก" }
  );
}
async function changePassword(db, user, data) {
  const action = "changePassword";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  if (
    typeof data.currentPassword !== "string" ||
    !await verifyPassword(data.currentPassword, user.password_hash)
  ) {
    throw new AppError("รหัสผ่านเดิมไม่ถูกต้อง", 403);
  }
  const newPassword = passwordValue(data.newPassword);
  if (equalString(newPassword, data.currentPassword)) {
    throw new AppError("รหัสผ่านใหม่ต้องต่างจากรหัสผ่านเดิม");
  }
  const hash = await passwordHash(newPassword);
  return commitMutation(
    db,
    user,
    action,
    context,
    [
      statement(
        db,
        `UPDATE users
         SET password_hash = ?, must_change_password = 0,
             session_version = session_version + 1, updated_at = ?
         WHERE user_id = ?`,
        hash,
        timestamp(),
        user.user_id
      ),
      auditStatement(
        db,
        user,
        action,
        "users",
        user.user_id,
        {}
      )
    ],
    { message: "เปลี่ยนรหัสผ่านแล้ว กรุณาเข้าสู่ระบบใหม่" }
  );
}
async function login(db, data) {
  const username = text(data.username, "Username", 80);
  if (
    typeof data.password !== "string" ||
    !data.password ||
    data.password.length > 128
  ) {
    throw new AppError("Username หรือ Password ไม่ถูกต้อง", 401);
  }
  const user = await db.prepare(
    "SELECT * FROM users WHERE username = ? AND active = 1"
  ).bind(username).first();
  if (!user || !await verifyPassword(data.password, user.password_hash)) {
    throw new AppError("Username หรือ Password ไม่ถูกต้อง", 401);
  }
  const token = bytesToBase64(
    crypto.getRandomValues(new Uint8Array(32))
  ).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const tokenHash = await sha256(token);
  const createdAt = timestamp();
  const expiresAt = new Date(
    Date.now() + SESSION_HOURS * 3600000
  ).toISOString();
  const statements = [];
  if (!user.password_hash.startsWith("pbkdf2$")) {
    const hash = await passwordHash(data.password);
    statements.push(statement(
      db,
      `UPDATE users SET password_hash = ?, updated_at = ?
       WHERE user_id = ? AND password_hash = ?`,
      hash,
      createdAt,
      user.user_id,
      user.password_hash
    ));
  }
  statements.push(statement(
    db,
    `INSERT INTO sessions
     (token_hash, user_id, session_version, created_at, expires_at, revoked_at)
     VALUES (?, ?, ?, ?, ?, NULL)`,
    tokenHash,
    user.user_id,
    user.session_version,
    createdAt,
    expiresAt
  ));
  statements.push(auditStatement(
    db,
    user,
    "login",
    "users",
    user.user_id,
    {}
  ));
  statements.push(statement(
    db,
    "DELETE FROM sessions WHERE expires_at < ?",
    createdAt
  ));
  await db.batch(statements);
  return {
    token,
    expiresAt,
    user: publicUser(user)
  };
}
async function dispatch(request, db, data) {
  if (data.action === "login") return login(db, data);
  const user = await authenticated(request, db, data);
  switch (data.action) {
    case "logout":
      await db.prepare(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?"
      ).bind(timestamp(), user.current_token_hash).run();
      return { message: "ออกจากระบบแล้ว" };
    case "changePassword":
      return changePassword(db, user, data);
    case "bootstrap":
      return bootstrap(db, user);
    case "mainView": {
      const [base, history] = await Promise.all([
        bootstrap(db, user),
        mainHistory(db, data)
      ]);
      return { bootstrap: base, history };
    }
    case "startInspection":
      return inspect(db, user, data, false);
    case "submitAttempt":
      return inspect(db, user, data, true);
    case "returnKey":
      return returnKey(db, user, data);
    case "handoverKey":
      return handoverKey(db, user, data);
    case "adminData":
      return adminData(db, user);
    case "saveVehicle":
      return saveVehicle(db, user, data);
    case "saveUser":
      return saveUser(db, user, data);
    default:
      throw new AppError("ไม่พบ API action", 404);
  }
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const headers = {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Vary": "Origin",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "600"
    };
    const respond = (body, status = 200) =>
      new Response(JSON.stringify(body), { status, headers });
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return respond({ ok: false, error: "Origin ไม่ได้รับอนุญาต" }, 403);
    }
    if (origin) headers["Access-Control-Allow-Origin"] = origin;
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }
    try {
      if (!env.DB) throw new AppError("Worker ไม่มี D1 Binding ชื่อ DB", 503);
      const url = new URL(request.url);
      if (url.pathname === "/health" && request.method === "GET") {
        const migration = await env.DB.prepare(
          "SELECT MAX(version) AS version FROM schema_migrations"
        ).first();
        return respond({
          ok: true,
          service: "alcohol-key-control-api",
          database: "connected",
          schemaVersion: migration?.version || 0,
          apiVersion: "manual-ui-v1"
        });
      }
      if (
        request.method !== "POST" ||
        !["/api", "/api/login"].includes(url.pathname)
      ) {
        throw new AppError("Not found", 404);
      }
      if (!request.headers.get("Content-Type")?.includes("application/json")) {
        throw new AppError("ใช้ Content-Type: application/json", 415);
      }
      const raw = await request.text();
      if (raw.length > 100000) {
        throw new AppError("ข้อมูลที่ส่งมีขนาดใหญ่เกินไป", 413);
      }
      let data;
      try {
        data = JSON.parse(raw);
      } catch {
        throw new AppError("JSON ไม่ถูกต้อง");
      }
      if (!data || Array.isArray(data) || typeof data !== "object") {
        throw new AppError("ข้อมูล API ไม่ถูกต้อง");
      }
      if (url.pathname === "/api/login") data.action = "login";
      const result = await dispatch(request, env.DB, data);
      return respond({ ok: true, data: result });
    } catch (error) {
      if (error instanceof AppError) {
        return respond({ ok: false, error: error.message }, error.status);
      }
      const message = String(error.message || error);
      console.error("API failure:", message);
      if (/manual-v1|CHECK constraint/i.test(message)) {
        return respond(
          {
            ok: false,
            error: "D1 ยังไม่รองรับ manual-v1 กรุณารัน SQL Migration ก่อน"
          },
          503
        );
      }
      return respond(
        {
          ok: false,
          error: "บันทึกไม่สำเร็จ กรุณารีเฟรช หากยังเกิดซ้ำให้ตรวจ Worker Logs"
        },
        500
      );
    }
  }
};
