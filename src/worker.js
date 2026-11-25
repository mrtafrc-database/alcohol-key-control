/*
 * Alcohol Test & Key Control — Cloudflare Worker + D1
 * Required binding: DB
 *
 * Existing schema must support manual-v1 inspection attempts.
 * Additional columns:
 *   vehicles.owner_department
 *   inspection_attempts.inspector_name
 *   key_returns.receiver_name
 *
 * Run 01_staff_migration.sql for staff_master_v3, user_staff_access_v3,
 * and immutable staff_assignments_v3 snapshots before deploying.
 *
 * Install the single-vehicle and required-name database triggers
 * before enabling writes with this version.
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
  if (required && !result) {
    throw new AppError(`กรุณากรอก${label}`);
  }
  if (result.length > max) {
    throw new AppError(`${label} ต้องมีความยาวไม่เกิน ${max} ตัวอักษร`);
  }
  return result;
}

function employee(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
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

  if (data.decision === "NotPassed" && result === 0) {
    throw new AppError("ผลตรวจ 0 mg/L ต้องเลือกผ่าน ไม่สามารถเลือกไม่ผ่านได้");
  }
  return {
    result,
    decision: data.decision,
    testedAt: isoDate(data.testedAt),
    notes: text(data.notes, "หมายเหตุ", 2000, false),
    // Staff name is resolved server-side, not trusted from browser input.
    inspectorName: ""
  };
}

function vehicleIds(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 1) {
    throw new AppError("เลือกรถได้ไม่เกิน 1 คันต่อรายการตรวจ");
  }
  return value.map(id => text(id, "Vehicle ID", 80));
}

function parsePlannedVehicles(value) {
  let planned;
  try {
    planned = JSON.parse(value || "[]");
  } catch {
    throw new AppError("ข้อมูลรายการเบิกรถไม่ถูกต้อง", 409);
  }
  if (!Array.isArray(planned)) {
    throw new AppError("ข้อมูลรายการเบิกรถไม่ถูกต้อง", 409);
  }
  return planned;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), ch => ch.charCodeAt(0));
}

async function sha256(value) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );
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

  // Compatibility for existing plaintext accounts only.
  // Successful login upgrades these accounts to PBKDF2.
  if (!stored.startsWith("pbkdf2$")) {
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
    staffGroup: user.staff_group || "",
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

function auditStatement(
  db,
  user,
  action,
  entityType,
  entityId,
  details = {}
) {
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
    throw new AppError(
      "CHANGE_PASSWORD: เปลี่ยนรหัสผ่านก่อนใช้งาน",
      403
    );
  }
  const access = await db.prepare("SELECT staff_group FROM user_staff_access_v3 WHERE user_id = ?")
    .bind(user.user_id).first();
  user.staff_group = access?.staff_group || "";
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

  statements.push(statement(
    db,
    `INSERT INTO mutation_requests
     (user_id, request_id, action, request_hash, response_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    user.user_id,
    context.requestId,
    action,
    context.hash,
    JSON.stringify(output),
    timestamp()
  ));

  try {
    // Keep all writes and the idempotency record in one D1 transaction.
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

    if (/INSPECTOR_NAME_REQUIRED/i.test(message)) {
      throw new AppError("กรุณากรอกชื่อผู้ตรวจ", 400);
    }
    if (/RECEIVER_NAME_REQUIRED/i.test(message)) {
      throw new AppError("กรุณากรอกชื่อผู้รับคืน", 400);
    }
    if (/SINGLE_VEHICLE_REQUIRED/i.test(message)) {
      throw new AppError(
        "รายการตรวจนี้เคยมอบกุญแจแล้ว เบิกได้เพียง 1 คันต่อรายการตรวจ",
        409
      );
    }
    if (/ZERO_CANNOT_FAIL/i.test(message)) {
      throw new AppError("ผลตรวจ 0 mg/L ต้องเลือกผ่าน", 409);
    }
    if (/STAFF_INSPECTOR_MISMATCH|STAFF_RECEIVER_MISMATCH|STAFF_SNAPSHOT_IMMUTABLE/i.test(message)) {
      throw new AppError("ชื่อเจ้าหน้าที่ไม่ตรงกับข้อมูลยืนยัน หรือมีการแก้ไขประวัติที่ล็อกไว้", 409);
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
    if (/UNIQUE|ATTEMPT_SEQUENCE|INSPECTION_NOT_AWAITING/i.test(message)) {
      throw new AppError(
        "ข้อมูลเปลี่ยนแล้ว หรือรถยังไม่คืนกุญแจ กรุณารีเฟรชและตรวจรายการ",
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
         WHERE h.vehicle_id = v.vehicle_id AND h.status = 'Borrowed'
       ) AS Borrowed
     FROM vehicles v
     ${activeOnly ? "WHERE v.active = 1" : ""}
     ORDER BY
       CASE WHEN TRIM(v.owner_department) = '' THEN 1 ELSE 0 END,
       v.owner_department COLLATE NOCASE,
       v.plate COLLATE NOCASE`
  );
}

function canSelectStaffGroup(user, group) {
  return user.staff_group === group ||
    (user.role === "Admin" && user.staff_group === "All");
}
async function allowedStaff(db, user) {
  if (!["Store", "TRW/TRD", "SIG", "COM", "PSY/GRS", "All"].includes(user.staff_group)) return [];
  if (user.staff_group === "All" && user.role !== "Admin") return [];
  return all(db,
    `SELECT staff_id AS StaffID, display_name AS StaffName, staff_group AS StaffGroup
     FROM staff_master_v3 WHERE active=1 ${user.staff_group === "All" ? "" : "AND staff_group=?"}
     ORDER BY staff_group COLLATE NOCASE, display_name COLLATE NOCASE`,
    ...(user.staff_group === "All" ? [] : [user.staff_group]));
}
async function selectedStaff(db, user, id, label) {
  if (!user.staff_group) throw new AppError("บัญชียังไม่กำหนดกลุ่มเจ้าหน้าที่ กรุณาให้ Admin ตั้งค่าที่ผู้ใช้ / สิทธิ์", 403);
  const staffId = text(id, label, 80);
  const staff = await db.prepare(
    "SELECT staff_id, display_name AS staff_name, staff_group FROM staff_master_v3 WHERE staff_id=? AND active=1"
  ).bind(staffId).first();
  if (!staff || !canSelectStaffGroup(user, staff.staff_group)) {
    throw new AppError("เจ้าหน้าที่ที่เลือกไม่อยู่ในกลุ่มที่บัญชีมีสิทธิ์ หรือถูกปิดใช้งาน กรุณารีเฟรช", 403);
  }
  return staff;
}
async function staffIdentity(db, user, id, manualName, manualGroup, label) {
  if (id === "__manual__") {
    const name = text(manualName, label, 200);
    const group = text(manualGroup, "กลุ่มเจ้าหน้าที่", 20);
    if (!canSelectStaffGroup(user, group) || !["Store", "TRW/TRD", "SIG", "COM", "PSY/GRS"].includes(group)) {
      throw new AppError("การกรอกชื่อ Manual ต้องระบุกลุ่มที่บัญชีมีสิทธิ์", 403);
    }
    return {staff_id:null, staff_name:name, staff_group:group, source:"Manual"};
  }
  return {...await selectedStaff(db, user, id, label), source:"Roster"};
}
async function inspectionStaff(db, user, inspectionId) {
  const staff = await db.prepare(
    "SELECT staff_id, staff_name, staff_group, source FROM staff_assignments_v3 WHERE entity_type='inspection' AND entity_id=?"
  ).bind(inspectionId).first();
  if (!staff) throw new AppError("รายการเดิมยังไม่มีรหัสเจ้าหน้าที่ที่ยืนยันแล้ว กรุณาให้ Admin ตรวจสอบ ไม่เติมชื่อย้อนหลังอัตโนมัติ", 409);
  if (!canSelectStaffGroup(user, staff.staff_group)) {
    throw new AppError("รายการตรวจนี้เป็นของเจ้าหน้าที่ต่างกลุ่มกับบัญชีที่ใช้อยู่", 403);
  }
  // Keep the original snapshot for retests, even if the roster later changes.
  return staff;
}
function staffAssignment(db, type, id, staff) {
  return statement(db,
    "INSERT INTO staff_assignments_v3 (entity_type,entity_id,staff_id,staff_name,staff_group,source) VALUES (?,?,?,?,?,?)",
    type,id,staff.staff_id,staff.staff_name,staff.staff_group,staff.source);
}

async function bootstrap(db, user) {
  const vehicles = await loadVehicles(db);
  return {
    user: publicUser(user),
    staff: await allowedStaff(db, user),
    vehicles: vehicles.map(v => ({
      ...v,
      Active: Boolean(v.Active),
      Borrowed: Boolean(v.Borrowed)
    }))
  };
}

async function mainHistory(db, data) {
  const page = Math.max(
    1,
    Math.min(1000000, Math.floor(Number(data.page) || 1))
  );
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
  } else if (status === "NotIssued") {
    clauses.push(
      "h.handover_id IS NULL AND json_array_length(i.planned_vehicle_ids_json) > 0"
    );
  } else if (status) {
    throw new AppError("สถานะตัวกรองไม่ถูกต้อง");
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
       COALESCE((SELECT staff_name FROM staff_assignments_v3 sa
         WHERE sa.entity_type='handover' AND sa.entity_id=h.handover_id), hu.display_name) AS HandoverByName,
       kr.returned_at AS ReturnedAt,
       kr.receiver_name AS ReceivedByName,
       ru.display_name AS ReceivedRecordedByName,
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
         a.inspector_name AS InspectorName,
         (SELECT staff_id FROM staff_assignments_v3 sa WHERE sa.entity_type='inspection' AND sa.entity_id=a.inspection_id) AS InspectorStaffID,
         (SELECT source FROM staff_assignments_v3 sa WHERE sa.entity_type='inspection' AND sa.entity_id=a.inspection_id) AS InspectorSource,
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
      if (!grouped.has(attempt.RecordID)) {
        grouped.set(attempt.RecordID, []);
      }
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

function handoverStatements(
  db,
  user,
  inspectionId,
  vehicles,
  notes = "",
  staff
) {
  if (vehicles.length > 1) {
    throw new AppError("เบิกได้เพียง 1 คันต่อรายการตรวจ");
  }

  const statements = [];

  for (const vehicle of vehicles) {
    const id = uuid();
    statements.push(staffAssignment(db, "handover", id, staff));
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
        plate: vehicle.plate,
        staffId: staff.staff_id,
        staffName: staff.staff_name,
        staffSource: staff.source
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

    const previousPlanned = parsePlannedVehicles(
      record.planned_vehicle_ids_json
    );
    if (previousPlanned.length > 1) {
      throw new AppError(
        "รายการเดิมมีรถหลายคัน กรุณาให้ผู้ดูแลตรวจสอบก่อนดำเนินการต่อ ระบบไม่ลดรายการรถเดิมอัตโนมัติ",
        409
      );
    }

    attemptNo = Number(record.attempt_count) + 1;
    if (
      attemptNo > 3 ||
      record.test_status !== "Awaiting" + attemptNo ||
      Number(data.attemptNo) !== attemptNo ||
      Number(data.version) !== Number(record.version)
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

  const staff = isRetest
    ? await inspectionStaff(db, user, inspectionId)
    : await staffIdentity(db, user, data.inspectorStaffId, data.inspectorManualName, data.inspectorManualGroup, "ชื่อผู้ตรวจ/ผู้มอบกุญแจ");
  if (isRetest && data.inspectorStaffId && data.inspectorStaffId !== staff.staff_id) {
    throw new AppError("ตรวจซ้ำต้องใช้ผู้ตรวจคนเดิมจากครั้งที่ 1", 409);
  }
  input.inspectorName = staff.staff_name;
  if (!isRetest) statements.push(staffAssignment(db, "inspection", inspectionId, staff));

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

  // Insert the attempt BEFORE updating inspection.attempt_count/status.
  // validate_manual_attempt_sequence depends on the previous state.
  statements.push(statement(
    db,
    `INSERT INTO inspection_attempts
     (attempt_id, inspection_id, attempt_no, tested_at, result_mg_l,
      decision, rule_version, notes, recorded_by, recorded_at,
      inspector_name)
     VALUES (?, ?, ?, ?, ?, ?, 'manual-v1', ?, ?, ?, ?)`,
    uuid(),
    inspectionId,
    attemptNo,
    input.testedAt,
    input.result,
    input.decision,
    input.notes,
    user.user_id,
    createdAt,
    input.inspectorName
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
      vehicleIds: ids,
      inspectorName: input.inspectorName,
      inspectorStaffId: staff.staff_id,
      staffGroup: staff.staff_group,
      staffSource: staff.source
    }
  ));

  if (pass && vehicles.length) {
    statements.push(...handoverStatements(
      db,
      user,
      inspectionId,
      vehicles,
      input.notes,
      staff
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
          ? "บันทึกผลผ่าน และมอบกุญแจรถ 1 คันแล้ว"
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
  const receiver = await staffIdentity(db, user, data.receiverStaffId, data.receiverManualName, data.receiverManualGroup, "ชื่อผู้รับคืน");
  const receiverName = receiver.staff_name;
  const notes = text(data.notes, "หมายเหตุ", 2000, false);

  const handover = await db.prepare(
    "SELECT * FROM key_handovers WHERE handover_id = ?"
  ).bind(id).first();

  if (!handover) {
    throw new AppError("ไม่พบรายการเบิกกุญแจ", 404);
  }
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
      staffAssignment(db, "return", returnId, receiver),
      statement(
        db,
        `INSERT INTO key_returns
         (return_id, handover_id, returned_by_gid, returned_by_name,
          returned_by_department, returned_at, received_by, notes,
          receiver_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        returnId,
        id,
        person.gid,
        person.name,
        person.department,
        returnedAt,
        user.user_id,
        notes,
        receiverName
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
        {
          handoverId: id,
          returnedByGid: person.gid,
          receiverStaffId: receiver.staff_id,
          staffGroup: receiver.staff_group,
          staffSource: receiver.source,
          receiverName
        }
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
    latest.result_mg_l === null ||
    latest.result_mg_l === undefined ||
    String(latest.result_mg_l).trim() === "" ||
    Number(latest.result_mg_l) !== 0
  ) {
    throw new AppError(
      "ผลตรวจล่าสุดต้องเป็น 0 mg/L และผ่าน จึงมอบกุญแจได้",
      409
    );
  }

  const planned = parsePlannedVehicles(
    record.planned_vehicle_ids_json
  );

  if (!planned.length) {
    throw new AppError(
      "รายการนี้ไม่มีการเบิกรถ ไม่สามารถมอบกุญแจได้",
      409
    );
  }
  if (ids.some(vehicleId => !planned.includes(vehicleId))) {
    throw new AppError("มอบได้เฉพาะรถที่อยู่ในรายการเบิกนี้", 409);
  }

  const alreadyIssued = await all(
    db,
    "SELECT vehicle_id FROM key_handovers WHERE inspection_id = ?",
    id
  );

  // A returned key still counts as an earlier handover.
  // A new borrowing requires a new inspection.
  if (alreadyIssued.length > 0) {
    throw new AppError(
      "รายการตรวจนี้เคยมอบกุญแจแล้ว หากเบิกใหม่ให้สร้างรายการตรวจใหม่",
      409
    );
  }

  const vehicles = await selectedVehicles(db, ids, true);

  // The database trigger also enforces the rule atomically,
  // including concurrent requests with different request IDs.
  return commitMutation(
    db,
    user,
    action,
    context,
    handoverStatements(db, user, id, vehicles, notes, await inspectionStaff(db, user, id)),
    { message: "มอบกุญแจรถ 1 คันแล้ว" }
  );
}

async function adminData(db, user) {
  requireAdmin(user);

  const [vehicles, users, staff, audit] = await Promise.all([
    loadVehicles(db, false),
    all(
      db,
      `SELECT username AS Username, display_name AS DisplayName,
              role AS Role, active AS Active,
              COALESCE((SELECT staff_group FROM user_staff_access_v3 sa WHERE sa.user_id=users.user_id),'') AS StaffGroup
       FROM users ORDER BY username COLLATE NOCASE`
    ),
    all(
      db,
      `SELECT staff_id AS StaffID, display_name AS StaffName,
              staff_group AS StaffGroup, active AS Active
       FROM staff_master_v3
       ORDER BY staff_group COLLATE NOCASE, display_name COLLATE NOCASE`
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
    staff: staff.map(s => ({ ...s, Active: Boolean(s.Active) })),
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

async function saveStaff(db, user, data) {
  requireAdmin(user);
  const action = "saveStaff";
  const context = await mutationContext(db, user, action, data);
  if (context.cached) return context.cached;
  const id = text(data.staffId, "Staff ID", 80);
  const name = text(data.displayName, "ชื่อเจ้าหน้าที่", 200);
  const group = text(data.staffGroup, "กลุ่มเจ้าหน้าที่", 20);
  if (!["Store", "TRW/TRD", "SIG", "COM", "PSY/GRS"].includes(group)) {
    throw new AppError("กลุ่มเจ้าหน้าที่ไม่ถูกต้อง");
  }
  const active = data.active === true ? 1 : 0;
  const at = timestamp();
  return commitMutation(
    db, user, action, context,
    [statement(db,
      `INSERT INTO staff_master_v3(staff_id,display_name,staff_group,active)
       VALUES(?,?,?,?)
       ON CONFLICT(staff_id) DO UPDATE SET
         display_name=excluded.display_name,
         staff_group=excluded.staff_group,
         active=excluded.active`,
      id, name, group, active),
      auditStatement(db, user, action, "staff_master_v3", id,
        { displayName:name, staffGroup:group, active:Boolean(active) })],
    {message: active ? "บันทึกรายชื่อเจ้าหน้าที่แล้ว" : "ปิดใช้งานรายชื่อเจ้าหน้าที่แล้ว"}
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
  const staffGroup = text(data.staffGroup, "กลุ่มเจ้าหน้าที่", 20, false);
  if (!["", "Store", "TRW/TRD", "All"].includes(staffGroup) || (staffGroup === "All" && role !== "Admin")) {
    throw new AppError("กลุ่มต้องเป็น Store, TRW/TRD, SIG, COM หรือ PSY/GRS; เฉพาะ Admin เลือกทั้งหมดได้");
  }

  if (!/^[A-Za-z0-9_.-]+$/.test(username)) {
    throw new AppError(
      "Username ใช้ภาษาอังกฤษ ตัวเลข จุด ขีดกลาง หรือขีดล่าง"
    );
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
    throw new AppError(
      "ไม่สามารถปิดหรือถอดสิทธิ์ Admin ของบัญชีที่กำลังใช้"
    );
  }

  const hasPassword =
    typeof data.password === "string" && data.password.length > 0;

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
      ...(staffGroup ? [statement(db,
        `INSERT INTO user_staff_access_v3(user_id,staff_group,updated_at) VALUES(?,?,?)
         ON CONFLICT(user_id) DO UPDATE SET staff_group=excluded.staff_group,updated_at=excluded.updated_at`,
        id,staffGroup,at)] : [statement(db,"DELETE FROM user_staff_access_v3 WHERE user_id=?",id)]),
      auditStatement(
        db,
        user,
        action,
        "users",
        id,
        {
          username,
          role,
          staffGroup,
          active: Boolean(active),
          passwordReset: hasPassword
        }
      )
    ],
    {
      message:
        "บันทึกบัญชีผู้ใช้แล้ว — Session เดิมของบัญชีนี้ถูกยกเลิก"
    }
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
    user: publicUser({
      ...user,
      staff_group: (await db.prepare("SELECT staff_group FROM user_staff_access_v3 WHERE user_id = ?")
        .bind(user.user_id).first())?.staff_group || ""
    })
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

    case "saveStaff":
      return saveStaff(db, user, data);

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
      return respond(
        { ok: false, error: "Origin ไม่ได้รับอนุญาต" },
        403
      );
    }

    if (origin) headers["Access-Control-Allow-Origin"] = origin;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    try {
      if (!env.DB) {
        throw new AppError("Worker ไม่มี D1 Binding ชื่อ DB", 503);
      }

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
          apiVersion: "actual-staff-single-vehicle-v2"
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
        return respond(
          { ok: false, error: error.message },
          error.status
        );
      }

      const message = String(error.message || error);
      console.error("API failure:", message);

      if (/no such column|has no column named/i.test(message)) {
        return respond({
          ok: false,
          error:
            "D1 ยังขาดคอลัมน์ที่ API ใช้ กรุณาตรวจ SQL เพิ่ม inspector_name, receiver_name และ owner_department ก่อน"
        }, 503);
      }

      if (/manual-v1|CHECK constraint/i.test(message)) {
        return respond({
          ok: false,
          error:
            "ข้อมูลไม่ตรงข้อกำหนด D1 กรุณาตรวจ schema manual-v1 และ Worker Logs"
        }, 503);
      }

      return respond({
        ok: false,
        error:
          "บันทึกไม่สำเร็จ กรุณารีเฟรช หากยังเกิดซ้ำให้ตรวจ Worker Logs"
      }, 500);
    }
  }
};
