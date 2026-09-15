require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { promisify } = require("util");
const { Pool } = require("pg");

const scrypt = promisify(crypto.scrypt);
const app = express();
const port = Number(process.env.PORT || 5000);

// إعداد اتصال قاعدة البيانات مع دعم SSL للإنتاج
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

const PAGE_KEYS = ["dashboard", "official-forms", "members", "supervisors", "reports", "settings"];
const SESSION_COOKIE = "scout_session";

// Middlewares الأساسية
app.use(express.json({ limit: "8mb" }));
app.use(express.urlencoded({ extended: true, limit: "8mb" }));
app.get("/app.css", (request, response) => {
  const baseStyles = fs.readFileSync(path.join(__dirname, "app.css"), "utf8");
  const responsiveStyles = fs.readFileSync(path.join(__dirname, "responsive.css"), "utf8");
  const polishStyles = fs.readFileSync(path.join(__dirname, "polish.css"), "utf8");
  response.type("css").send(`${baseStyles}\n${responsiveStyles}\n${polishStyles}`);
});
app.get("/index.html", (request, response) => response.redirect(302, "/login"));
app.get("/legacy-forms", requireAuth, requirePermission("official-forms"), (request, response) => response.sendFile(path.join(__dirname, "index.html")));

const protectedPages = {
  "/dashboard": "dashboard",
  "/dashboard.html": "dashboard",
  "/forms": "official-forms",
  "/forms.html": "official-forms",
  "/reports": "reports",
  "/reports.html": "reports",
  "/members": "members",
  "/members.html": "members",
  "/supervisors": "supervisors",
  "/supervisors.html": "supervisors",
  "/settings": "settings",
  "/settings.html": "settings",
  "/legacy-forms": "official-forms",
};

app.use(async (request, response, next) => {
  const pageKey = protectedPages[request.path];
  if (!pageKey) return next();

  try {
    const user = await getCurrentUser(request);
    if (!user) return response.redirect(302, "/login");
    if (!can(user, pageKey)) {
      return response.status(403).type("html").send(`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>غير مخول</title><link rel="stylesheet" href="/app.css"></head><body class="login-page"><main class="login-card"><h1>أنت غير مخول</h1><p class="muted">لا تملك صلاحية الوصول إلى هذه الصفحة.</p><a class="button primary" href="/dashboard">العودة للرئيسية</a></main></body></html>`);
    }
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
});
app.use(express.static(path.join(__dirname)));

app.get("/", (request, response) => {
  response.sendFile(path.join(__dirname, "login.html"));
});

const pageRoutes = {
  "/login": "login.html",
  "/dashboard": "dashboard.html",
  "/forms": "forms.html",
  "/reports": "reports.html",
  "/members": "members.html",
  "/supervisors": "supervisors.html",
  "/settings": "settings.html",
};

for (const [route, file] of Object.entries(pageRoutes)) {
  app.get(route, (request, response) => response.sendFile(path.join(__dirname, file)));
}

app.get("/api/health", async (request, response) => {
  try {
    await pool.query("SELECT 1");
    response.json({ ok: true, database: "connected", service: "scout-management" });
  } catch (error) {
    response.status(503).json({ ok: false, database: "unavailable", error: "قاعدة البيانات غير متاحة" });
  }
});

// ==========================================
// 1. الدوارل المساعدة والتشفير (Helper Functions)
// ==========================================

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  const [, salt, expectedHex] = String(storedHash || "").split("$");
  if (!salt || !expectedHex) return false;
  const actual = await scrypt(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

function parseCookies(request) {
  const header = request.headers.cookie || "";
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
      .map(([key, ...value]) => [key, decodeURIComponent(value.join("="))])
  );
}

function setSessionCookie(response, token) {
  const secure = process.env.NODE_ENV === "production" ? " Secure;" : "";
  response.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800;${secure}`
  );
}

function clearSessionCookie(response) {
  response.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax`
  );
}

function sendError(response, status, message) {
  return response.status(status).json({ error: message });
}

// ==========================================
// 2. التحقق من الهوية والصلاحيات (Auth & RBAC)
// ==========================================

async function getCurrentUser(request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;

  const result = await pool.query(
    `SELECT u.id, u.username, u.full_name, u.role, u.active,
            COALESCE(
              jsonb_object_agg(
                p.page_key,
                jsonb_build_object(
                  'view', p.can_view,
                  'create', p.can_create,
                  'edit', p.can_edit,
                  'delete', p.can_delete
                )
              ) FILTER (WHERE p.page_key IS NOT NULL),
              '{}'::jsonb
            ) AS permissions
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN page_permissions p ON p.user_id = u.id
      WHERE s.token_hash = $1
        AND s.expires_at > NOW()
        AND u.active = TRUE
      GROUP BY u.id`,
    [hashSessionToken(token)]
  );

  return result.rows[0] || null;
}

async function requireAuth(request, response, next) {
  try {
    const user = await getCurrentUser(request);
    if (!user) return sendError(response, 401, "يجب تسجيل الدخول أولاً");
    request.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

function can(user, pageKey, capability = "view") {
  if (user.role === "قائد الفرقة") return true;
  return Boolean(user.permissions?.[pageKey]?.[capability]);
}

function requirePermission(pageKey, capability = "view") {
  return (request, response, next) => {
    if (!can(request.user, pageKey, capability)) {
      return sendError(response, 403, "لا تملك الصلاحية لتنفيذ هذا الإجراء");
    }
    next();
  };
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query(
    `INSERT INTO sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
    [userId, hashSessionToken(token)]
  );
  return token;
}

async function seedPermissions(userId, role) {
  const permissions =
    role === "قائد الفرقة"
      ? PAGE_KEYS.map((pageKey) => [pageKey, true, true, true, true])
      : [
          ["dashboard", true, false, false, false],
          ["official-forms", true, true, false, false],
          ["members", true, true, true, false],
          ["supervisors", false, false, false, false],
          ["reports", true, true, false, false],
          ["settings", false, false, false, false],
        ];

  for (const [pageKey, view, create, edit, remove] of permissions) {
    await pool.query(
      `INSERT INTO page_permissions (user_id, page_key, can_view, can_create, can_edit, can_delete)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id, page_key)
       DO UPDATE SET can_view = EXCLUDED.can_view,
                     can_create = EXCLUDED.can_create,
                     can_edit = EXCLUDED.can_edit,
                     can_delete = EXCLUDED.can_delete`,
      [userId, pageKey, view, create, edit, remove]
    );
  }
}

async function seedUser(username, fullName, role, password) {
  const existing = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
  let userId = existing.rows[0]?.id;

  if (!userId) {
    const passwordHash = await hashPassword(password);
    const inserted = await pool.query(
      `INSERT INTO users (username, full_name, role, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [username, fullName, role, passwordHash]
    );
    userId = inserted.rows[0].id;
  }

  await seedPermissions(userId, role);
  return userId;
}

// ==========================================
// 3. إنزاع الجداول والبيانات الأولية (Database Init)
// ==========================================

async function ensureDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'مشرف عام',
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS page_permissions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      page_key TEXT NOT NULL,
      can_view BOOLEAN NOT NULL DEFAULT FALSE,
      can_create BOOLEAN NOT NULL DEFAULT FALSE,
      can_edit BOOLEAN NOT NULL DEFAULT FALSE,
      can_delete BOOLEAN NOT NULL DEFAULT FALSE,
      UNIQUE (user_id, page_key)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      scout_number TEXT UNIQUE,
      national_id TEXT,
      birth_date DATE,
      phone TEXT,
      guardian_name TEXT,
      guardian_phone TEXT,
      email TEXT,
      patrol TEXT,
      rank TEXT,
      join_date DATE,
      address TEXT,
      medical_notes TEXT,
      notes TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity_reports (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      axis TEXT NOT NULL,
      activity_date DATE,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS meeting_minutes (
      id SERIAL PRIMARY KEY,
      meeting_date DATE,
      title TEXT NOT NULL DEFAULT 'تقرير اجتماع مجلس الشرف',
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS members_active_idx ON members(active);
    CREATE INDEX IF NOT EXISTS activity_reports_created_at_idx ON activity_reports(created_at DESC);
  `);

  const userCount = await pool.query("SELECT COUNT(*)::int AS count FROM users");
  let adminId = (await pool.query(
    "SELECT id FROM users WHERE username = $1 LIMIT 1",
    ["al-naaim_scout"]
  )).rows[0]?.id;

  const firstDatabaseInitialization = userCount.rows[0].count === 0;

  // Seed demo data only during the first database initialization.
  if (firstDatabaseInitialization) {
    adminId = await seedUser("al-naaim_scout", "قائد الفرقة", "قائد الفرقة", "scout2026");
    await seedUser("mohammed@scouts.bh", "محمد علي", "مشرف عام", "scout2026");
    await seedUser("salman@scouts.bh", "سلمان حسن", "قائد طليعة", "scout2026");
  }

  if (firstDatabaseInitialization) {
    await pool.query(`
      INSERT INTO members
        (full_name, scout_number, patrol, rank, join_date, phone, guardian_name, guardian_phone, email, address, notes)
      VALUES
        ('عبدالله محمد', 'SC-001', 'طليعة الصقر', 'كشاف متقدم', '2025-09-01', '39990001', 'محمد عبدالله', '39990002', 'abdullah@example.com', 'النعيم', 'ملتزم بالحضور'),
        ('يوسف علي', 'SC-002', 'طليعة النسر', 'كشاف متقدم', '2025-09-08', '39990003', 'علي يوسف', '39990004', 'yousef@example.com', 'المنامة', ''),
        ('حسن أحمد', 'SC-003', 'طليعة الذئب', 'كشاف', '2026-01-10', '39990005', 'أحمد حسن', '39990006', 'hassan@example.com', 'مدينة حمد', 'يحتاج متابعة في الحضور')
    `);
  }

  if (firstDatabaseInitialization) {
    await pool.query(
      `INSERT INTO activity_reports (title, axis, activity_date, data, created_by)
       VALUES
        ('رحلة الخلاء والتطبيق الخارجي', 'الكشفي والتربوي', '2026-09-10', '{"target":"كشافة فرقة المتقدم","count":24}'::jsonb, $1),
        ('حملة تنظيف شاطئ النعيم', 'الخدمة المجتمعية', '2026-08-28', '{"target":"كشافة فرقة المتقدم","count":24}'::jsonb, $1)`,
      [adminId]
    );
  }
}

// ==========================================
// 4. مسارات المصادقة (Auth Endpoints)
// ==========================================

app.post("/api/auth/login", async (request, response, next) => {
  try {
    const { username, password } = request.body || {};
    if (!username || !password) return sendError(response, 400, "أدخل اسم المستخدم وكلمة المرور");

    const result = await pool.query(
      "SELECT id, username, full_name, role, active, password_hash FROM users WHERE username = $1",
      [String(username).trim()]
    );
    const user = result.rows[0];

    if (!user || !user.active || !(await verifyPassword(password, user.password_hash))) {
      return sendError(response, 401, "بيانات الدخول غير صحيحة");
    }

    const token = await createSession(user.id);
    setSessionCookie(response, token);
    const currentUser = await getCurrentUser({ headers: { cookie: `${SESSION_COOKIE}=${token}` } });
    response.json({ user: currentUser });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", async (request, response, next) => {
  try {
    const token = parseCookies(request)[SESSION_COOKIE];
    if (token) await pool.query("DELETE FROM sessions WHERE token_hash = $1", [hashSessionToken(token)]);
    clearSessionCookie(response);
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", requireAuth, (request, response) => {
  response.json({ user: request.user });
});

// ==========================================
// 5. مسارات النواحي والإدارة (API Routes)
// ==========================================

app.get("/api/dashboard", requireAuth, requirePermission("dashboard"), async (request, response, next) => {
  try {
    const [members, reports, patrols, attendance, latestReports] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM members WHERE active = TRUE"),
      pool.query("SELECT COUNT(*)::int AS count FROM activity_reports"),
      pool.query("SELECT COUNT(DISTINCT patrol)::int AS count FROM members WHERE active = TRUE AND patrol IS NOT NULL AND patrol <> ''"),
      pool.query("SELECT 92::int AS percent"),
      pool.query(
        `SELECT id, title, axis, activity_date, created_at
           FROM activity_reports
          ORDER BY activity_date DESC NULLS LAST, created_at DESC
          LIMIT 10`
      ),
    ]);

    response.json({
      stats: {
        members: members.rows[0].count,
        reports: reports.rows[0].count,
        patrols: patrols.rows[0].count,
        attendance: attendance.rows[0].percent,
      },
      latestReports: latestReports.rows,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/system/monitor", requireAuth, requirePermission("settings"), async (request, response, next) => {
  try {
    const [members, activities, meetings, users, database] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM members"),
      pool.query("SELECT COUNT(*)::int AS count FROM activity_reports"),
      pool.query("SELECT COUNT(*)::int AS count FROM meeting_minutes"),
      pool.query("SELECT COUNT(*)::int AS count FROM users WHERE active = TRUE"),
      pool.query("SELECT NOW() AS checked_at"),
    ]);

    response.json({
      database: "connected",
      checkedAt: database.rows[0].checked_at,
      counts: {
        members: members.rows[0].count,
        activities: activities.rows[0].count,
        meetings: meetings.rows[0].count,
        users: users.rows[0].count,
      },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/system/reset", requireAuth, requirePermission("settings", "delete"), async (request, response, next) => {
  if (request.body?.confirmation !== "تصفير") {
    return sendError(response, 400, "اكتب كلمة تصفير للتأكيد");
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const deleted = await client.query(`
      WITH deleted_activity AS (
        DELETE FROM activity_reports RETURNING 1
      ), deleted_meetings AS (
        DELETE FROM meeting_minutes RETURNING 1
      ), deleted_members AS (
        DELETE FROM members RETURNING 1
      )
      SELECT
        (SELECT COUNT(*)::int FROM deleted_activity) AS activities,
        (SELECT COUNT(*)::int FROM deleted_meetings) AS meetings,
        (SELECT COUNT(*)::int FROM deleted_members) AS members
    `);
    await client.query("COMMIT");
    response.json({ ok: true, deleted: deleted.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

// إدارة المستخدمين والمشرفين
app.get("/api/users", requireAuth, requirePermission("supervisors"), async (request, response, next) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.full_name, u.role, u.active, u.created_at,
              COALESCE(jsonb_object_agg(p.page_key, jsonb_build_object(
                'view', p.can_view, 'create', p.can_create, 'edit', p.can_edit, 'delete', p.can_delete
              )) FILTER (WHERE p.page_key IS NOT NULL), '{}'::jsonb) AS permissions
         FROM users u
         LEFT JOIN page_permissions p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at`
    );
    response.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/users", requireAuth, requirePermission("supervisors", "create"), async (request, response, next) => {
  try {
    const { username, fullName, role, password } = request.body || {};
    if (!username || !fullName || !role || !password || String(password).length < 6) {
      return sendError(response, 400, "أكمل بيانات المستخدم، وكلمة المرور يجب أن تكون 6 أحرف على الأقل");
    }

    const passwordHash = await hashPassword(String(password));
    const created = await pool.query(
      `INSERT INTO users (username, full_name, role, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, full_name, role, active, created_at`,
      [String(username).trim(), String(fullName).trim(), String(role).trim(), passwordHash]
    );

    await seedPermissions(created.rows[0].id, role);
    response.status(201).json({ user: created.rows[0] });
  } catch (error) {
    if (error.code === "23505") return sendError(response, 409, "اسم المستخدم مستخدم مسبقاً");
    next(error);
  }
});

app.patch("/api/users/:id", requireAuth, requirePermission("supervisors", "edit"), async (request, response, next) => {
  try {
    const { fullName, role, active } = request.body || {};
    const result = await pool.query(
      `UPDATE users
          SET full_name = COALESCE($1, full_name),
              role = COALESCE($2, role),
              active = COALESCE($3, active),
              updated_at = NOW()
        WHERE id = $4
        RETURNING id, username, full_name, role, active, created_at`,
      [fullName || null, role || null, typeof active === "boolean" ? active : null, request.params.id]
    );

    if (!result.rows[0]) return sendError(response, 404, "المستخدم غير موجود");
    if (role) await seedPermissions(result.rows[0].id, role);
    response.json({ user: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.get("/api/users/:id/permissions", requireAuth, requirePermission("supervisors"), async (request, response, next) => {
  try {
    const result = await pool.query(
      `SELECT page_key, can_view, can_create, can_edit, can_delete
         FROM page_permissions
        WHERE user_id = $1
        ORDER BY page_key`,
      [request.params.id]
    );
    response.json({ permissions: result.rows });
  } catch (error) {
    next(error);
  }
});

app.put("/api/users/:id/permissions", requireAuth, requirePermission("supervisors", "edit"), async (request, response, next) => {
  try {
    const permissions = Array.isArray(request.body?.permissions) ? request.body.permissions : [];
    await pool.query("DELETE FROM page_permissions WHERE user_id = $1", [request.params.id]);

    for (const pageKey of PAGE_KEYS) {
      const item = permissions.find((permission) => permission.pageKey === pageKey) || {};
      await pool.query(
        `INSERT INTO page_permissions (user_id, page_key, can_view, can_create, can_edit, can_delete)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          request.params.id,
          pageKey,
          Boolean(item.view),
          Boolean(item.create),
          Boolean(item.edit),
          Boolean(item.delete),
        ]
      );
    }
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/users/:id", requireAuth, requirePermission("supervisors", "delete"), async (request, response, next) => {
  try {
    if (String(request.params.id) === String(request.user.id)) {
      return sendError(response, 400, "لا يمكنك حذف حسابك الحالي");
    }
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [request.params.id]);
    if (!result.rows[0]) return sendError(response, 404, "المستخدم غير موجود");
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

// إدارة الأعضاء
app.get("/api/members", requireAuth, requirePermission("members"), async (request, response, next) => {
  try {
    const result = await pool.query("SELECT * FROM members ORDER BY active DESC, full_name");
    response.json({ members: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/members", requireAuth, requirePermission("members", "create"), async (request, response, next) => {
  try {
    const member = request.body || {};
    if (!member.fullName?.trim()) return sendError(response, 400, "الاسم الكامل مطلوب");

    const result = await pool.query(
      `INSERT INTO members
        (full_name, scout_number, national_id, birth_date, phone, guardian_name, guardian_phone,
         email, patrol, rank, join_date, address, medical_notes, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING *`,
      [
        member.fullName.trim(),
        member.scoutNumber || null,
        member.nationalId || null,
        member.birthDate || null,
        member.phone || null,
        member.guardianName || null,
        member.guardianPhone || null,
        member.email || null,
        member.patrol || null,
        member.rank || null,
        member.joinDate || null,
        member.address || null,
        member.medicalNotes || null,
        member.notes || null,
      ]
    );
    response.status(201).json({ member: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") return sendError(response, 409, "رقم الكشاف مستخدم مسبقاً");
    next(error);
  }
});

app.patch("/api/members/:id", requireAuth, requirePermission("members", "edit"), async (request, response, next) => {
  try {
    const member = request.body || {};
    const result = await pool.query(
      `UPDATE members SET
        full_name = COALESCE($1, full_name), scout_number = COALESCE($2, scout_number),
        national_id = COALESCE($3, national_id), birth_date = COALESCE($4, birth_date),
        phone = COALESCE($5, phone), guardian_name = COALESCE($6, guardian_name),
        guardian_phone = COALESCE($7, guardian_phone), email = COALESCE($8, email),
        patrol = COALESCE($9, patrol), rank = COALESCE($10, rank), join_date = COALESCE($11, join_date),
        address = COALESCE($12, address), medical_notes = COALESCE($13, medical_notes),
        notes = COALESCE($14, notes), active = COALESCE($15, active), updated_at = NOW()
       WHERE id = $16 RETURNING *`,
      [
        member.fullName || null,
        member.scoutNumber || null,
        member.nationalId || null,
        member.birthDate || null,
        member.phone || null,
        member.guardianName || null,
        member.guardianPhone || null,
        member.email || null,
        member.patrol || null,
        member.rank || null,
        member.joinDate || null,
        member.address || null,
        member.medicalNotes || null,
        member.notes || null,
        typeof member.active === "boolean" ? member.active : null,
        request.params.id,
      ]
    );

    if (!result.rows[0]) return sendError(response, 404, "العضو غير موجود");
    response.json({ member: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/members/:id", requireAuth, requirePermission("members", "delete"), async (request, response, next) => {
  try {
    const result = await pool.query("DELETE FROM members WHERE id = $1 RETURNING id", [request.params.id]);
    if (!result.rows[0]) return sendError(response, 404, "العضو غير موجود");
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

// إدارة التقارير
app.get("/api/reports", requireAuth, requirePermission("reports"), async (request, response, next) => {
  try {
    const [activities, meetings] = await Promise.all([
      pool.query(
        `SELECT id, title, axis AS category, activity_date AS report_date, data, 'activity' AS type, created_at
           FROM activity_reports
          ORDER BY activity_date DESC NULLS LAST, created_at DESC`
      ),
      pool.query(
        `SELECT id, title, 'محضر اجتماع مجلس الشرف' AS category, meeting_date AS report_date, data, 'meeting' AS type, created_at
           FROM meeting_minutes
          ORDER BY meeting_date DESC NULLS LAST, created_at DESC`
      )
    ]);

    const reports = [...activities.rows, ...meetings.rows]
      .map((report) => ({
        ...report,
        date: report.report_date || report.created_at,
      }))
      .sort((a, b) => new Date(b.date) - new Date(a.date));

    response.json({ reports });
  } catch (error) {
    next(error);
  }
});

app.post("/api/reports/activity", requireAuth, requirePermission("reports", "create"), async (request, response, next) => {
  try {
    const { title, axis, activityDate, data } = request.body || {};
    if (!title || !axis) return sendError(response, 400, "اسم البرنامج والمحور مطلوبان");

    const result = await pool.query(
      `INSERT INTO activity_reports (title, axis, activity_date, data, created_by)
       VALUES ($1, $2, $3, $4::jsonb, $5)
       RETURNING id, title, axis, activity_date, created_at`,
      [title, axis, activityDate || null, JSON.stringify(data || {}), request.user.id]
    );
    response.status(201).json({ report: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.post("/api/reports/meeting", requireAuth, requirePermission("reports", "create"), async (request, response, next) => {
  try {
    const { meetingDate, data } = request.body || {};
    const result = await pool.query(
      `INSERT INTO meeting_minutes (meeting_date, data, created_by)
       VALUES ($1, $2::jsonb, $3)
       RETURNING id, title, meeting_date, created_at`,
      [meetingDate || null, JSON.stringify(data || {}), request.user.id]
    );
    response.status(201).json({ report: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// ==========================================
// 6. معالجة الأخطاء والتشغيل (Error Handling & Launch)
// ==========================================

app.use((error, request, response, next) => {
  console.error(error);
  if (response.headersSent) return next(error);
  response.status(500).json({ error: "حدث خطأ غير متوقع في الخادم" });
});

ensureDatabase()
  .then(() => {
    app.listen(port, "0.0.0.0", () => {
      console.log(`Scout management server listening on 0.0.0.0:${port}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed", error);
    process.exit(1);
  });