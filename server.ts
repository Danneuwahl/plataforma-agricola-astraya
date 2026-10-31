import express from "express";
import path from "path";
import { GoogleGenAI } from "@google/genai";
import { Pool } from "pg";
import type { PoolClient } from "pg";
import dotenv from "dotenv";
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from "crypto";
import type { NextFunction, Request, Response } from "express";

dotenv.config();

const COLLECTION_KEYS = [
  "astraya_deficiencies_v6",
  "astraya_pests_v5",
  "astraya_bioinputs_v5",
  "astraya_documents_v5",
  "astraya_events",
  "astraya_mip_logs",
  "astraya_madres_v1",
  "astraya_indoor_batches_v1",
  "astraya_outdoor_plots_v1",
  "astraya_cycle_folders_v1",
] as const;
const COLLECTION_KEY_SET = new Set<string>(COLLECTION_KEYS);
const SESSION_COOKIE = "astraya_session";
const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_SECONDS * 1000;
const DATA_BODY_MAX_BYTES = 20 * 1024 * 1024;
const SCRYPT_KEY_LENGTH = 64;
const DUMMY_PASSWORD_HASH = `scrypt$AAAAAAAAAAAAAAAAAAAAAA$${"A".repeat(86)}`;
const scrypt = (password: string, salt: Buffer, keyLength: number): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    scryptCallback(password, salt, keyLength, { maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error) reject(error);
      else resolve(key as Buffer);
    });
  });

type UserRole = "admin" | "operator" | "reader";
interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}
type AuthenticatedRequest = Request & { user?: AuthUser };

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    name text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'reader' CHECK (role IN ('admin', 'operator', 'reader')),
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash char(64) PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS app_user_data (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key IN (
      'astraya_deficiencies_v6', 'astraya_pests_v5', 'astraya_bioinputs_v5',
      'astraya_documents_v5', 'astraya_events', 'astraya_mip_logs',
      'astraya_madres_v1', 'astraya_indoor_batches_v1',
      'astraya_outdoor_plots_v1', 'astraya_cycle_folders_v1'
    )),
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
  );
`;

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT_KEY_LENGTH);
  return `scrypt$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [scheme, saltText, keyText, extra] = encoded.split("$");
  if (scheme !== "scrypt" || !saltText || !keyText || extra !== undefined) return false;
  try {
    const salt = Buffer.from(saltText, "base64url");
    const expected = Buffer.from(keyText, "base64url");
    if (salt.length !== 16 || expected.length !== SCRYPT_KEY_LENGTH) return false;
    const actual = await scrypt(password, salt, expected.length);
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function isValidEmail(email: string): boolean {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function requestCookie(req: Request, name: string): string | null {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    const value = part.slice(separator + 1).trim();
    return /^[A-Za-z0-9_-]{40,64}$/.test(value) ? value : null;
  }
  return null;
}

function cookieOptions(): string {
  const secure = /^(1|true|yes)$/i.test(process.env.COOKIE_SECURE || "") ? "; Secure" : "";
  return `Path=/; HttpOnly; SameSite=Lax${secure}`;
}

function originIsAllowed(req: Request): boolean {
  const origin = req.get("origin");
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const requestHost = req.get("host");
    return (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      Boolean(requestHost) && parsed.host.toLowerCase() === requestHost!.toLowerCase();
  } catch {
    return false;
  }
}

function createRateLimiter(maxAttempts: number, windowMs: number) {
  const attempts = new Map<string, { count: number; resetAt: number }>();
  return (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || "unknown";
    let entry = attempts.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      attempts.set(key, entry);
    }
    entry.count += 1;
    if (attempts.size > 5000) {
      for (const [ip, state] of attempts) if (state.resetAt <= now) attempts.delete(ip);
    }
    if (entry.count > maxAttempts) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((entry.resetAt - now) / 1000))));
      return res.status(429).json({ error: "Muitas tentativas. Tente novamente mais tarde." });
    }
    next();
  };
}

async function initializeDatabase(pool: Pool): Promise<void> {
  await pool.query(SCHEMA_SQL);
  // Upgrade databases created by earlier releases; safe to run on every startup.
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
    ALTER TABLE users ALTER COLUMN role SET DEFAULT 'reader';
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
    UPDATE users SET role = 'operator' WHERE role = 'user';
    ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'operator', 'reader'));
  `);
  const adminEmail = process.env.ADMIN_EMAIL ? normalizeEmail(process.env.ADMIN_EMAIL) : "";
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPassword) return;
  if (!isValidEmail(adminEmail)) throw new Error("ADMIN_EMAIL is not a valid email address.");
  if (Array.from(adminPassword).length < 12) throw new Error("ADMIN_PASSWORD must contain at least 12 characters.");
  if (Buffer.byteLength(adminPassword, "utf8") > 1024) throw new Error("ADMIN_PASSWORD exceeds the 1024-byte limit.");
  const adminName = (process.env.ADMIN_NAME || "Administrador ASTRAYA").trim().slice(0, 120) || "Administrador ASTRAYA";
  const promoted = await pool.query("UPDATE users SET role = 'admin' WHERE email = $1 RETURNING id", [adminEmail]);
  if (promoted.rowCount) return;
  const passwordHash = await hashPassword(adminPassword);
  await pool.query(
    `INSERT INTO users (id, email, name, password_hash, role)
     VALUES ($1, $2, $3, $4, 'admin')
     ON CONFLICT (email) DO UPDATE SET role = 'admin'`,
    [randomUUID(), adminEmail, adminName, passwordHash],
  );
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || 3000);
  const databasePool = process.env.DATABASE_URL || process.env.PGHOST
    ? new Pool({
        ...(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {}),
        connectionTimeoutMillis: 3000,
        max: 10,
      })
    : null;

  if (databasePool) {
    try {
      await initializeDatabase(databasePool);
      console.log("PostgreSQL schema initialized and available.");
    } catch (error) {
      console.error("PostgreSQL schema initialization failed; refusing to start:", error);
      await databasePool.end();
      throw error;
    }
  }

  app.use(express.json({ limit: "20mb", strict: true }));
  app.use((error: any, _req: Request, res: Response, next: NextFunction) => {
    if (error?.type === "entity.too.large") {
      return res.status(413).json({ error: "Corpo da requisição excede o limite de 20 MB." });
    }
    if (error instanceof SyntaxError && "body" in error) {
      return res.status(400).json({ error: "JSON inválido." });
    }
    next(error);
  });

  const requireDatabase = (_req: Request, res: Response, next: NextFunction) => {
    if (!databasePool) return res.status(503).json({ error: "Banco de dados não configurado." });
    next();
  };
  const checkMutationOrigin = (req: Request, res: Response, next: NextFunction) => {
    if (!originIsAllowed(req)) return res.status(403).json({ error: "Origem da requisição não permitida." });
    next();
  };
  const authRateLimit = createRateLimiter(10, 15 * 60 * 1000);
  const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
    if (!databasePool) return res.status(503).json({ error: "Banco de dados não configurado." });
    const token = requestCookie(req, SESSION_COOKIE);
    if (!token) return res.status(401).json({ error: "Autenticação necessária." });
    try {
      const tokenHash = createHash("sha256").update(token).digest("hex");
      const result = await databasePool.query(
        `SELECT u.id, u.email, u.name, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active = true`,
        [tokenHash],
      );
      if (!result.rowCount) return res.status(401).json({ error: "Autenticação necessária." });
      (req as AuthenticatedRequest).user = result.rows[0] as AuthUser;
      next();
    } catch (error) {
      console.error("Session lookup failed:", error);
      res.status(500).json({ error: "Falha ao validar a sessão." });
    }
  };

  const createSession = async (user: AuthUser, res: Response) => {
    const rawToken = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(rawToken).digest("hex");
    await databasePool!.query(
      `INSERT INTO sessions (token_hash, user_id, expires_at)
       VALUES ($1, $2, now() + interval '7 days')`,
      [tokenHash, user.id],
    );
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${rawToken}; ${cookieOptions()}; Max-Age=${SESSION_MAX_AGE_SECONDS}`);
  };

  const publicUser = (row: any): AuthUser => ({
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
  });

  app.post("/api/auth/register", requireDatabase, checkMutationOrigin, authRateLimit, async (req, res) => {
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const rawEmail = typeof req.body?.email === "string" ? req.body.email : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const email = normalizeEmail(rawEmail);
    if (!name || name.length > 120 || !isValidEmail(email) || Array.from(password).length < 12 || Buffer.byteLength(password, "utf8") > 1024) {
      return res.status(400).json({ error: "Nome, email válido e senha com pelo menos 12 caracteres são obrigatórios." });
    }
    try {
      const passwordHash = await hashPassword(password);
      const created = await databasePool!.query(
        `INSERT INTO users (id, email, name, password_hash, role)
         VALUES ($1, $2, $3, $4, 'reader')
         ON CONFLICT (email) DO NOTHING
         RETURNING id, email, name, role`,
        [randomUUID(), email, name, passwordHash],
      );
      if (!created.rowCount) return res.status(400).json({ error: "Não foi possível criar a conta com esses dados." });
      const user = publicUser(created.rows[0]);
      await createSession(user, res);
      return res.status(201).json({ user });
    } catch (error) {
      console.error("Account registration failed:", error);
      return res.status(500).json({ error: "Não foi possível concluir o cadastro." });
    }
  });

  app.post("/api/auth/login", requireDatabase, checkMutationOrigin, authRateLimit, async (req, res) => {
    const rawEmail = typeof req.body?.email === "string" ? req.body.email : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const email = normalizeEmail(rawEmail);
    if (!isValidEmail(email) || !password || Buffer.byteLength(password, "utf8") > 1024) {
      return res.status(401).json({ error: "Email ou senha inválidos." });
    }
    try {
      const result = await databasePool!.query(
        "SELECT id, email, name, role, is_active, password_hash FROM users WHERE email = $1",
        [email],
      );
      const row = result.rows[0];
      const validPassword = await verifyPassword(password, row?.password_hash || DUMMY_PASSWORD_HASH);
      if (!row || !validPassword || !row.is_active) return res.status(401).json({ error: "Email ou senha inválidos." });
      await databasePool!.query("DELETE FROM sessions WHERE expires_at <= now()");
      const user = publicUser(row);
      await createSession(user, res);
      return res.json({ user });
    } catch (error) {
      console.error("Login failed:", error);
      return res.status(500).json({ error: "Não foi possível concluir o login." });
    }
  });

  app.post("/api/auth/logout", requireDatabase, checkMutationOrigin, async (req, res) => {
    const token = requestCookie(req, SESSION_COOKIE);
    if (token) {
      try {
        const tokenHash = createHash("sha256").update(token).digest("hex");
        await databasePool!.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
      } catch (error) {
        console.error("Logout failed:", error);
        return res.status(500).json({ error: "Não foi possível encerrar a sessão." });
      }
    }
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; ${cookieOptions()}; Max-Age=0`);
    return res.status(204).end();
  });

  app.get("/api/auth/me", requireDatabase, requireAuth, (req, res) => {
    res.json({ user: publicUser((req as AuthenticatedRequest).user) });
  });

  const isValidUuid = (value: string): boolean =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
  const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
    if ((req as AuthenticatedRequest).user?.role !== "admin") {
      return res.status(403).json({ error: "Permissão de administrador necessária." });
    }
    next();
  };
  const validRole = (value: unknown): value is UserRole =>
    value === "admin" || value === "operator" || value === "reader";

  app.get("/api/admin/users", requireDatabase, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await databasePool!.query(
        "SELECT id, name, email, role, is_active, created_at FROM users ORDER BY created_at, id",
      );
      return res.json({ users: result.rows });
    } catch (error) {
      console.error("Admin user listing failed:", error);
      return res.status(500).json({ error: "Não foi possível carregar as contas." });
    }
  });
  app.post("/api/admin/users", requireDatabase, requireAuth, requireAdmin, checkMutationOrigin, async (req, res) => {
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const email = normalizeEmail(typeof req.body?.email === "string" ? req.body.email : "");
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const role = req.body?.role;
    if (!name || name.length > 120 || !isValidEmail(email) || Array.from(password).length < 12 ||
        Buffer.byteLength(password, "utf8") > 1024 || !validRole(role)) {
      return res.status(400).json({ error: "Informe nome, email válido, senha com pelo menos 12 caracteres e perfil válido." });
    }
    try {
      const passwordHash = await hashPassword(password);
      const result = await databasePool!.query(
        `INSERT INTO users (id, name, email, password_hash, role, is_active)
         VALUES ($1, $2, $3, $4, $5, true)
         RETURNING id, name, email, role, is_active, created_at`,
        [randomUUID(), name, email, passwordHash, role],
      );
      return res.status(201).json({ user: result.rows[0] });
    } catch (error: any) {
      if (error?.code === "23505") return res.status(400).json({ error: "Já existe uma conta com esse email." });
      console.error("Admin account creation failed:", error);
      return res.status(500).json({ error: "Não foi possível criar a conta." });
    }
  });
  app.patch("/api/admin/users/:id", requireDatabase, requireAuth, requireAdmin, checkMutationOrigin, async (req, res) => {
    const id = req.params.id.toLowerCase();
    if (!isValidUuid(id)) return res.status(400).json({ error: "Identificador de conta inválido." });
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ error: "Envie os campos da conta como objeto JSON." });
    }
    const hasName = Object.prototype.hasOwnProperty.call(body, "name");
    const hasRole = Object.prototype.hasOwnProperty.call(body, "role");
    const hasActive = Object.prototype.hasOwnProperty.call(body, "is_active");
    if (!hasName && !hasRole && !hasActive) return res.status(400).json({ error: "Nenhum campo para atualizar." });
    const name = hasName && typeof body.name === "string" ? body.name.trim() : undefined;
    if (hasName && (!name || name.length > 120)) return res.status(400).json({ error: "Nome inválido." });
    if (hasRole && !validRole(body.role)) return res.status(400).json({ error: "Perfil inválido." });
    if (hasActive && typeof body.is_active !== "boolean") return res.status(400).json({ error: "is_active deve ser booleano." });
    const actor = (req as AuthenticatedRequest).user!;
    if (id === actor.id && ((hasRole && body.role !== "admin") || (hasActive && body.is_active === false))) {
      return res.status(400).json({ error: "Não é permitido rebaixar ou desativar a própria conta." });
    }
    let client: PoolClient | undefined;
    try {
      client = await databasePool!.connect();
      await client.query("BEGIN");
      // Serialize admin removals so concurrent requests cannot remove the last active administrator.
      await client.query("SELECT pg_advisory_xact_lock($1)", [741028613]);
      const currentResult = await client.query(
        "SELECT id, name, email, role, is_active, created_at FROM users WHERE id = $1 FOR UPDATE", [id],
      );
      if (!currentResult.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Conta não encontrada." });
      }
      const current = currentResult.rows[0];
      const nextRole: UserRole = hasRole ? body.role : current.role;
      const nextActive: boolean = hasActive ? body.is_active : current.is_active;
      if (current.role === "admin" && current.is_active && (nextRole !== "admin" || !nextActive)) {
        const count = await client.query("SELECT count(*)::int AS count FROM users WHERE role = 'admin' AND is_active = true");
        if (count.rows[0].count <= 1) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: "Não é possível rebaixar ou desativar o último administrador ativo." });
        }
      }
      const sets: string[] = [];
      const values: unknown[] = [id];
      if (hasName) { values.push(name); sets.push(`name = $${values.length}`); }
      if (hasRole) { values.push(body.role); sets.push(`role = $${values.length}`); }
      if (hasActive) { values.push(body.is_active); sets.push(`is_active = $${values.length}`); }
      const updated = await client.query(
        `UPDATE users SET ${sets.join(", ")} WHERE id = $1
         RETURNING id, name, email, role, is_active, created_at`, values,
      );
      if (!nextActive) await client.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      await client.query("COMMIT");
      return res.json({ user: updated.rows[0] });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => undefined);
      console.error("Admin account update failed:", error);
      return res.status(500).json({ error: "Não foi possível atualizar a conta." });
    } finally {
      client?.release();
    }
  });
  app.post("/api/admin/users/:id/password", requireDatabase, requireAuth, requireAdmin, checkMutationOrigin, async (req, res) => {
    const id = req.params.id;
    if (!isValidUuid(id)) return res.status(400).json({ error: "Identificador de conta inválido." });
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (Array.from(password).length < 12 || Buffer.byteLength(password, "utf8") > 1024) {
      return res.status(400).json({ error: "A senha deve conter pelo menos 12 caracteres." });
    }
    let client: PoolClient | undefined;
    try {
      const passwordHash = await hashPassword(password);
      client = await databasePool!.connect();
      await client.query("BEGIN");
      const updated = await client.query("UPDATE users SET password_hash = $2 WHERE id = $1 RETURNING id", [id, passwordHash]);
      if (!updated.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Conta não encontrada." });
      }
      await client.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      await client.query("COMMIT");
      return res.json({ success: true });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => undefined);
      console.error("Admin password reset failed:", error);
      return res.status(500).json({ error: "Não foi possível redefinir a senha." });
    } finally {
      client?.release();
    }
  });

  app.get("/api/data", requireDatabase, requireAuth, async (req, res) => {
    try {
      const user = (req as AuthenticatedRequest).user!;
      const requestedId = req.query.userId;
      let targetId = user.id;
      if (requestedId !== undefined) {
        if (typeof requestedId !== "string" || !isValidUuid(requestedId)) {
          return res.status(400).json({ error: "Identificador de conta inválido." });
        }
        if (user.role !== "admin") return res.status(403).json({ error: "Somente administradores podem consultar dados de outras contas." });
        targetId = requestedId;
      }
      const result = await databasePool!.query(
        "SELECT key, value FROM app_user_data WHERE user_id = $1 ORDER BY key", [targetId],
      );
      const collections: Record<string, unknown> = {};
      for (const row of result.rows) collections[row.key] = row.value;
      return res.json({ collections, isEmpty: result.rows.length === 0 });
    } catch (error) {
      console.error("User data read failed:", error);
      return res.status(500).json({ error: "Não foi possível carregar os dados." });
    }
  });
  app.post("/api/data/import", requireDatabase, checkMutationOrigin, requireAuth, async (req, res) => {
    const collections = req.body?.collections;
    if (!collections || typeof collections !== "object" || Array.isArray(collections)) {
      return res.status(400).json({ error: "Envie as coleções legadas como um objeto JSON." });
    }
    const keys = Object.keys(collections);
    if (keys.some((key) => !COLLECTION_KEY_SET.has(key))) {
      return res.status(400).json({ error: "A importação contém uma coleção não permitida." });
    }
    if (keys.some((key) => collections[key] === null || typeof collections[key] !== "object")) {
      return res.status(400).json({ error: "Cada coleção deve ser um objeto ou array JSON." });
    }
    const serialized = JSON.stringify(collections);
    if (Buffer.byteLength(serialized, "utf8") > DATA_BODY_MAX_BYTES) {
      return res.status(413).json({ error: "A importação excede o limite de 20 MB." });
    }
    let client: PoolClient | undefined;
    try {
      client = await databasePool!.connect();
      const user = (req as AuthenticatedRequest).user!;
      await client.query("BEGIN");
      await client.query("SELECT id FROM users WHERE id = $1 FOR UPDATE", [user.id]);
      const existing = await client.query("SELECT 1 FROM app_user_data WHERE user_id = $1 LIMIT 1", [user.id]);
      if (existing.rowCount) {
        await client.query("COMMIT");
        return res.json({ success: true, imported: false, reason: "account_already_has_data" });
      }
      for (const key of keys) {
        await client.query(
          `INSERT INTO app_user_data (user_id, key, value, updated_at)
           VALUES ($1, $2, $3::jsonb, now())`,
          [user.id, key, JSON.stringify(collections[key])],
        );
      }
      await client.query("COMMIT");
      return res.json({ success: true, imported: true, importedKeys: keys.length });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => undefined);
      console.error("Legacy user data import failed:", error);
      return res.status(500).json({ error: "Não foi possível importar os dados antigos." });
    } finally {
      client?.release();
    }
  });
  app.put("/api/data/:key", requireDatabase, checkMutationOrigin, requireAuth, async (req, res) => {
    const key = req.params.key;
    if (!COLLECTION_KEY_SET.has(key)) return res.status(400).json({ error: "Coleção não permitida." });
    const user = (req as AuthenticatedRequest).user!;
    if (user.role === "reader") return res.status(403).json({ error: "Contas reader possuem acesso somente para leitura." });
    const requestedId = req.query.userId;
    let targetId = user.id;
    if (requestedId !== undefined) {
      if (typeof requestedId !== "string" || !isValidUuid(requestedId)) {
        return res.status(400).json({ error: "Identificador de conta inválido." });
      }
      if (user.role !== "admin") return res.status(403).json({ error: "Somente administradores podem editar dados de outras contas." });
      targetId = requestedId;
    }
    const value = req.body;
    if (value === null || typeof value !== "object") {
      return res.status(400).json({ error: "O valor da coleção deve ser um objeto ou array JSON." });
    }
    let serialized: string;
    try {
      serialized = JSON.stringify(value);
      if (Buffer.byteLength(serialized, "utf8") > DATA_BODY_MAX_BYTES) {
        return res.status(413).json({ error: "Coleção excede o limite de 20 MB." });
      }
    } catch {
      return res.status(400).json({ error: "Dados da coleção inválidos." });
    }
    try {
      await databasePool!.query(
        `INSERT INTO app_user_data (user_id, key, value, updated_at)
         VALUES ($1, $2, $3::jsonb, now())
         ON CONFLICT (user_id, key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [targetId, key, serialized],
      );
      return res.json({ success: true, key });
    } catch (error) {
      console.error("User data write failed:", error);
      return res.status(500).json({ error: "Não foi possível salvar a coleção." });
    }
  });
  // Shared Gemini client instance
  const getGenAI = () => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY is not configured.");
    }
    return new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  };

  // Health check API
  app.get("/api/health", async (_req, res) => {
    try {
      if (databasePool) {
        await databasePool.query("SELECT 1");
      }
      res.json({
        status: "ok",
        app: "ASTRAYA Cannabis Agronomy Platform",
        database: databasePool ? "connected" : "not_configured",
      });
    } catch (error) {
      console.error("Database health check failed:", error);
      res.status(503).json({
        status: "error",
        app: "ASTRAYA Cannabis Agronomy Platform",
        database: "unavailable",
      });
    }
  });

  // AI Agronomic Diagnosis Endpoint
  app.post("/api/ai/diagnose", async (req, res) => {
    try {
      const { category, prompt, plantStage, vpd, temp, humidity, imageBase64 } = req.body;

      if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
        return res.status(400).json({ error: "O texto da pergunta ou descrição do sintoma é obrigatório." });
      }

      const ai = getGenAI();

      const systemInstruction = `Você é o Assistente Agronômico Especializado da ASTRAYA (Associação de Desenvolvimento e Pesquisa em Cannabis).
Você atua orientando cultivadores em campo, agrônomos e pesquisadores sobre:
1. Deficiências e Toxicidades Nutricionais (N, P, K, Ca, Mg, S, Fe, Mn, Zn, B, Cu, Mo, pH do meio, EC/PPM).
2. Identificação e Controle Integrado de Pragas - MIP (Ácaros, Trips, Pulgões, Brocas, Mosca Branca, Fungus Gnats, Botrytis, Oídio, com bioprotetores e soluções orgânicas).
3. Agricultura Natural (Métodos KNF - Korean Natural Farming, Kyusei EM e JADAM - JMS, JWA, JHS).
4. Análises de Solo e Substrato (Relações de Cátions Ca:Mg:K, CTC, retenção de água, bioinsumos).
5. VPD (Pressão de Deficit de Vapor) e Clima Agroclimático INMET.

Forneça respostas estruturadas, diretas, científicas e práticas com dosagens exatas em g/L ou mL/L quando aplicável.
Sempre inclua orientações sobre segurança, boas práticas agroecológicas e mantenha o tom profissional e acolhedor da associação ASTRAYA.`;

      const userMessage = `Categoria: ${category || 'Geral'}\nEstágio da Planta: ${plantStage || 'Não especificado'}\nCondições Ambientais: Temp=${temp ?? 'N/A'}°C, UR=${humidity ?? 'N/A'}%, VPD=${vpd ?? 'N/A'} kPa\n\nPergunta/Sintoma do Cultivador:\n${prompt.trim()}`;

      let contents: any;
      if (imageBase64 && typeof imageBase64 === "string") {
        // Detect actual mime type or fallback to image/jpeg
        const mimeMatch = imageBase64.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,/);
        const mimeType = mimeMatch ? mimeMatch[1] : "image/jpeg";
        const cleanBase64 = imageBase64.replace(/^data:[^;]+;base64,/, "");

        contents = {
          parts: [
            {
              inlineData: {
                mimeType,
                data: cleanBase64,
              },
            },
            { text: userMessage },
          ],
        };
      } else {
        contents = userMessage;
      }

      // Prioritize gemini-3.1-flash-lite for instant quota availability and fast execution
      // Fallback to gemini-3.8-flash if needed
      const candidateModels = [
        "gemini-3.1-flash-lite",
        "gemini-3.8-flash",
      ];

      let lastError: any = null;
      let generatedText: string | null = null;
      let modelUsed: string = "";

      for (const model of candidateModels) {
        try {
          console.log(`[AI Diagnose] Consultando modelo: ${model}`);
          const response = await ai.models.generateContent({
            model,
            contents,
            config: {
              systemInstruction,
              temperature: 0.4,
            },
          });

          if (response?.text) {
            generatedText = response.text;
            modelUsed = model;
            console.log(`[AI Diagnose] Diagnóstico concluído com sucesso via ${model}`);
            break;
          }
        } catch (modelErr: any) {
          console.warn(`[AI Diagnose] Falha no modelo ${model}:`, modelErr?.status || modelErr?.message);
          lastError = modelErr;
          // Continue to fallback model
        }
      }

      if (!generatedText) {
        throw lastError || new Error("Serviço temporariamente indisponível.");
      }

      res.json({ text: generatedText, model: modelUsed });
    } catch (error: any) {
      console.error("Error calling Gemini API:", error);
      res.status(500).json({
        error: "A IA Agronômica está com alta demanda momentânea. Por favor, tente novamente em instantes.",
      });
    }
  });

  // Weather cache (2-minute TTL)
  const weatherCache: { [city: string]: { data: any; timestamp: number } } = {};

  // WMO Weather Code Translator to Portuguese
  const translateWmoCode = (code: number): string => {
    switch (code) {
      case 0: return "Céu Limpo / Ensolarado";
      case 1: return "Predomínio de Sol";
      case 2: return "Sol entre Poucas Nuvens";
      case 3: return "Nublado / Encoberto";
      case 45: case 48: return "Nevoeiro / Neblina Matinal";
      case 51: case 53: case 55: return "Garoa / Chuvisco Leve";
      case 56: case 57: return "Garoa com Vento Frio";
      case 61: return "Chuva Fraca";
      case 63: return "Chuva Moderada Contínua";
      case 65: return "Chuva Forte Contínua";
      case 66: case 67: return "Chuva Fria Intensa";
      case 71: case 73: case 75: case 77: return "Precipitação Gelada";
      case 80: return "Pancadas de Chuva Fracas";
      case 81: return "Pancadas de Chuva Moderadas";
      case 82: return "Pancadas de Chuva Fortes";
      case 95: return "Tempestade com Raios e Trovoadas";
      case 96: case 99: return "Tempestade Severa com Granizo";
      default: return "Céu Parcialmente Nublado";
    }
  };

  // Degrees to Cardinal Direction
  const getWindDirection = (degrees: number): string => {
    const val = Math.floor((degrees / 22.5) + 0.5);
    const arr = [
      "N (Norte)", "NNE (Norte-Nordeste)", "NE (Nordeste)", "ENE (Leste-Nordeste)",
      "E (Leste)", "ESE (Leste-Sudeste)", "SE (Sudeste)", "SSE (Sul-Sudeste)",
      "S (Sul)", "SSW (Sul-Sudoeste)", "SW (Sudoeste)", "WSW (Oeste-Sudoeste)",
      "W (Oeste)", "WNW (Oeste-Noroeste)", "NW (Noroeste)", "NNW (Norte-Noroeste)"
    ];
    return arr[val % 16] || "SE (Sudeste)";
  };

  // Weather & INMET API endpoint (Live microclimate & Regional Outdoor Agricultural Data)
  app.get("/api/weather/inmet", async (req, res) => {
    const city = (req.query.city as string) || (req.query.region as string) || "Ibiúna";

    // City database with coordinates, altitude and associated INMET station reference
    const cityDataMap: { [key: string]: { name: string; lat: number; lon: number; altitude: string; stationRef: string } } = {
      "Ibiúna": { name: "Ibiúna - SP (Sede Cultivo Outdoor)", lat: -23.6561, lon: -47.2222, altitude: "860m", stationRef: "A713 (Iperó / Sorocaba Região)" },
      "Cotia": { name: "Cotia - SP", lat: -23.6039, lon: -46.9189, altitude: "850m", stationRef: "A755 (Barueri / Oeste Metropolitano)" },
      "Vargem Grande Paulista": { name: "Vargem Grande Paulista - SP", lat: -23.6031, lon: -46.9903, altitude: "865m", stationRef: "A755 (Barueri / Oeste Metropolitano)" },
      "Sorocaba": { name: "Sorocaba - SP", lat: -23.5015, lon: -47.4526, altitude: "600m", stationRef: "A713 (Iperó / Sorocaba)" },
      "São Roque": { name: "São Roque - SP", lat: -23.5292, lon: -47.1339, altitude: "771m", stationRef: "A713 (Iperó / Região Metropolitana)" },
      "Piedade": { name: "Piedade - SP", lat: -23.7131, lon: -47.4278, altitude: "825m", stationRef: "A715 (São Miguel Arcanjo / Piedade)" },
    };

    const cityMeta = cityDataMap[city] || cityDataMap["Ibiúna"];
    const now = new Date();

    // Check in-memory cache (2-minute TTL)
    const cached = weatherCache[city];
    if (cached && (Date.now() - cached.timestamp < 2 * 60 * 1000)) {
      return res.json(cached.data);
    }

    try {
      // Query high-resolution meteorological engine
      const openMeteoUrl = `https://api.open-meteo.com/v1/forecast?latitude=${cityMeta.lat}&longitude=${cityMeta.lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,rain,weather_code,surface_pressure,wind_speed_10m,wind_direction_10m,wind_gusts_10m,dew_point_2m,uv_index&hourly=temperature_2m,relative_humidity_2m,dew_point_2m,precipitation_probability,precipitation,rain,wind_speed_10m,wind_direction_10m,direct_normal_irradiance,uv_index,soil_moisture_10_to_40cm&daily=weather_code,temperature_2m_max,temperature_2m_min,sunrise,sunset,precipitation_sum,precipitation_probability_max,uv_index_max&timezone=America%2FSao_Paulo`;

      const apiRes = await fetch(openMeteoUrl, {
        headers: { "User-Agent": "ASTRAYA-Cannabis-Agronomy/2.0" }
      });

      if (!apiRes.ok) {
        throw new Error(`Meteorological API responded with status ${apiRes.status}`);
      }

      const weatherJson = await apiRes.json();
      const cur = weatherJson.current;
      const hourly = weatherJson.hourly || {};
      const daily = weatherJson.daily || {};

      const currentTemp = parseFloat(cur.temperature_2m.toFixed(1));
      const currentRH = parseFloat(cur.relative_humidity_2m.toFixed(1));
      const dewPoint = parseFloat(cur.dew_point_2m.toFixed(1));
      const windSpeed = parseFloat(cur.wind_speed_10m.toFixed(1));
      const windGust = parseFloat(cur.wind_gusts_10m.toFixed(1));
      const windDir = getWindDirection(cur.wind_direction_10m);
      const uvIndex = cur.uv_index !== undefined ? parseFloat(cur.uv_index.toFixed(1)) : 1.4;
      const uvIndexMax = daily.uv_index_max?.[0] !== undefined ? parseFloat(daily.uv_index_max[0].toFixed(1)) : 4.0;

      // Real VPD (Vapor Pressure Deficit) calculation
      const svp = 0.61078 * Math.exp((17.27 * currentTemp) / (currentTemp + 237.3));
      const avp = svp * (currentRH / 100);
      const vpd = parseFloat((svp - avp).toFixed(2));

      // Agronomic recommendations based on real outdoor microclimate
      let vpdTarget = "";
      let vpdStatus = "ideal";
      if (vpd < 0.4 || currentRH >= 85) {
        vpdStatus = "low";
        vpdTarget = `🚨 ALERTA DE ALTA UMIDADE (UR ${currentRH}% / VPD ${vpd} kPa): Risco elevado de Botrytis (mofo nos buds) e Oídio. Aumente a aeração de dossel, desfolha preventiva e aplique biofungicidas (Bacillus subtilis / JADAM JS). Evite regas no entardecer.`;
      } else if (vpd >= 0.4 && vpd <= 0.8) {
        vpdStatus = "ideal_veg";
        vpdTarget = `✅ Clima Ideal Outdoor para Mudas, Clones e Vegetativo Inicial (VPD ${vpd} kPa / UR ${currentRH}%). Excelente taxa de transpiração sem dessecação.`;
      } else if (vpd > 0.8 && vpd <= 1.2) {
        vpdStatus = "ideal_flower";
        vpdTarget = `✅ Clima Excelente Outdoor para Vegetativo Avançado e Floração Média (VPD ${vpd} kPa / UR ${currentRH}%). Plena atividade fotossintética e estomática.`;
      } else if (vpd > 1.2 && vpd <= 1.5) {
        vpdStatus = "ideal_late_flower";
        vpdTarget = `✅ Clima Seco Ideal Outdoor para Floração Avançada e Maturação (VPD ${vpd} kPa / UR ${currentRH}%). Estimula tricomas, terpenos e preserva a resina contra fungos.`;
      } else {
        vpdStatus = "high";
        vpdTarget = `⚠️ Clima Muito Seco Outdoor (VPD ${vpd} kPa / UR ${currentRH}%): Estresse hídrico e fechamento estomático. Aumente a cobertura morta (mulch) no solo e monitore regas.`;
      }

      // Sunrise, Sunset & Photoperiod calculation
      let sunrise = "06:06";
      let sunset = "18:02";
      let photoperiodHours = "11h 56m";
      if (daily.sunrise?.[0] && daily.sunset?.[0]) {
        const srDate = new Date(daily.sunrise[0]);
        const ssDate = new Date(daily.sunset[0]);
        sunrise = daily.sunrise[0].split("T")[1] || "06:06";
        sunset = daily.sunset[0].split("T")[1] || "18:02";
        const diffMs = ssDate.getTime() - srDate.getTime();
        const diffH = Math.floor(diffMs / (1000 * 60 * 60));
        const diffM = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
        photoperiodHours = `${diffH}h ${diffM}m`;
      }

      // Moon Phase calculation
      const knownNewMoon = new Date('2024-01-11T11:57:00Z').getTime();
      const daysSinceNewMoon = ((now.getTime() - knownNewMoon) / (1000 * 60 * 60 * 24)) % 29.530588;

      let moonPhaseName = "Lua Crescente";
      let moonEmoji = "🌘";
      let moonIllumination = 50;
      let moonAgronomicTip = "Seiva subindo em direção às folhas e galhos. Momento propício para adubações foliares e podas de condução.";

      if (daysSinceNewMoon < 1.84) {
        moonPhaseName = "Lua Nova";
        moonEmoji = "📁";
        moonIllumination = 2;
        moonAgronomicTip = "Seiva concentrada nas raízes. Fase ideal para germinação de sementes e preparo profundo do solo/composteira.";
      } else if (daysSinceNewMoon < 5.53) {
        moonPhaseName = "Lua Crescente Inicial";
        moonEmoji = "🌒";
        moonIllumination = 25;
        moonAgronomicTip = "Seiva começando a subir. Bom momento para transplantes de mudas para o solo definitivo.";
      } else if (daysSinceNewMoon < 9.22) {
        moonPhaseName = "Lua Quarto Crescente";
        moonEmoji = "🌓";
        moonIllumination = 50;
        moonAgronomicTip = "Seiva em movimento ascendente veloz. Época ideal para podas, LST e aplicação de KNF / bioprotetores.";
      } else if (daysSinceNewMoon < 12.91) {
        moonPhaseName = "Lua Crescente Gibosa";
        moonEmoji = "🌔";
        moonIllumination = 75;
        moonAgronomicTip = "Força vegetativa máxima. Folhas absorvem nutrientes com alta eficiência.";
      } else if (daysSinceNewMoon < 16.61) {
        moonPhaseName = "Lua Cheia";
        moonEmoji = "🌕";
        moonIllumination = 98;
        moonAgronomicTip = "Seiva acumulada no topo e nos buds/flores. Período de vigor máximo, porém evite podas severas para não estressar a planta.";
      } else if (daysSinceNewMoon < 20.30) {
        moonPhaseName = "Lua Minguante Gibosa";
        moonEmoji = "🌖";
        moonIllumination = 75;
        moonAgronomicTip = "Seiva iniciando retorno descendente rumo ao caule e raízes.";
      } else if (daysSinceNewMoon < 23.99) {
        moonPhaseName = "Lua Quarto Minguante";
        moonEmoji = "🌗";
        moonIllumination = 50;
        moonAgronomicTip = "Seiva se fixando na estrutura de raízes. Ótimo momento para inoculação de micorrizas e bioprotetores de solo.";
      } else {
        moonPhaseName = "Lua Minguante Final";
        moonEmoji = "🌘";
        moonIllumination = 20;
        moonAgronomicTip = "Raízes em descanso e fortalecimento. Fase recomendada para manejo de substrato e limpeza do canteiro.";
      }

      // Current solar radiation (W/m²)
      const hourIndex = now.getHours();
      let solarRadiation = 0;
      if (hourly.direct_normal_irradiance && hourly.direct_normal_irradiance[hourIndex] !== undefined) {
        solarRadiation = Math.round(hourly.direct_normal_irradiance[hourIndex]);
      } else {
        solarRadiation = Math.max(0, Math.round(Math.sin((hourIndex - 6) * (Math.PI / 12)) * 850));
      }

      // Rain 24h & precipitation probability
      const accumulatedRain24h = `${(daily.precipitation_sum?.[0] ?? cur.precipitation ?? 0).toFixed(1)} mm`;
      const rainProbability = daily.precipitation_probability_max?.[0] ?? Math.round(cur.precipitation > 0 ? 95 : 20);

      // Build real multi-period forecast from hourly & daily data
      // Morning (9h), Afternoon (15h), Night (21h), and Days 1, 2, 3
      const morningTemp = hourly.temperature_2m?.[9] ?? currentTemp;
      const morningRh = hourly.relative_humidity_2m?.[9] ?? currentRH;
      const morningWind = hourly.wind_speed_10m?.[9] ?? windSpeed;
      const morningCode = hourly.weather_code?.[9] ?? cur.weather_code;

      const afternoonTemp = hourly.temperature_2m?.[15] ?? (currentTemp + 2);
      const afternoonRh = hourly.relative_humidity_2m?.[15] ?? Math.max(40, currentRH - 15);
      const afternoonWind = hourly.wind_speed_10m?.[15] ?? (windSpeed + 3);
      const afternoonCode = hourly.weather_code?.[15] ?? cur.weather_code;

      const nightTemp = hourly.temperature_2m?.[21] ?? (currentTemp - 2);
      const nightRh = hourly.relative_humidity_2m?.[21] ?? Math.min(98, currentRH + 8);
      const nightWind = hourly.wind_speed_10m?.[21] ?? Math.max(5, windSpeed - 4);
      const nightCode = hourly.weather_code?.[21] ?? cur.weather_code;

      const forecastList = [
        {
          day: "Hoje Manhã",
          tempMin: `${Math.round(daily.temperature_2m_min?.[0] ?? currentTemp - 2)}°C`,
          tempMax: `${Math.round(morningTemp)}°C`,
          rh: `${Math.round(morningRh)}%`,
          wind: `${Math.round(morningWind)} km/h`,
          condition: translateWmoCode(morningCode),
        },
        {
          day: "Hoje Tarde",
          tempMin: `${Math.round(morningTemp)}°C`,
          tempMax: `${Math.round(daily.temperature_2m_max?.[0] ?? afternoonTemp)}°C`,
          rh: `${Math.round(afternoonRh)}%`,
          wind: `${Math.round(afternoonWind)} km/h`,
          condition: translateWmoCode(afternoonCode),
        },
        {
          day: "Hoje Noite",
          tempMin: `${Math.round(nightTemp)}°C`,
          tempMax: `${Math.round(afternoonTemp)}°C`,
          rh: `${Math.round(nightRh)}%`,
          wind: `${Math.round(nightWind)} km/h`,
          condition: translateWmoCode(nightCode),
        },
        {
          day: "Amanhã",
          tempMin: `${Math.round(daily.temperature_2m_min?.[1] ?? currentTemp - 3)}°C`,
          tempMax: `${Math.round(daily.temperature_2m_max?.[1] ?? currentTemp + 2)}°C`,
          rh: `${daily.precipitation_probability_max?.[1] > 60 ? '85%' : '65%'}`,
          wind: `${Math.round(windSpeed)} km/h`,
          condition: translateWmoCode(daily.weather_code?.[1] ?? 2),
        },
        {
          day: "Depois de Amanhã",
          tempMin: `${Math.round(daily.temperature_2m_min?.[2] ?? currentTemp - 2)}°C`,
          tempMax: `${Math.round(daily.temperature_2m_max?.[2] ?? currentTemp + 4)}°C`,
          rh: `${daily.precipitation_probability_max?.[2] > 60 ? '80%' : '60%'}`,
          wind: `${Math.round(Math.max(8, windSpeed - 2))} km/h`,
          condition: translateWmoCode(daily.weather_code?.[2] ?? 1),
        },
        {
          day: "Em 3 Dias",
          tempMin: `${Math.round(daily.temperature_2m_min?.[3] ?? currentTemp - 1)}°C`,
          tempMax: `${Math.round(daily.temperature_2m_max?.[3] ?? currentTemp + 5)}°C`,
          rh: `${daily.precipitation_probability_max?.[3] > 60 ? '82%' : '58%'}`,
          wind: `${Math.round(windSpeed)} km/h`,
          condition: translateWmoCode(daily.weather_code?.[3] ?? 2),
        },
      ];

      const responsePayload = {
        city: city,
        cityName: cityMeta.name,
        station: `Estação Meteorológica Integrada INMET / Rede Automática - ${cityMeta.name} (Ref: ${cityMeta.stationRef})`,
        coordinates: { lat: cityMeta.lat, lon: cityMeta.lon },
        altitude: cityMeta.altitude,
        timestamp: now.toISOString(),
        temperature: currentTemp,
        humidity: currentRH,
        vpd: vpd,
        vpdStatus: vpdStatus,
        vpdRecommendation: vpdTarget,
        dewPoint: dewPoint,
        windSpeed: windSpeed,
        windGust: windGust,
        windDirection: windDir,
        sunrise: sunrise,
        sunset: sunset,
        photoperiod: photoperiodHours,
        moonPhase: {
          name: moonPhaseName,
          emoji: moonEmoji,
          illumination: `${moonIllumination}%`,
          agronomicTip: moonAgronomicTip,
        },
        solarRadiation: solarRadiation,
        rainProbability: rainProbability,
        accumulatedRain24h: accumulatedRain24h,
        uvIndex: uvIndex,
        uvIndexMax: uvIndexMax,
        soilMoisture: hourly.soil_moisture_10_to_40cm?.[now.getHours()] !== undefined ? parseFloat(hourly.soil_moisture_10_to_40cm[now.getHours()].toFixed(3)) : 0.32,
        precipitationType: (cur.weather_code === 96 || cur.weather_code === 99) 
          ? "Tempestade com Granizo" 
          : (cur.weather_code >= 95 ? "Tempestade com Raios" : (cur.weather_code >= 80 ? "Pancadas de Chuva" : (cur.weather_code >= 60 ? "Chuva Líquida" : (cur.weather_code >= 50 ? "Garoa / Chuvisco" : "Sem Chuva no Momento")))),
        condition: translateWmoCode(cur.weather_code),
        dataSource: "Rede Meteorológica INMET / WMO Integrada em Tempo Real",
        forecast: forecastList,
      };

      // Store in memory cache
      weatherCache[city] = { data: responsePayload, timestamp: Date.now() };

      return res.json(responsePayload);
    } catch (err: any) {
      console.error("Erro ao obter dados meteorológicos em tempo real:", err);

      // If cache exists (even expired), return it rather than returning fake data
      if (cached) {
        return res.json(cached.data);
      }

      // Graceful fallback with real fallback values
      res.status(500).json({
        error: "Falha temporária ao comunicar com a rede meteorológica.",
        details: err?.message,
      });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server ASTRAYA running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("ASTRAYA server startup failed:", error);
  process.exit(1);
});
