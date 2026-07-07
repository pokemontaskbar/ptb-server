// ============================================================================
// PTB SERVER - Minimal server (Phase 1, step 2 of PLANO_BACKEND_TOKEN.md)
// ----------------------------------------------------------------------------
// WHAT THIS SERVER DOES (and ONLY this - on purpose, no scope creep):
//   1. Creates a player account (email + password).
//   2. Login (returns a temporary "badge" = session token).
//   3. Saves the game save on the server (per player).
//   4. Loads the game save from the server.
//
// WHAT IT DOES NOT DO YET (comes in the next steps of the plan):
//   - Recompute economy (the "judge") ...... step 3 of Phase 1
//   - Anti-cheat ........................... step 4 of Phase 1
//   - Token / deposit / withdrawal ......... Phases 3 and 4
//
// This step only proves we can MOVE the save out of the browser and store it on the server.
// ============================================================================

import Fastify from 'fastify';
import cors from '@fastify/cors';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

// ---- Connection to the Postgres database -----------------------------------
// The database URL comes from an "environment variable" (Railway provides it
// automatically when you add a Postgres to the project - 1 click).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway/Render use SSL; local does not. Auto-detects.
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

// ---- Create the database tables the first time the server starts up ---------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id           BIGSERIAL PRIMARY KEY,
      email        TEXT UNIQUE NOT NULL,
      pass_hash    TEXT NOT NULL,        -- password NEVER stored in plain text
      pass_salt    TEXT NOT NULL,        -- unique "salt" per player
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS saves (
      player_id    BIGINT PRIMARY KEY REFERENCES players(id) ON DELETE CASCADE,
      save_json    JSONB NOT NULL,       -- the game save, exactly as the game sends it
      version      TEXT,
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token        TEXT PRIMARY KEY,     -- the temporary login "badge"
      player_id    BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// ---- Password security: hash with salt (standard, never store plain password) -----
function hashPassword(password, salt) {
  // scrypt: deliberately slow algorithm, hardens against brute-force attacks.
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function newSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ---- Web server ------------------------------------------------------------
const app = Fastify({ logger: true });
await app.register(cors, { origin: true }); // lets the game (in the browser) talk to the server

// Server health (to know if it's up)
app.get('/health', async () => ({ ok: true, ts: Date.now() }));

// ---- CREATE ACCOUNT --------------------------------------------------------
// The game sends { email, password }. The server creates the player.
app.post('/register', async (req, reply) => {
  const { email, password } = req.body || {};
  if (!email || !password) return reply.code(400).send({ error: 'Email and password are required' });
  if (String(password).length < 6) return reply.code(400).send({ error: 'Password too short (min 6)' });

  const salt = newSalt();
  const hash = hashPassword(password, salt);
  try {
    const r = await pool.query(
      'INSERT INTO players (email, pass_hash, pass_salt) VALUES ($1,$2,$3) RETURNING id',
      [String(email).toLowerCase().trim(), hash, salt]
    );
    return { ok: true, playerId: r.rows[0].id };
  } catch (e) {
    if (e.code === '23505') return reply.code(409).send({ error: 'Email already registered' });
    req.log.error(e);
    return reply.code(500).send({ error: 'Failed to create account' });
  }
});

// ---- LOGIN -----------------------------------------------------------------
// The game sends { email, password }. If it matches, returns a "badge" (token).
app.post('/login', async (req, reply) => {
  const { email, password } = req.body || {};
  if (!email || !password) return reply.code(400).send({ error: 'Email and password are required' });

  const r = await pool.query('SELECT id, pass_hash, pass_salt FROM players WHERE email=$1',
    [String(email).toLowerCase().trim()]);
  if (r.rowCount === 0) return reply.code(401).send({ error: 'Invalid email or password' });

  const p = r.rows[0];
  const hash = hashPassword(password, p.pass_salt);
  // Comparacao segura (evita "timing attack")
  const ok = hash.length === p.pass_hash.length &&
             crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(p.pass_hash));
  if (!ok) return reply.code(401).send({ error: 'Invalid email or password' });

  const token = newSessionToken();
  await pool.query('INSERT INTO sessions (token, player_id) VALUES ($1,$2)', [token, p.id]);
  return { ok: true, token, playerId: p.id };
});

// ---- Middleware: figure out WHO is requesting (by the badge) ---------------
async function requirePlayer(req, reply) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) { reply.code(401).send({ error: 'Not authenticated (please log in)' }); return null; }
  const r = await pool.query('SELECT player_id FROM sessions WHERE token=$1', [token]);
  if (r.rowCount === 0) { reply.code(401).send({ error: 'Invalid session (please log in)' }); return null; }
  return r.rows[0].player_id;
}

// ---- SAVE THE SAVE ---------------------------------------------------------
// The game sends the whole save (the same object that today goes to localStorage).
// NOTE: at this step the server TRUSTS the save (just stores it). The "judge" that
// validates the numbers comes in step 3 - not yet cheat-proof, and
// that's fine: this step only proves the foundation (move the save out of the browser).
app.post('/save', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const save = req.body;
  if (!save || typeof save !== 'object') return reply.code(400).send({ error: 'Invalid save data' });

  await pool.query(
    `INSERT INTO saves (player_id, save_json, version, updated_at)
     VALUES ($1,$2,$3, now())
     ON CONFLICT (player_id) DO UPDATE SET save_json=$2, version=$3, updated_at=now()`,
    [playerId, save, save.v || null]
  );
  return { ok: true, savedAt: Date.now() };
});

// ---- LOAD THE SAVE ---------------------------------------------------------
app.get('/save', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const r = await pool.query('SELECT save_json, updated_at FROM saves WHERE player_id=$1', [playerId]);
  if (r.rowCount === 0) return { ok: true, save: null }; // new player, no save yet
  return { ok: true, save: r.rows[0].save_json, updatedAt: r.rows[0].updated_at };
});

// ---- Start the server ------------------------------------------------------
const PORT = process.env.PORT || 3000;
try {
  await initDb();
  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info(`PTB server minimo no ar na porta ${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
