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
  // ---- Ranking migrations (idempotent) ----
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS nickname TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS players_nickname_uq ON players (LOWER(nickname)) WHERE nickname IS NOT NULL`);
  await pool.query(`ALTER TABLE saves ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0`);
  await pool.query(`CREATE INDEX IF NOT EXISTS saves_score_idx ON saves (score DESC)`);
  // ---- Blockchain-prep migrations (idempotent) ----
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS wallet TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS players_wallet_uq ON players (wallet) WHERE wallet IS NOT NULL`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS reg_ip TEXT`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS last_ip TEXT`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`);
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

// Leaderboard cache (declared early: /save invalidates it before it's defined below)
let _lbCache = null, _lbCacheTs = 0;
// ---- SERVER-SIDE SCORE (mini-judge for the ranking) -------------------------
// The client's `score` field is NEVER trusted. The server recomputes the score
// from the finite, verifiable sets in the save (species/stages/acts), using the
// exact same formulas as the game. This kills the trivial `G.score=999999`
// cheat and enforces a hard mathematical ceiling.
const POKE_BST = [0,318,405,525,309,405,534,314,405,530,195,205,395,195,205,395,251,349,479,253,413,262,442,288,448,320,485,300,450,275,365,505,273,365,505,323,483,299,505,270,435,245,455,320,395,490,285,405,305,450,265,425,290,440,320,500,305,455,350,555,300,385,510,310,400,500,305,405,505,300,390,490,335,515,300,390,495,410,500,315,490,325,465,377,310,470,325,475,325,500,305,525,310,405,500,385,328,483,325,475,330,490,325,530,320,425,455,455,385,340,490,345,485,450,435,490,295,440,320,450,340,520,460,500,455,490,495,500,490,200,540,535,288,325,525,525,525,395,355,495,355,495,515,540,580,580,580,300,420,600,680,600];
const RARITY_STR = '1231231231111111131212121312113113131312121131212121213121411312312311313113131312113131313123113131313122211313223121213232333314311333113133455512455';
function rarityOf(id){ const c = RARITY_STR.charCodeAt(id-1)-48; return (c>=1&&c<=5)?c:1; }
function speciesPoints(sp){
  const bst = POKE_BST[sp] || 200;
  const rarMul = 1 + (rarityOf(sp)-1)*0.5;
  return Math.max(1, Math.round((bst/20) * rarMul));
}
// ---- Solana wallet validation (real base58 decode -> must be 32 bytes) ------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function isSolanaAddress(str){
  if (typeof str !== 'string' || str.length < 32 || str.length > 44) return false;
  let n = 0n;
  for (const ch of str){
    const v = B58.indexOf(ch);
    if (v < 0) return false;
    n = n * 58n + BigInt(v);
  }
  // count bytes: leading '1' chars = leading zero bytes
  let zeros = 0; for (const ch of str){ if (ch === '1') zeros++; else break; }
  let bytes = 0; let t = n;
  while (t > 0n){ bytes++; t >>= 8n; }
  return (zeros + bytes) === 32;
}

function stagePoints(gs){ return gs * 10; }
function actPoints(ai){ return (ai + 1) * 500; }

// Validates the sets and recomputes the score. Garbage in -> ignored.
function computeScore(save){
  if(!save || typeof save !== 'object') return 0;
  let total = 0;
  const species = Array.isArray(save.scoredSpecies) ? save.scoredSpecies : [];
  const stages  = Array.isArray(save.scoredStages)  ? save.scoredStages  : [];
  const acts    = Array.isArray(save.scoredActs)    ? save.scoredActs    : [];
  // species: unique ints 1..151
  const sp = new Set();
  for(const v of species){ if(Number.isInteger(v) && v>=1 && v<=151) sp.add(v); }
  for(const v of sp) total += speciesPoints(v);
  // stages: unique ints 1..120 (game documents st1..st120)
  const st = new Set();
  for(const v of stages){ if(Number.isInteger(v) && v>=1 && v<=120) st.add(v); }
  for(const v of st) total += stagePoints(v);
  // acts: unique ints 0..11 (12 global acts, 500..6000)
  const ac = new Set();
  for(const v of acts){ if(Number.isInteger(v) && v>=0 && v<=11) ac.add(v); }
  for(const v of ac) total += actPoints(v);
  return total;
}

// ---- Web server ------------------------------------------------------------
const app = Fastify({ logger: true, trustProxy: true }); // trustProxy: real client IP behind Render's proxy
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
      'INSERT INTO players (email, pass_hash, pass_salt, reg_ip) VALUES ($1,$2,$3,$4) RETURNING id',
      [String(email).toLowerCase().trim(), hash, salt, req.ip || null]
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
  await pool.query('UPDATE players SET last_ip=$1, last_login=now() WHERE id=$2', [req.ip || null, p.id]);
  return { ok: true, token, playerId: p.id };
});

// ---- SET SOLANA WALLET --------------------------------------------------------
// One wallet per account (UNIQUE) - the same wallet cannot sit on two accounts.
// Prizes are paid manually by the admin to these wallets.
app.post('/wallet', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const wallet = String(req.body?.wallet || '').trim();
  if (!isSolanaAddress(wallet)) {
    return reply.code(400).send({ error: 'Invalid Solana address' });
  }
  try {
    await pool.query('UPDATE players SET wallet=$1 WHERE id=$2', [wallet, playerId]);
    return { ok: true, wallet };
  } catch (e) {
    if (e.code === '23505') return reply.code(409).send({ error: 'This wallet is already linked to another account' });
    throw e;
  }
});

// ---- GET current wallet (so the UI can show what's linked) ------------------
app.get('/wallet', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const r = await pool.query('SELECT wallet FROM players WHERE id=$1', [playerId]);
  return { ok: true, wallet: r.rows[0]?.wallet || null };
});

// ---- ADMIN: winners + wallets (for manual prize payment) ----------------------
// Protected by ADMIN_KEY env var. If not set, the endpoint is disabled.
// Returns top 20 with nickname, score, wallet and IPs (to review multi-account
// clusters BEFORE paying).
app.get('/admin/winners', async (req, reply) => {
  const key = process.env.ADMIN_KEY;
  if (!key) return reply.code(503).send({ error: 'ADMIN_KEY not configured' });
  if (req.query?.key !== key) return reply.code(403).send({ error: 'Forbidden' });
  const r = await pool.query(
    `SELECT p.nickname, p.email, p.wallet, p.reg_ip, p.last_ip, p.created_at, s.score, s.updated_at AS last_save
       FROM saves s JOIN players p ON p.id = s.player_id
      WHERE p.nickname IS NOT NULL
      ORDER BY s.score DESC, s.updated_at ASC
      LIMIT 20`
  );
  return { ok: true, winners: r.rows.map((x,i)=>({ rank:i+1, ...x })) };
});

// ---- Middleware: figure out WHO is requesting (by the badge) ---------------
async function requirePlayer(req, reply) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) { reply.code(401).send({ error: 'Not authenticated (please log in)' }); return null; }
  // Sessions expire after 30 days (stale/stolen tokens do not live forever).
  const r = await pool.query(
    "SELECT player_id, (created_at < now() - interval '30 days') AS expired FROM sessions WHERE token=$1", [token]);
  if (r.rowCount === 0) { reply.code(401).send({ error: 'Invalid session (please log in)' }); return null; }
  if (r.rows[0].expired) {
    await pool.query('DELETE FROM sessions WHERE token=$1', [token]);
    reply.code(401).send({ error: 'Session expired (please log in again)' }); return null;
  }
  return r.rows[0].player_id;
}

// ---- LOGOUT -----------------------------------------------------------------
// Invalidates the session server-side (the badge stops working everywhere).
app.post('/logout', async (req, reply) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) await pool.query('DELETE FROM sessions WHERE token=$1', [token]);
  return { ok: true };
});

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

  // Server-side score: recomputed from the sets, never trusted from the client.
  const score = computeScore(save);
  _lbCacheTs = 0; // a new score may change the ranking -> drop the leaderboard cache

  await pool.query(
    `INSERT INTO saves (player_id, save_json, version, score, updated_at)
     VALUES ($1,$2,$3,$4, now())
     ON CONFLICT (player_id) DO UPDATE SET save_json=$2, version=$3, score=$4, updated_at=now()`,
    [playerId, save, save.v || null, score]
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

// ---- SET NICKNAME -----------------------------------------------------------
// The public name shown on the leaderboard. 3-16 chars, letters/numbers/underscore.
// Unique (case-insensitive) - same race-safe pattern as email (UNIQUE index + catch).
const _nickRate = new Map(); // playerId -> last change ts (light in-memory rate limit)
app.post('/nickname', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const nick = String(req.body?.nickname || '').trim();
  if (!/^[A-Za-z0-9_]{3,16}$/.test(nick)) {
    return reply.code(400).send({ error: 'Nickname must be 3-16 chars: letters, numbers, underscore' });
  }
  const last = _nickRate.get(playerId) || 0;
  if (Date.now() - last < 60_000) {
    return reply.code(429).send({ error: 'Please wait a minute before changing nickname again' });
  }
  try {
    await pool.query('UPDATE players SET nickname=$1 WHERE id=$2', [nick, playerId]);
    _nickRate.set(playerId, Date.now());
    return { ok: true, nickname: nick };
  } catch (e) {
    if (e.code === '23505') return reply.code(409).send({ error: 'Nickname already taken' });
    throw e;
  }
});

// ---- LEADERBOARD ------------------------------------------------------------
// Top 20 by server-computed score + the requester's own position (if logged in).
// Only players who set a nickname appear. Cached 10s to protect the database.
app.get('/leaderboard', async (req, reply) => {
  const now = Date.now();
  if (!_lbCache || now - _lbCacheTs > 10_000) {
    const top = await pool.query(
      `SELECT p.nickname, s.score
         FROM saves s JOIN players p ON p.id = s.player_id
        WHERE p.nickname IS NOT NULL
        ORDER BY s.score DESC, s.updated_at ASC
        LIMIT 20`
    );
    const tot = await pool.query(
      `SELECT COUNT(*)::int AS n FROM saves s JOIN players p ON p.id = s.player_id WHERE p.nickname IS NOT NULL`
    );
    _lbCache = { top: top.rows.map((r, i) => ({ rank: i + 1, nickname: r.nickname, score: r.score })), total: tot.rows[0].n };
    _lbCacheTs = now;
  }
  const out = { ok: true, top: _lbCache.top, total: _lbCache.total };

  // "me": optional - resolved per request (not cached), via Bearer token
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) {
    const sess = await pool.query('SELECT player_id FROM sessions WHERE token=$1', [token]);
    if (sess.rowCount > 0) {
      const pid = sess.rows[0].player_id;
      const me = await pool.query(
        `SELECT p.nickname, s.score,
                (SELECT COUNT(*)::int + 1 FROM saves s2 JOIN players p2 ON p2.id=s2.player_id
                  WHERE p2.nickname IS NOT NULL AND s2.score > s.score) AS rank
           FROM players p LEFT JOIN saves s ON s.player_id = p.id
          WHERE p.id = $1`, [pid]
      );
      if (me.rowCount > 0) {
        out.me = { nickname: me.rows[0].nickname, score: me.rows[0].score || 0,
                   rank: me.rows[0].nickname ? me.rows[0].rank : null };
      }
    }
  }
  return out;
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
