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
import nacl from 'tweetnacl';

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
  // ---- S1 (anti-cheat) migration: suspicion flags counter (flag, don't ban) ----
  await pool.query(`ALTER TABLE saves ADD COLUMN IF NOT EXISTS flags INTEGER NOT NULL DEFAULT 0`);
  // ---- S2 (telemetry) migration: score history, ONE row per score CHANGE ------
  // Volume budget (free-tier aware, plan §6): score only changes when the player
  // earns a new milestone (~300 events per player LIFETIME). 500 players ≈ 150k
  // rows over months — fine for the free tier. client_score = what the client
  // *claimed*; big divergence from our recomputed score = console-edit signal.
  await pool.query(`CREATE TABLE IF NOT EXISTS score_events (
    id           BIGSERIAL PRIMARY KEY,
    player_id    BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    old_score    INTEGER NOT NULL,
    new_score    INTEGER NOT NULL,
    client_score INTEGER,
    gap          BOOLEAN NOT NULL DEFAULT FALSE
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS score_events_player_idx ON score_events(player_id, ts)`);
  // ---- Blockchain-prep migrations (idempotent) ----
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS wallet TEXT`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS players_wallet_uq ON players (wallet) WHERE wallet IS NOT NULL`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS reg_ip TEXT`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS last_ip TEXT`);
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ`);
  // ---- Wallet proof-of-ownership migrations (Phase 1 - PLANO_WALLET_CONNECT.md) ----
  await pool.query(`ALTER TABLE players ADD COLUMN IF NOT EXISTS wallet_verified BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`CREATE TABLE IF NOT EXISTS wallet_nonces (
    nonce      TEXT PRIMARY KEY,
    player_id  INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used       BOOLEAN NOT NULL DEFAULT FALSE
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_wallet_nonces_player ON wallet_nonces(player_id)`);
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

// Decode a base58 Solana address to its raw 32 bytes (for ed25519 verification).
// Returns a Uint8Array(32) or null if invalid. Mirrors isSolanaAddress's alphabet.
function base58Decode(str){
  if (typeof str !== 'string' || !str.length) return null;
  let n = 0n;
  for (const ch of str){
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  // big-endian bytes from the bigint
  const bytes = [];
  while (n > 0n){ bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  // restore leading zero bytes (each leading '1' = one 0x00)
  let zeros = 0; for (const ch of str){ if (ch === '1') zeros++; else break; }
  while (zeros-- > 0) bytes.unshift(0);
  if (bytes.length !== 32) return null;
  return Uint8Array.from(bytes);
}

// Canonical wallet-link message. The SERVER builds this; the client mirrors the
// EXACT same format. Phantom shows this text to the user before they sign.
// Human-readable + anti-phishing line ("does NOT move funds").
function walletLinkMessage(playerId, nonce){
  return (
    'Pokemon Task Bar - Link wallet\n' +
    'I am linking this wallet to my PTB account.\n' +
    'Account: #' + playerId + '\n' +
    'Nonce: ' + nonce + '\n' +
    'This request is free and does NOT move any funds.'
  );
}

// ---- Simple in-memory rate limiter (server is single-instance) --------------
const _rl = new Map(); // key -> [timestamps]
function rateLimit(playerId, key, max, windowMs){
  const k = key + ':' + playerId, now = Date.now();
  const arr = (_rl.get(k) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now); _rl.set(k, arr); return true;
}
// S0: periodic sweep so _rl doesn't grow forever (entries whose window fully
// expired are dropped). Cheap: runs every 10 min, single pass.
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of _rl) {
    const alive = arr.filter(t => now - t < 10 * 60_000);
    if (alive.length === 0) _rl.delete(k); else _rl.set(k, alive);
  }
}, 10 * 60_000).unref?.();
// S4.1 (audit, 500+ players): expired sessions (>30d) currently only die when
// someone tries to USE them — abandoned tokens linger forever. Daily sweep.
setInterval(() => {
  pool.query("DELETE FROM sessions WHERE created_at < now() - interval '30 days'")
    .catch(() => {}); // sweep failure is harmless; next day retries
}, 24 * 60 * 60_000).unref?.();

function stagePoints(gs){ return gs * 10; }
function actPoints(ai){ return (ai + 1) * 500; }

// Validates the sets and recomputes the score. Garbage in -> ignored.
// S1.2 (order rule): game progression is strictly linear — VERIFIED in the client
// (tier only advances after clearing act2/stage9; stage picker blocks unplayed
// stages with "Clear the previous stage first"). So a legitimate scoredStages is
// ALWAYS the contiguous prefix 1..N, and scoredActs the prefix 0..M. Anything
// after a gap is unearnable -> it simply doesn't count (and we flag the save).
// This kills the classic forge `scoredStages:[120]` (counts 0). Species have no
// known order map yet (S3.2) -> left as-is on purpose, per the plan.
//
// S3-LITE (physics gate, launch hardening): a stage takes a MINIMUM wall-clock
// time — derived from game CODE constants, not guesses: initial spawn is 1-2
// enemies, the rest trickle in 1 per 4-7s (scheduleTrickle), min wave = 5
// enemies => >=12s/wave; min waves/stage = 2 (WaveCountReduction floor) =>
// theoretical floor ~24s/stage. We enforce HALF of that (12s) as a player-
// favorable margin. The budget is the ACCOUNT AGE (players.created_at — a
// 100%% server-side, unforgeable clock) + a grace window (env) that covers
// guest-progress import on account creation. No account can hold more stages
// than its lifetime physically allows. Species get the same treatment with an
// ultra-conservative 1s/species floor. Excess NEVER destroys the save — it
// just doesn't count (capped) and raises a flag for admin review.
const MIN_STAGE_MS   = parseInt(process.env.MIN_STAGE_MS   || '12000', 10); // 12s/stage
const MIN_SPECIES_MS = parseInt(process.env.MIN_SPECIES_MS || '3000', 10);  // 3s/species (kill floor: trickle spawns 1 enemy per 4-7s)
const GRACE_MS       = parseInt(process.env.GRACE_MS       || '120000', 10); // 2min headroom
// NOTE on caps being self-healing: the budget is the ACCOUNT AGE, so a capped
// legitimate save (e.g. guest importing progress on account creation) counts
// MORE on every subsequent autosave as the account ages — full score appears
// on its own within minutes. Nothing is ever destroyed.

function computeScore(save, accountAgeMs){
  if(!save || typeof save !== 'object') return { score: 0, gap: false, capped: false };
  let total = 0;
  let gap = false;
  let capped = false;
  // physics budget from account age (server clock). If age unknown, no cap
  // (fail-open for score only; the caller always passes it for /save).
  const budget = (typeof accountAgeMs === 'number') ? accountAgeMs + GRACE_MS : Infinity;
  const maxStagesAllowed  = Math.min(120, Math.floor(budget / MIN_STAGE_MS));
  const maxSpeciesAllowed = Math.min(151, Math.floor(budget / MIN_SPECIES_MS));
  const species = Array.isArray(save.scoredSpecies) ? save.scoredSpecies : [];
  const stages  = Array.isArray(save.scoredStages)  ? save.scoredStages  : [];
  const acts    = Array.isArray(save.scoredActs)    ? save.scoredActs    : [];
  // species: unique ints 1..151, capped by physics budget
  const sp = new Set();
  for(const v of species){ if(Number.isInteger(v) && v>=1 && v<=151) sp.add(v); }
  if(sp.size > maxSpeciesAllowed) capped = true;
  let spCount = 0;
  for(const v of sp){ if(spCount >= maxSpeciesAllowed) break; total += speciesPoints(v); spCount++; }
  // stages: contiguous prefix from 1, capped by physics budget
  const st = new Set();
  for(const v of stages){ if(Number.isInteger(v) && v>=1 && v<=120) st.add(v); }
  let prefixLen = 0; // full contiguous prefix length (before physics cap)
  for(let gs=1; gs<=120; gs++){ if(!st.has(gs)) break; prefixLen = gs; }
  if(st.size > prefixLen) gap = true;
  let stageN = 0; // highest contiguous stage that COUNTED (after cap)
  for(let gs=1; gs<=prefixLen; gs++){
    if(gs > maxStagesAllowed){ capped = true; break; }
    total += stagePoints(gs);
    stageN = gs;
  }
  // acts: contiguous prefix from 0, and global act i is only clearable once
  // stage (i+1)*10 was cleared -> tie acts to the stage prefix that counted.
  const ac = new Set();
  for(const v of acts){ if(Number.isInteger(v) && v>=0 && v<=11) ac.add(v); }
  for(let ai=0; ai<=11; ai++){
    if(!ac.has(ai)){ if(ac.size > ai) gap = true; break; }
    if(stageN < (ai+1)*10){ capped = true; break; } // act i requires global stage (i+1)*10 cleared
    total += actPoints(ai);
  }
  return { score: total, gap, capped, excessStages: Math.max(0, prefixLen - stageN) };
}

// ---- Web server ------------------------------------------------------------
// S0.1: bodyLimit 256KB. Measured real save sizes (2026-07-09): fresh game ~2KB,
// absolute-endgame save (151 species, 120 stages, full stash, all runes) ~14KB.
// 256KB = ~18x headroom over the worst legitimate case, while cutting the
// 1MB default that would accept abusive payloads.
const app = Fastify({ logger: true, trustProxy: true, bodyLimit: 256 * 1024 });
// S0.3: CORS restricted to the game's origin(s). Comma-separated env var so
// G can add a custom domain / localhost for dev WITHOUT redeploying code.
// Fallback = production origin. `origin:true` (any site) was hole F4.
// HONESTY NOTE: CORS only stops *browsers on other sites* from reading our
// responses with the victim's cookies/session. It does NOT stop direct scripts
// (curl etc.) — that's what auth + rate limits are for. Don't oversell it.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://ptb-game.pages.dev')
  .split(',').map(s => s.trim()).filter(Boolean);
await app.register(cors, {
  origin: (origin, cb) => {
    // No Origin header = same-origin, curl, health checks, mobile webviews -> allow.
    if (!origin) return cb(null, true);
    cb(null, ALLOWED_ORIGINS.includes(origin));
  }
});

// Server health (to know if it's up)
app.get('/health', async () => ({ ok: true, ts: Date.now() }));

// ---- CREATE ACCOUNT --------------------------------------------------------
// The game sends { email, password }. The server creates the player.
app.post('/register', async (req, reply) => {
  // S4.2: per-IP limit — mass account creation is the cheapest attack against a
  // ranked game (bot accounts flooding the leaderboard). 10/hour per IP allows
  // shared IPs (NAT: family, campus) while adding friction to naive scripts.
  // AUDIT NOTE: forgeable via X-Forwarded-For (see /login note) -> friction, not
  // a wall. Real wall against bot accounts = S2 telemetry + admin review.
  if (!rateLimit(req.ip, 'register', 10, 60 * 60_000)) {
    return reply.code(429).send({ error: 'Too many accounts created, try later' });
  }
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
  // S4.2: two independent limits.
  // (a) per-IP: generous human ceiling. AUDIT NOTE: with trustProxy:true the
  //     client can forge X-Forwarded-For and rotate req.ip, so the IP limit is
  //     honest-friction only, not a hard wall. Changing trustProxy blindly risks
  //     collapsing all players into one IP (mass 429) if Render has >1 hop, so
  //     we keep it and add (b), which the attacker CANNOT forge:
  // (b) per-target-email: brute-force is against a specific account; 10 tries /
  //     15 min per email stops dictionaries cold regardless of source IP.
  if (!rateLimit(req.ip, 'login', 30, 15 * 60_000)) {
    return reply.code(429).send({ error: 'Too many login attempts, try later' });
  }
  const { email, password } = req.body || {};
  if (email && !rateLimit(String(email).toLowerCase().trim(), 'loginTarget', 10, 15 * 60_000)) {
    return reply.code(429).send({ error: 'Too many login attempts for this account, try later' });
  }
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
  // S4.1 (session rotation, multi-device-safe): keep only the 5 most recent
  // sessions per player. Old tokens die on re-login instead of lingering for
  // 30 days; phone + PC (2-3 devices) never get logged out by a new login.
  // Also stops the sessions table from growing forever (500+ player audit).
  try {
    await pool.query(
      `DELETE FROM sessions WHERE player_id=$1 AND token NOT IN (
         SELECT token FROM sessions WHERE player_id=$1 ORDER BY created_at DESC LIMIT 5)`,
      [p.id]
    );
  } catch (e) { req.log.warn({ err: e.message }, 'S4.1: session rotation failed (login still ok)'); }
  await pool.query('UPDATE players SET last_ip=$1, last_login=now() WHERE id=$2', [req.ip || null, p.id]);
  return { ok: true, token, playerId: p.id };
});

// ---- SET SOLANA WALLET --------------------------------------------------------
// One wallet per account (UNIQUE) - the same wallet cannot sit on two accounts.
// Prizes are paid manually by the admin to these wallets.
// NOTE: this is the MANUAL paste path -> stored as UNVERIFIED (no proof of ownership).
// The verified path is POST /wallet/verify (connect + signature).
app.post('/wallet', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const wallet = String(req.body?.wallet || '').trim();
  if (!isSolanaAddress(wallet)) {
    return reply.code(400).send({ error: 'Invalid Solana address' });
  }
  try {
    await pool.query('UPDATE players SET wallet=$1, wallet_verified=FALSE WHERE id=$2', [wallet, playerId]);
    return { ok: true, wallet, verified: false };
  } catch (e) {
    if (e.code === '23505') return reply.code(409).send({ error: 'This wallet is already linked to another account' });
    throw e;
  }
});

// ---- GET current wallet (so the UI can show what's linked) ------------------
app.get('/wallet', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const r = await pool.query('SELECT wallet, wallet_verified FROM players WHERE id=$1', [playerId]);
  return { ok: true, wallet: r.rows[0]?.wallet || null, verified: r.rows[0]?.wallet_verified || false };
});

// ---- WALLET PROOF-OF-OWNERSHIP (Phase 1) -----------------------------------
// Two-step connect+sign flow that proves the user CONTROLS the wallet, instead
// of just pasting an address. Step 1 issues a one-time nonce; step 2 verifies
// an ed25519 signature over a message the SERVER reconstructs (never trusts the
// client's message text). See PLANO_WALLET_CONNECT.md section 2.

// Step 1: issue a one-time nonce bound to this player.
app.post('/wallet/nonce', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  if (!rateLimit(playerId, 'wnonce', 5, 60_000)) {
    return reply.code(429).send({ error: 'Too many attempts, wait a minute' });
  }
  // opportunistic cleanup of stale nonces (no cron needed)
  await pool.query("DELETE FROM wallet_nonces WHERE created_at < now() - interval '1 hour'");
  // one live nonce per player: invalidate any previous
  await pool.query('DELETE FROM wallet_nonces WHERE player_id=$1', [playerId]);
  const nonce = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO wallet_nonces(nonce, player_id) VALUES ($1,$2)', [nonce, playerId]);
  // playerId returned so the client can build the exact canonical message
  return { ok: true, nonce, playerId };
});

// Step 2: verify the signature and link the wallet as VERIFIED.
app.post('/wallet/verify', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  if (!rateLimit(playerId, 'wverify', 5, 60_000)) {
    return reply.code(429).send({ error: 'Too many attempts, wait a minute' });
  }

  const wallet = String(req.body?.wallet || '').trim();
  const sigB64 = String(req.body?.signature || '').trim();
  const nonce  = String(req.body?.nonce || '').trim();

  // 1. address format (base58 -> exactly 32 bytes)
  if (!isSolanaAddress(wallet)) {
    return reply.code(400).send({ error: 'Invalid Solana address' });
  }
  // 2. nonce format (64 hex) and signature format (base64 of 64 bytes)
  if (!/^[0-9a-f]{64}$/.test(nonce)) {
    return reply.code(400).send({ error: 'Invalid nonce' });
  }
  let sig;
  try { sig = Buffer.from(sigB64, 'base64'); } catch (e) { sig = null; }
  if (!sig || sig.length !== 64) {
    return reply.code(400).send({ error: 'Invalid signature format' });
  }

  // 3. nonce must exist, belong to THIS player, be unused and unexpired.
  //    Burned atomically in the same statement (single-use even under a race).
  const nr = await pool.query(
    `UPDATE wallet_nonces SET used=TRUE
      WHERE nonce=$1 AND player_id=$2 AND used=FALSE
        AND created_at > now() - interval '5 minutes'
      RETURNING nonce`, [nonce, playerId]);
  if (nr.rowCount !== 1) {
    return reply.code(400).send({ error: 'Nonce expired or already used - try again' });
  }

  // 4. ed25519 verify. The message is RECONSTRUCTED here (never from the client).
  const msg = Buffer.from(walletLinkMessage(playerId, nonce), 'utf8');
  const pubkey = base58Decode(wallet);
  if (!pubkey) {
    return reply.code(400).send({ error: 'Invalid Solana address' });
  }
  const valid = nacl.sign.detached.verify(
    new Uint8Array(msg), new Uint8Array(sig), pubkey);
  if (!valid) {
    return reply.code(401).send({ error: 'Signature verification failed' });
  }

  // 5. store as VERIFIED (UNIQUE index still guards against reuse across accounts)
  try {
    await pool.query(
      'UPDATE players SET wallet=$1, wallet_verified=TRUE WHERE id=$2',
      [wallet, playerId]);
    return { ok: true, wallet, verified: true };
  } catch (e) {
    if (e.code === '23505') {
      return reply.code(409).send({ error: 'This wallet is already linked to another account' });
    }
    throw e;
  }
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
    `SELECT p.nickname, p.email, p.wallet, p.wallet_verified, p.reg_ip, p.last_ip, p.created_at, s.score, s.updated_at AS last_save
       FROM saves s JOIN players p ON p.id = s.player_id
      WHERE p.nickname IS NOT NULL
      ORDER BY s.score DESC, s.updated_at ASC
      LIMIT 20`
  );
  return { ok: true, winners: r.rows.map((x,i)=>({ rank:i+1, ...x })) };
});

// ---- S2.3: SUSPECT REVIEW (admin) -------------------------------------------
// Accounts with suspicion flags (S1 regressions/gaps) and recent client-vs-server
// score divergences (classic console-edit signal), for G's MANUAL review.
// Flags never auto-ban (plan philosophy); this endpoint is the human-review path.
app.get('/admin/suspects', async (req, reply) => {
  const key = process.env.ADMIN_KEY;
  if (!key) return reply.code(503).send({ error: 'ADMIN_KEY not configured' });
  if (req.query?.key !== key) return reply.code(403).send({ error: 'Forbidden' });
  const flagged = await pool.query(
    `SELECT p.id, p.nickname, p.email, p.reg_ip, p.last_ip, p.created_at,
            s.score, s.flags, s.updated_at AS last_save
       FROM saves s JOIN players p ON p.id = s.player_id
      WHERE s.flags > 0
      ORDER BY s.flags DESC, s.updated_at DESC
      LIMIT 50`
  );
  const diverging = await pool.query(
    `SELECT e.player_id, p.nickname, e.ts, e.new_score, e.client_score
       FROM score_events e JOIN players p ON p.id = e.player_id
      WHERE e.client_score IS NOT NULL
        AND (e.client_score - e.new_score > 1000 OR e.new_score - e.client_score > 1000)
      ORDER BY e.ts DESC
      LIMIT 50`
  );
  return { ok: true, flagged: flagged.rows, diverging: diverging.rows };
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
// S0.4: structural sanity check on the save. Philosophy: "flag, don't ban" —
// we only REJECT what is impossible for a legitimate client (forged/abusive),
// and never destroy the player's local save (client keeps playing on 4xx).
// Bounds are structural (array sizes), not gameplay judgments.
function saveShapeError(save){
  if (!save || typeof save !== 'object' || Array.isArray(save)) return 'not an object';
  // score sets: legitimate maxima are 151 species / 120 stages / 12 acts.
  // We allow slack (bugs may duplicate entries) but cut off the absurd.
  const cap = (arr, max, name) =>
    (arr !== undefined && (!Array.isArray(arr) || arr.length > max)) ? (name + ' invalid or > ' + max) : null;
  return cap(save.scoredSpecies, 1000, 'scoredSpecies')
      || cap(save.scoredStages,  1000, 'scoredStages')
      || cap(save.scoredActs,     100, 'scoredActs')
      || null;
}

app.post('/save', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  // S0.2: rate limit. Client autosaves every ~30s + on visibilitychange (tab
  // switches), so honest bursts happen; 30/min is far above any honest pattern
  // (~2-6/min) while stopping save-flood abuse.
  if (!rateLimit(playerId, 'save', 30, 60_000)) {
    return reply.code(429).send({ error: 'Too many saves, slow down' });
  }
  const save = req.body;
  if (!save || typeof save !== 'object') return reply.code(400).send({ error: 'Invalid save data' });
  // S0.4: reject structurally-forged saves (impossible for a real client).
  const shapeErr = saveShapeError(save);
  if (shapeErr) {
    req.log.warn({ playerId, shapeErr }, 'save rejected: bad shape');
    return reply.code(400).send({ error: 'Invalid save data' });
  }

  // Server-side score: recomputed from the sets, never trusted from the client.
  // S1.2: only the contiguous progression prefix counts (gap => forged tail ignored).
  // S3-LITE: capped by the account-age physics budget (see computeScore).
  const ageRow = await pool.query('SELECT created_at FROM players WHERE id=$1', [playerId]);
  const accountAgeMs = ageRow.rowCount
    ? Math.max(0, Date.now() - new Date(ageRow.rows[0].created_at).getTime())
    : 0;
  const { score: newScore, gap, capped, excessStages } = computeScore(save, accountAgeMs);

  // S1.1 (monotonicity): progress only moves forward. Fetch the currently stored
  // score; if the new one is LOWER, the save is still accepted (could be a local
  // restore) but the ranking score never goes down, and we count a flag.
  const prev = await pool.query('SELECT score, flags FROM saves WHERE player_id=$1', [playerId]);
  const oldScore = prev.rowCount ? (prev.rows[0].score || 0) : 0;
  let flags = prev.rowCount ? (prev.rows[0].flags || 0) : 0;
  if (gap) { flags++; req.log.warn({ playerId, newScore }, 'S1.2: progression gap in save (forged tail ignored)'); }
  // S3-lite flag: only when the excess is clearly forgery (>20 stages beyond the
  // physics budget). Small excess = honest guest import catching up (self-heals
  // as the account ages) — logging it every autosave would just flood the admin.
  if (capped && excessStages > 20) { flags++; req.log.warn({ playerId, excessStages, accountAgeMs }, 'S3-lite: progress far beyond physics budget (excess not counted)'); }
  if (newScore < oldScore) { flags++; req.log.warn({ playerId, oldScore, newScore }, 'S1.1: score regression (ranking kept at high-water mark)'); }
  let effScore = Math.max(newScore, oldScore); // high-water mark
  // FASE T (lock 2/2): dev-test saves (_cheated) never rank. Deliberately
  // bypasses the high-water mark: once a save is marked as test, its account
  // holds score 0 and leaves the leaderboard (which filters score > 0).
  if (save._cheated === true) effScore = 0;

  // Scale fix (audited for 500+ players): only drop the leaderboard cache when
  // the effective score actually CHANGED. Before, EVERY autosave nuked the cache,
  // turning the 10s cache useless under load (~17 saves/min at 500 players).
  if (effScore !== oldScore) {
    _lbCacheTs = 0;
    // S2.2 (telemetry): one history row per score CHANGE. Captures, never judges
    // — thresholds come later (S3) from THIS data, not from guesses.
    // client_score = what the client itself claims; divergence from our
    // recomputed number is the classic `G.score=999999` console-edit signal.
    const clientScore = Number.isInteger(save.score) ? save.score : null;
    try {
      await pool.query(
        `INSERT INTO score_events (player_id, old_score, new_score, client_score, gap)
         VALUES ($1,$2,$3,$4,$5)`,
        [playerId, oldScore, effScore, clientScore, gap]
      );
    } catch (e) {
      req.log.warn({ err: e.message }, 'S2: score_event insert failed (save still accepted)');
    }
  }

  await pool.query(
    `INSERT INTO saves (player_id, save_json, version, score, flags, updated_at)
     VALUES ($1,$2,$3,$4,$5, now())
     ON CONFLICT (player_id) DO UPDATE SET save_json=$2, version=$3, score=$4, flags=$5, updated_at=now()`,
    [playerId, save, save.v || null, effScore, flags]
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
        WHERE p.nickname IS NOT NULL AND s.score > 0
        ORDER BY s.score DESC, s.updated_at ASC
        LIMIT 20`
    );
    const tot = await pool.query(
      `SELECT COUNT(*)::int AS n FROM saves s JOIN players p ON p.id = s.player_id WHERE p.nickname IS NOT NULL AND s.score > 0`
    );
    _lbCache = { top: top.rows.map((r, i) => ({ rank: i + 1, nickname: r.nickname, score: r.score })), total: tot.rows[0].n };
    _lbCacheTs = now;
  }
  const out = { ok: true, top: _lbCache.top, total: _lbCache.total };

  // "me": optional - resolved per request (not cached), via Bearer token
  // Wrapped in try/catch: a failure computing "me" must NEVER take down the
  // whole leaderboard (top20 still answers; "me" is just omitted).
  try {
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
        // score 0 = out of the ranking (new players and _cheated test saves):
        // rank must be null, consistent with the top/total filters (score > 0).
        const meScore = me.rows[0].score || 0;
        out.me = { nickname: me.rows[0].nickname, score: meScore,
                   rank: (me.rows[0].nickname && meScore > 0) ? me.rows[0].rank : null };
      }
    }
  }
  } catch (e) {
    req.log.warn({ err: e.message }, 'leaderboard: "me" lookup failed (top20 still served)');
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
