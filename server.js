// ============================================================================
// PTB SERVER - Servidor minimo (Fase 1, passo 2 do PLANO_BACKEND_TOKEN.md)
// ----------------------------------------------------------------------------
// O QUE ESTE SERVIDOR FAZ (e SO isto - de proposito, sem scope creep):
//   1. Cria conta de jogador (email + senha).
//   2. Login (devolve um "cracha" temporario = token de sessao).
//   3. Salva o save do jogo no servidor (por jogador).
//   4. Carrega o save do jogo do servidor.
//
// O QUE ELE AINDA NAO FAZ (vem nos proximos passos do plano):
//   - Recalcular economia (o "juiz") ....... passo 3 da Fase 1
//   - Anti-trapaca ......................... passo 4 da Fase 1
//   - Token / deposito / saque ............. Fases 3 e 4
//
// Este passo so prova que da pra TIRAR o save do navegador e guardar no servidor.
// ============================================================================

import Fastify from 'fastify';
import cors from '@fastify/cors';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

// ---- Conexao com o banco de dados Postgres ---------------------------------
// A URL do banco vem de uma "variavel de ambiente" (o Railway fornece isso
// automaticamente quando voce adiciona um Postgres ao projeto - 1 clique).
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway/Render usam SSL; local nao. Detecta automatico.
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

// ---- Criar as tabelas do banco na primeira vez que o servidor sobe ----------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id           BIGSERIAL PRIMARY KEY,
      email        TEXT UNIQUE NOT NULL,
      pass_hash    TEXT NOT NULL,        -- senha NUNCA guardada em texto puro
      pass_salt    TEXT NOT NULL,        -- "tempero" unico por jogador
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS saves (
      player_id    BIGINT PRIMARY KEY REFERENCES players(id) ON DELETE CASCADE,
      save_json    JSONB NOT NULL,       -- o save do jogo, do jeitinho que o jogo manda
      version      TEXT,
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token        TEXT PRIMARY KEY,     -- o "cracha" temporario do login
      player_id    BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// ---- Seguranca de senha: hash com salt (padrao, sem guardar senha pura) -----
function hashPassword(password, salt) {
  // scrypt: algoritmo lento de proposito, dificulta ataque de forca bruta.
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function newSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ---- Servidor web ----------------------------------------------------------
const app = Fastify({ logger: true });
await app.register(cors, { origin: true }); // permite o jogo (no navegador) falar com o servidor

// Saude do servidor (pra saber se esta de pe)
app.get('/health', async () => ({ ok: true, ts: Date.now() }));

// ---- CRIAR CONTA -----------------------------------------------------------
// O jogo manda { email, password }. O servidor cria o jogador.
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
// O jogo manda { email, password }. Se bater, devolve um "cracha" (token).
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

// ---- Middleware: descobrir QUEM esta pedindo (pelo cracha) ------------------
async function requirePlayer(req, reply) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) { reply.code(401).send({ error: 'Not authenticated (please log in)' }); return null; }
  const r = await pool.query('SELECT player_id FROM sessions WHERE token=$1', [token]);
  if (r.rowCount === 0) { reply.code(401).send({ error: 'Invalid session (please log in)' }); return null; }
  return r.rows[0].player_id;
}

// ---- SALVAR O SAVE ---------------------------------------------------------
// O jogo manda o save inteiro (o mesmo objeto que hoje vai pro localStorage).
// NOTA: neste passo o servidor CONFIA no save (so guarda). O "juiz" que
// valida os numeros vem no passo 3 - ainda nao e seguro contra trapaca, e
// esta certo assim: este passo so prova a fundacao (tirar o save do navegador).
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

// ---- CARREGAR O SAVE -------------------------------------------------------
app.get('/save', async (req, reply) => {
  const playerId = await requirePlayer(req, reply);
  if (!playerId) return;
  const r = await pool.query('SELECT save_json, updated_at FROM saves WHERE player_id=$1', [playerId]);
  if (r.rowCount === 0) return { ok: true, save: null }; // jogador novo, sem save ainda
  return { ok: true, save: r.rows[0].save_json, updatedAt: r.rows[0].updated_at };
});

// ---- Ligar o servidor ------------------------------------------------------
const PORT = process.env.PORT || 3000;
try {
  await initDb();
  await app.listen({ port: PORT, host: '0.0.0.0' });
  app.log.info(`PTB server minimo no ar na porta ${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
