# PTB Server — servidor mínimo (Fase 1, passo 2)

Servidor que tira o save do navegador e guarda no servidor. Faz SÓ isto:
criar conta, login, salvar save, carregar save. Ainda NÃO tem economia
recalculada, anti-trapaça, nem token — isso vem nos próximos passos do
PLANO_BACKEND_TOKEN.md.

## O que tem aqui
- `src/server.js` — o servidor (Fastify + Postgres).
- `package.json` — a lista de dependências.

## Como subir no Railway (passo a passo, sem programar)

1. Crie conta em https://railway.app (login com o seu GitHub).
2. No GitHub, crie um repositório **PRIVADO** (ex.: `ptb-server`) e suba
   estes arquivos nele (o Railway vai ler daí).
3. No Railway: **New Project → Deploy from GitHub repo →** escolha `ptb-server`.
4. No mesmo projeto: **New → Database → Add PostgreSQL** (1 clique).
   O Railway cria a variável `DATABASE_URL` automaticamente e o servidor a usa.
5. Pronto. O Railway te dá uma URL pública (ex.: `https://ptb-server-production.up.railway.app`).
   Teste abrindo `SUA_URL/health` no navegador — deve responder `{"ok":true,...}`.

## Endpoints (o que o jogo vai chamar)
- `POST /register`  body `{email, password}`  → cria conta
- `POST /login`     body `{email, password}`  → devolve `{token}` (o "crachá")
- `POST /save`      header `Authorization: Bearer TOKEN`, body = o save do jogo → grava
- `GET  /save`      header `Authorization: Bearer TOKEN` → devolve o save
- `GET  /health`    → diz se o servidor está de pé

## Rodar no seu PC (opcional, pra testar local)
Precisa de Node 18+ e um Postgres local. Depois:
```
npm install
DATABASE_URL="postgres://localhost/ptb" npm start
```
