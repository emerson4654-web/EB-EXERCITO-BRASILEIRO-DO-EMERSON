'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(__dirname, { extensions: ['html'], index: 'index.html' }));

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const CODE_TTL_MS = 10 * 60 * 1000;
const pending = new Map();
const attempts = new Map();
const COOKIE_NAME = 'ebm_session';

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('CONFIGURAÇÃO AUSENTE: defina SESSION_SECRET com pelo menos 32 caracteres nas variáveis do Render.');
  if (require.main === module) process.exit(1);
}

function jsonError(res, status, message) { return res.status(status).json({ ok: false, error: message }); }
function cleanUsername(value) {
  if (typeof value !== 'string') return '';
  const s = value.trim();
  return /^[A-Za-z0-9_]{3,20}$/.test(s) ? s : '';
}
function getRateKey(req) { return req.ip || req.socket.remoteAddress || 'unknown'; }
function rateLimit(req, res, next) {
  const key = getRateKey(req), now = Date.now();
  let item = attempts.get(key);
  if (!item || now > item.until) item = { count: 0, until: now + 60_000 };
  item.count++;
  attempts.set(key, item);
  if (item.count > 20) return jsonError(res, 429, 'Muitas tentativas. Aguarde um minuto e tente novamente.');
  next();
}
async function robloxUserByUsername(username) {
  const response = await fetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: true }),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error('Roblox não respondeu à consulta de usuário.');
  const data = await response.json();
  const user = Array.isArray(data.data) ? data.data[0] : null;
  if (!user) return null;
  return { id: user.id, name: user.name, displayName: user.displayName };
}
async function robloxProfile(userId) {
  const response = await fetch(`https://users.roblox.com/v1/users/${encodeURIComponent(userId)}`, {
    headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error('Não foi possível consultar a bio pública do Roblox.');
  return response.json();
}
function signSession(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const data = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function readSession(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const data = `${parts[0]}.${parts[1]}`;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest();
    const got = Buffer.from(parts[2], 'base64url');
    if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
function sessionUser(req) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim()).filter(Boolean).map(x => {
    const i = x.indexOf('='); return [x.slice(0, i), decodeURIComponent(x.slice(i + 1))];
  }));
  return readSession(cookies[COOKIE_NAME]);
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'EB Manager — Emerson', mode: 'roblox-bio-verification' }));

app.post('/api/auth/start', rateLimit, async (req, res) => {
  const username = cleanUsername(req.body?.username);
  if (!username) return jsonError(res, 400, 'Digite um nome de usuário Roblox válido (3 a 20 caracteres; letras, números e _).');
  try {
    const user = await robloxUserByUsername(username);
    if (!user) return jsonError(res, 404, 'Não encontrei esse usuário no Roblox. Confira o nome e tente novamente.');
    const code = `EBM-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    // One pending challenge per Roblox user; codes are short-lived and never treated as login until bio is checked.
    for (const [key, value] of pending) if (value.userId === user.id || value.expiresAt < Date.now()) pending.delete(key);
    pending.set(code, { userId: user.id, username: user.name, displayName: user.displayName, expiresAt: Date.now() + CODE_TTL_MS });
    return res.json({ ok: true, code, username: user.name, displayName: user.displayName, profileUrl: `https://www.roblox.com/users/${user.id}/profile`, expiresInSeconds: CODE_TTL_MS / 1000 });
  } catch (e) {
    console.error('auth/start:', e.message);
    return jsonError(res, 502, 'O Roblox está indisponível para consulta agora. Tente novamente em instantes.');
  }
});

app.post('/api/auth/verify', rateLimit, async (req, res) => {
  const code = typeof req.body?.code === 'string' ? req.body.code.trim().toUpperCase() : '';
  const challenge = pending.get(code);
  if (!challenge) return jsonError(res, 400, 'Código inválido ou inexistente. Gere um novo código.');
  if (challenge.expiresAt < Date.now()) { pending.delete(code); return jsonError(res, 400, 'O código expirou. Gere outro código.'); }
  try {
    const profile = await robloxProfile(challenge.userId);
    if (typeof profile.description !== 'string' || !profile.description.includes(code)) {
      return jsonError(res, 400, 'Ainda não encontrei o código na bio pública. Salve a bio no Roblox e tente novamente.');
    }
    pending.delete(code);
    const now = Math.floor(Date.now() / 1000);
    const token = signSession({ sub: String(challenge.userId), username: challenge.username, displayName: challenge.displayName, iat: now, exp: now + 8 * 60 * 60 });
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`);
    return res.json({ ok: true, user: { id: challenge.userId, username: challenge.username, displayName: challenge.displayName, profileUrl: `https://www.roblox.com/users/${challenge.userId}/profile` }, message: 'Perfil verificado com sucesso.' });
  } catch (e) {
    console.error('auth/verify:', e.message);
    return jsonError(res, 502, 'Não foi possível consultar o perfil Roblox agora. Tente novamente.');
  }
});

app.get('/api/auth/me', (req, res) => {
  const user = sessionUser(req);
  if (!user) return jsonError(res, 401, 'Você ainda não verificou seu perfil.');
  return res.json({ ok: true, user: { id: Number(user.sub), username: user.username, displayName: user.displayName } });
});
app.post('/api/auth/logout', (_req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  res.json({ ok: true });
});

// Remove expired challenges and old rate-limit buckets.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
  for (const [k, v] of attempts) if (v.until < now) attempts.delete(k);
}, 60_000).unref();

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`EB Manager — Emerson rodando na porta ${PORT}`));
