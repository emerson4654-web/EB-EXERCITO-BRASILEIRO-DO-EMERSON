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



// Gestão de patentes e promoções do grupo Roblox.
// A chave Open Cloud fica somente no servidor (variável do Render), nunca no navegador.
const ROBLOX_API_KEY = process.env.ROBLOX_API_KEY || '';
const GROUP_ID = /^\d+$/.test(process.env.ROBLOX_GROUP_ID || '') ? process.env.ROBLOX_GROUP_ID : '13616747';
const ADMIN_USER_IDS = new Set((process.env.ADMIN_USER_IDS || '').split(',').map(v => v.trim()).filter(v => /^\d+$/.test(v)));
const promotionHistory = [];

function promotionAccess(req, res, needApiKey = true) {
  const user = sessionUser(req);
  if (!user) { jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.'); return null; }
  if (ADMIN_USER_IDS.size === 0) {
    jsonError(res, 503, 'O acesso administrativo ainda não foi configurado. Adicione ADMIN_USER_IDS nas variáveis do Render.');
    return null;
  }
  if (!ADMIN_USER_IDS.has(String(user.sub))) {
    jsonError(res, 403, 'Sua conta Roblox não está autorizada a gerenciar patentes.');
    return null;
  }
  if (needApiKey && !ROBLOX_API_KEY) {
    jsonError(res, 503, 'A integração do Roblox ainda não está configurada. Adicione ROBLOX_API_KEY nas variáveis do Render.');
    return null;
  }
  return user;
}

async function readJsonResponse(response) {
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = {}; }
  if (!response.ok) {
    const apiMessage = data?.errors?.[0]?.message || data?.message;
    const e = new Error(apiMessage || `A API do Roblox respondeu com HTTP ${response.status}.`);
    e.status = response.status;
    throw e;
  }
  return data;
}

async function fetchGroupRoles() {
  const response = await fetch(`https://groups.roblox.com/v1/groups/${GROUP_ID}/roles`, {
    headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000)
  });
  const data = await readJsonResponse(response);
  const roles = Array.isArray(data.roles) ? data.roles : [];
  return roles.map((r, order) => ({ id: String(r.id), name: String(r.name || `Patente ${r.rank ?? ''}`), rank: Number(r.rank ?? 0), order, memberCount: Number(r.memberCount ?? 0) }));
}

async function findMembership(userId) {
  const filter = `user == 'users/${userId}'`;
  const query = new URLSearchParams({ maxPageSize: '1', filter });
  const response = await fetch(`https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships?${query}`, {
    headers: { accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
    signal: AbortSignal.timeout(10000)
  });
  const data = await readJsonResponse(response);
  const memberships = data.groupMemberships || data.memberships || [];
  return Array.isArray(memberships) ? memberships[0] || null : null;
}

function membershipIdOf(membership, fallbackUserId = '') {
  if (!membership || typeof membership !== 'object') return '';
  // Open Cloud returns the resource path (groups/{group}/memberships/{userId}) in path.
  const pathValue = typeof membership.path === 'string' ? membership.path : '';
  const match = pathValue.match(/\/memberships\/(\d+)$/);
  if (match) return match[1];
  for (const candidate of [membership.membershipId, membership.membership_id, membership.id]) {
    if (candidate != null && /^\d+$/.test(String(candidate))) return String(candidate);
    if (typeof candidate === 'string') {
      const m = candidate.match(/\/memberships\/(\d+)$/);
      if (m) return m[1];
    }
  }
  // Some responses only expose the user resource, whose ID is also the membership path ID.
  const userValue = typeof membership.user === 'string' ? membership.user : membership.user?.path;
  const userMatch = typeof userValue === 'string' ? userValue.match(/(?:^|\/)users\/(\d+)$/) : null;
  if (userMatch) return userMatch[1];
  return /^\d+$/.test(String(fallbackUserId)) ? String(fallbackUserId) : '';
}
function parseRoleId(value) {
  if (value == null) return '';
  if (typeof value === 'number' || typeof value === 'string') {
    const text = String(value);
    if (/^\d+$/.test(text)) return text;
    const match = text.match(/(?:^|\/)roles\/(\d+)$/);
    return match ? match[1] : '';
  }
  if (typeof value === 'object') {
    // Open Cloud resource references are normally strings, but tolerate object-shaped variants too.
    for (const candidate of [value.path, value.name, value.role, value.id, value.roleId, value.role_id]) {
      const id = parseRoleId(candidate);
      if (id) return id;
    }
  }
  return '';
}
function roleIdsOf(membership) {
  if (!membership || typeof membership !== 'object') return [];
  const values = [];
  // Older/single-role responses use `role`; multi-role responses can expose `roles`.
  if (membership.role != null) values.push(membership.role);
  if (Array.isArray(membership.roles)) values.push(...membership.roles);
  else if (membership.roles != null) values.push(membership.roles);
  for (const key of ['roleId', 'role_id', 'groupRole', 'group_role']) {
    if (membership[key] != null) values.push(membership[key]);
  }
  return [...new Set(values.map(parseRoleId).filter(Boolean))];
}
function rankForRole(roles, id) { return roles.find(r => String(r.id) === String(id)) || null; }
function highestMembershipRole(roles, membership) {
  // Desde a unificação das funções dos grupos, a hierarquia é a posição na lista,
  // não o número `rank`. Posição menor = função mais alta (mais autoridade).
  return roleIdsOf(membership)
    .map(id => rankForRole(roles, id))
    .filter(Boolean)
    .sort((a, b) => a.order - b.order)[0] || null;
}

app.get('/api/promotions/status', (req, res) => {
  const user = sessionUser(req);
  if (!user) return jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
  const admin = ADMIN_USER_IDS.has(String(user.sub));
  res.json({
    ok: true,
    isAdmin: admin,
    integrationConfigured: Boolean(ROBLOX_API_KEY),
    groupId: GROUP_ID,
    userId: String(user.sub),
    setupMissing: [
      ...(ADMIN_USER_IDS.size ? [] : ['ADMIN_USER_IDS']),
      ...(ROBLOX_API_KEY ? [] : ['ROBLOX_API_KEY'])
    ]
  });
});

app.get('/api/promotions/roles', async (req, res) => {
  const actor = promotionAccess(req, res, false);
  if (!actor) return;
  try {
    const roles = await fetchGroupRoles();
    res.json({ ok: true, groupId: GROUP_ID, roles });
  } catch (e) {
    console.error('promotions/roles:', e.message);
    return jsonError(res, 502, 'Não consegui carregar as patentes públicas do grupo Roblox agora.');
  }
});

app.post('/api/promotions/search', async (req, res) => {
  const actor = promotionAccess(req, res, true);
  if (!actor) return;
  const username = cleanUsername(req.body?.username);
  if (!username) return jsonError(res, 400, 'Digite um nome de usuário Roblox válido.');
  try {
    const target = await robloxUserByUsername(username);
    if (!target) return jsonError(res, 404, 'Não encontrei esse usuário no Roblox. Confira o nome.');
    const membership = await findMembership(target.id);
    if (!membership) return jsonError(res, 404, `@${target.name} não foi encontrado como membro do grupo ${GROUP_ID}.`);
    const membershipId = membershipIdOf(membership, target.id);
    if (!membershipId) {
      console.error('Membership response missing membership ID:', JSON.stringify(membership).slice(0, 500));
      return jsonError(res, 502, 'A API do Roblox encontrou o membro, mas não retornou o identificador da associação. Confira os logs do servidor.');
    }
    const roles = await fetchGroupRoles();
    const currentRole = highestMembershipRole(roles, membership);
    if (!currentRole) {
      console.error('Membership response has no matching role reference:', JSON.stringify(membership).slice(0, 800));
      return jsonError(res, 502, 'A API encontrou o membro, mas não retornou uma patente reconhecida. A resposta pode usar um formato de função diferente; confira a API Key e os logs do Render.');
    }
    return res.json({ ok: true, member: { id: target.id, username: target.name, displayName: target.displayName, profileUrl: `https://www.roblox.com/users/${target.id}/profile`, currentRole: { id: currentRole.id, name: currentRole.name, rank: currentRole.rank, order: currentRole.order } }, roles });
  } catch (e) {
    console.error('promotions/search:', e.status || '', e.message);
    if (e.status === 401 || e.status === 403) return jsonError(res, 502, 'A API Key do Roblox não tem permissão para consultar os membros. Confira no Render se a chave está correta e autorizada para o grupo.');
    if (e.status === 429) return jsonError(res, 429, 'O Roblox limitou as consultas. Aguarde um pouco e tente novamente.');
    return jsonError(res, 502, 'Não consegui consultar o membro no grupo Roblox. Confira a configuração da API Key e tente novamente.');
  }
});

app.post('/api/promotions/execute', async (req, res) => {
  const actor = promotionAccess(req, res, true);
  if (!actor) return;
  const username = cleanUsername(req.body?.username);
  const targetRoleId = typeof req.body?.targetRoleId === 'string' || typeof req.body?.targetRoleId === 'number' ? String(req.body.targetRoleId) : '';
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 300) : '';
  if (!username) return jsonError(res, 400, 'Nome de usuário inválido. Pesquise o membro novamente.');
  if (!/^\d+$/.test(targetRoleId)) return jsonError(res, 400, 'Selecione uma patente válida.');
  if (reason.length < 3) return jsonError(res, 400, 'Informe o motivo da promoção (mínimo de 3 caracteres).');
  try {
    const target = await robloxUserByUsername(username);
    if (!target) return jsonError(res, 404, 'Não encontrei esse usuário no Roblox.');
    if (String(target.id) === String(actor.sub)) return jsonError(res, 403, 'Você não pode alterar a própria patente por este painel.');
    const membership = await findMembership(target.id);
    if (!membership) return jsonError(res, 404, 'Esse usuário não está no grupo do Exército Brasileiro configurado no Render.');
    const membershipId = membershipIdOf(membership, target.id);
    if (!membershipId) return jsonError(res, 502, 'A API do Roblox não retornou o identificador da associação do membro.');
    const roles = await fetchGroupRoles();
    const currentRole = highestMembershipRole(roles, membership);
    const targetRole = rankForRole(roles, targetRoleId);
    if (!currentRole || !targetRole) return jsonError(res, 400, 'A patente atual ou a patente escolhida não foi encontrada no grupo. Atualize e pesquise novamente.');
    if (targetRole.order >= currentRole.order) return jsonError(res, 400, `Escolha uma patente acima da atual (${currentRole.name}). A hierarquia do Roblox é definida pela posição da função na lista, não pelo número rank.`);
    if (targetRole.id === currentRole.id) return jsonError(res, 400, 'O membro já possui essa patente.');

    const url = `https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships/${encodeURIComponent(membershipId)}:assignRole`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
      body: JSON.stringify({ role: `groups/${GROUP_ID}/roles/${targetRole.id}` }),
      signal: AbortSignal.timeout(12000)
    });
    const result = await readJsonResponse(response);
    // Em grupos com múltiplas funções, atribuir a nova patente não remove automaticamente a anterior.
    // Tentamos remover a antiga depois de aplicar a nova, para não deixar a promoção pela metade antes do assign.
    let cleanupWarning = '';
    if (currentRole.id !== targetRole.id) {
      try {
        const removeResponse = await fetch(`https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships/${encodeURIComponent(membershipId)}:unassignRole`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
          body: JSON.stringify({ role: `groups/${GROUP_ID}/roles/${currentRole.id}` }),
          signal: AbortSignal.timeout(12000)
        });
        await readJsonResponse(removeResponse);
      } catch (removeError) {
        console.error('promotions/unassign-old-role:', removeError.status || '', removeError.message);
        cleanupWarning = ' A nova patente foi atribuída, mas a patente anterior não pôde ser removida automaticamente; confira os cargos do membro no grupo.';
      }
    }
    const entry = {
      id: crypto.randomBytes(5).toString('hex'),
      at: new Date().toISOString(),
      actorId: String(actor.sub), actorUsername: actor.username,
      targetId: String(target.id), targetUsername: target.name,
      fromRole: currentRole.name, toRole: targetRole.name, reason, cleanupWarning
    };
    promotionHistory.unshift(entry);
    if (promotionHistory.length > 50) promotionHistory.length = 50;
    return res.json({ ok: true, message: `Promoção aplicada no Roblox: @${target.name} agora está em ${targetRole.name}.${cleanupWarning}`, promotion: entry, result, partial: Boolean(cleanupWarning) });
  } catch (e) {
    console.error('promotions/execute:', e.status || '', e.message);
    if (e.status === 401 || e.status === 403) return jsonError(res, 502, 'O Roblox recusou a promoção. Confira a API Key (permissão group:write), o grupo autorizado e se sua conta pode atribuir essa patente.');
    if (e.status === 404) return jsonError(res, 404, 'Membro ou patente não encontrado no grupo Roblox. Pesquise novamente.');
    if (e.status === 429) return jsonError(res, 429, 'O Roblox limitou as alterações. Aguarde antes de tentar novamente.');
    return jsonError(res, 502, 'Não foi possível concluir a promoção no Roblox. Confira a API Key e as permissões de grupo no Render.');
  }
});

app.get('/api/promotions/history', (req, res) => {
  const actor = promotionAccess(req, res, false);
  if (!actor) return;
  return res.json({ ok: true, history: promotionHistory.slice(0, 20) });
});


// Remove expired challenges and old rate-limit buckets.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
  for (const [k, v] of attempts) if (v.until < now) attempts.delete(k);
}, 60_000).unref();

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`EB Manager — Emerson rodando na porta ${PORT}`));
