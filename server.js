'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');

// Banco PostgreSQL opcional para preservar CDP e cooldowns após reinícios do Render.
// Sem DATABASE_URL, o site usa um arquivo local (que pode ser apagado em hospedagens gratuitas).
const DatabasePool = process.env.DATABASE_URL ? require('pg').Pool : null;
const statePool = DatabasePool
  ? new DatabasePool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === 'disable' ? false : { rejectUnauthorized: false }
    })
  : null;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '3mb' }));
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
const promotionHistory = [];
const proofFiles = new Map();
const promotionCooldowns = new Map();
const promotionLocks = new Set();
const cdpRecords = new Map();
const PROMOTION_COOLDOWN_MS = 30 * 60 * 1000;
// Configure um Persistent Disk no Render em /var/data e a variável EB_DATA_DIR=/var/data.
// Sem disco persistente, o arquivo funciona no processo atual, mas o Render pode apagá-lo em novas implantações.
const DATA_DIR = process.env.EB_DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'eb-manager-state.json');
const PROOF_DIR = path.join(DATA_DIR, 'proofs');
let persistenceChain = Promise.resolve();
let databaseTableReady = false;

async function ensureDatabaseStateTable() {
  if (!statePool || databaseTableReady) return;
  await statePool.query(`CREATE TABLE IF NOT EXISTS eb_manager_state (
    state_key TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  databaseTableReady = true;
}

function promotionAccess(req, res, needApiKey = true) {
  const user = sessionUser(req);
  if (!user) {
    jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
    return null;
  }
  if (needApiKey && !ROBLOX_API_KEY) {
    jsonError(res, 503, 'A integração do Roblox ainda não está configurada. Adicione ROBLOX_API_KEY nas variáveis do Render.');
    return null;
  }
  return user;
}

async function promotionAccessWithRank(req, res, needApiKey = true) {
  const user = promotionAccess(req, res, needApiKey);
  if (!user) return null;
  try {
    const roles = await fetchGroupRoles();
    const membership = await findMembership(user.sub);
    const authorizedRole = membership ? authorizedPromotionRole(roles, membership) : null;
    const actorRole = authorizedRole || (membership ? highestMembershipRole(roles, membership) : null);
    if (!membership || !authorizedRole) {
      jsonError(res, 403, 'A área de patentes está disponível somente para cargos entre [ASP] Aspirante a Oficial e [CR] Criador.');
      return null;
    }
    return { ...user, groupRole: actorRole, isCreatorAdmin: String(authorizedRole.id) === '844132065' };
  } catch (e) {
    console.error('promotionAccessWithRank:', e.status || '', e.message);
    jsonError(res, 502, 'Não foi possível verificar sua patente no grupo Roblox. Tente novamente.');
    return null;
  }
}

function normalizeRoleName(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[ºª°]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function cooldownRemaining(userId) {
  const until = Number(promotionCooldowns.get(String(userId)) || 0);
  return Math.max(0, until - Date.now());
}

function cooldownMessage(remainingMs) {
  return `Você já promoveu recentemente. Aguarde ${formatDuration(remainingMs)} para promover novamente. O intervalo é individual para cada promotor.`;
}

function formatDuration(milliseconds) {
  const ms = Math.max(0, Number(milliseconds) || 0);
  const totalMinutes = Math.ceil(ms / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes || !parts.length) parts.push(`${minutes}min`);
  return parts.join(' ');
}

function beginPromotionOperation(userId, res) {
  const key = String(userId);
  const remaining = cooldownRemaining(key);
  if (remaining > 0) {
    jsonError(res, 429, cooldownMessage(remaining));
    return false;
  }
  if (promotionLocks.has(key)) {
    jsonError(res, 409, 'Uma operação de promoção sua já está em andamento. Aguarde o resultado antes de tentar novamente.');
    return false;
  }
  promotionLocks.add(key);
  return true;
}

function endPromotionOperation(userId) {
  promotionLocks.delete(String(userId));
}

function cdpDurationMs(role, roles) {
  const name = normalizeRoleName(role?.name);
  const hour = 60 * 60 * 1000;

  // Tabela oficial da CDP do site: progressão de 3 horas por patente.
  // Os códigos e nomes alternativos são aceitos porque o nome do cargo no Roblox pode variar.
  const rules = [
    [/\brecruta\b|\brec\b/, 3],
    [/\bsoldado\b|\bsld\b/, 6],
    [/\bcabo\b|\bcb\b/, 9],
    [/\b(?:3|terceiro)\s*(?:sgt|sargento)\b/, 12],
    [/\b(?:2|segundo)\s*(?:sgt|sargento)\b/, 15],
    [/\b(?:1|primeiro)\s*(?:sgt|sargento)\b/, 18],
    [/\bsubtenente\b|\bst\b/, 21],
    [/\bcadete\b|\bct\b/, 24],
    [/\baspirante(?: a oficial)?\b|\basp\b/, 27],
    [/\b(?:2|segundo)\s*(?:ten|tenente)\b/, 30],
    [/\b(?:1|primeiro)\s*(?:ten|tenente)\b/, 33],
    [/\bcapitao\b|\bcap\b/, 36],
    [/\bmajor\b|\bmaj\b/, 39],
    [/\btenente coronel\b|\bten cel\b/, 42],
    [/\bcoronel\b|\bcel\b/, 45],
    [/\bgeneral de brigada\b|\bgen bda\b/, 48],
    [/\bgeneral de divisao\b|\bgen dv\b/, 51],
    [/\bgeneral de exercito\b|\bgen ex\b/, 54],
    [/\belite militar\b|\bem\b/, 57],
    [/\belite real\b|\belite secreta\b|\ber\b|\bes\b/, 60],
    [/\bsubcomandante\b|\bscmt\b/, 63],
    [/^comandante$|\bcmt\b/, 66]
  ];

  for (const [pattern, hours] of rules) {
    if (pattern.test(name)) return hours * hour;
  }

  // Cargo sem correspondência na tabela: usa 3 horas como padrão conservador.
  // Ajuste o nome do cargo no Roblox para um dos nomes/códigos oficiais acima.
  return 3 * hour;
}

function buildCdpStatus(record, roles) {
  const role = { id: record.roleId, name: record.roleName, order: record.roleOrder };
  const requiredMs = cdpDurationMs(role, roles || []);
  const startedAt = Number(record.startedAt) || Date.now();
  const eligibleAt = startedAt + requiredMs;
  const remainingMs = Math.max(0, eligibleAt - Date.now());
  return {
    roleName: record.roleName,
    requiredMs,
    requiredHours: requiredMs / 3600000,
    startedAt,
    eligibleAt,
    remainingMs,
    remainingLabel: formatDuration(remainingMs),
    eligible: remainingMs <= 0,
    trackedBy: 'site'
  };
}

function ensureCdpRecord(userId, username, currentRole, roles) {
  const key = String(userId);
  const roleId = String(currentRole.id);
  let record = cdpRecords.get(key);
  let changed = false;

  // Se ainda não havia histórico, a contagem começa na primeira consulta no site.
  // Se a patente mudou fora deste site, o site não conhece a data antiga; inicia um novo prazo observado.
  if (!record || String(record.roleId) !== roleId) {
    record = {
      userId: key,
      username,
      roleId,
      roleName: currentRole.name,
      roleOrder: Number(currentRole.order),
      startedAt: Date.now()
    };
    cdpRecords.set(key, record);
    changed = true;
  } else {
    record.username = username;
    record.roleName = currentRole.name;
    record.roleOrder = Number(currentRole.order);
  }

  return { changed, record, status: buildCdpStatus(record, roles) };
}

async function savePersistentState() {
  const snapshot = {
    version: 1,
    savedAt: new Date().toISOString(),
    promotionHistory: promotionHistory.slice(0, 100),
    promotionCooldowns: [...promotionCooldowns.entries()],
    cdpRecords: [...cdpRecords.entries()],
    proofFiles: [...proofFiles.entries()].map(([id, proof]) => ({ id, filePath: proof.filePath, mimeType: proof.mimeType }))
  };

  const write = persistenceChain.then(async () => {
    if (statePool) {
      await ensureDatabaseStateTable();
      await statePool.query(
        `INSERT INTO eb_manager_state (state_key, payload, updated_at)
         VALUES ('main', $1::jsonb, NOW())
         ON CONFLICT (state_key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
        [JSON.stringify(snapshot)]
      );
      return;
    }

    await fs.mkdir(DATA_DIR, { recursive: true });
    const tempFile = `${STATE_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    await fs.writeFile(tempFile, JSON.stringify(snapshot, null, 2), { encoding: 'utf8', mode: 0o600 });
    await fs.rename(tempFile, STATE_FILE);
  });

  persistenceChain = write.catch(error => {
    console.error('Não foi possível persistir o estado do EB Manager:', error.message);
  });
  await write;
}

async function loadPersistentState() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(PROOF_DIR, { recursive: true });

  let saved;
  if (statePool) {
    await ensureDatabaseStateTable();
    const result = await statePool.query(
      `SELECT payload FROM eb_manager_state WHERE state_key = 'main' LIMIT 1`
    );
    saved = result.rows[0]?.payload || null;
  } else {
    try {
      saved = JSON.parse(await fs.readFile(STATE_FILE, 'utf8'));
    } catch (e) {
      if (e.code !== 'ENOENT') console.error('O arquivo de estado não pôde ser lido; um estado novo será iniciado:', e.message);
      return;
    }
  }

  if (typeof saved === 'string') {
    try { saved = JSON.parse(saved); } catch { saved = null; }
  }
  if (!saved || typeof saved !== 'object') return;
  if (Array.isArray(saved.promotionHistory)) promotionHistory.push(...saved.promotionHistory.slice(0, 100));
  if (Array.isArray(saved.promotionCooldowns)) {
    for (const entry of saved.promotionCooldowns) {
      if (Array.isArray(entry) && /^\d+$/.test(String(entry[0])) && Number(entry[1]) > Date.now()) {
        promotionCooldowns.set(String(entry[0]), Number(entry[1]));
      }
    }
  }
  if (Array.isArray(saved.cdpRecords)) {
    for (const entry of saved.cdpRecords) {
      if (Array.isArray(entry) && /^\d+$/.test(String(entry[0])) && entry[1] && /^\d+$/.test(String(entry[1].roleId)) && Number(entry[1].startedAt) > 0) {
        cdpRecords.set(String(entry[0]), entry[1]);
      }
    }
  }
  if (Array.isArray(saved.proofFiles)) {
    const proofRoot = path.resolve(PROOF_DIR) + path.sep;
    for (const item of saved.proofFiles) {
      if (!item || !/^[a-f0-9]{24}$/.test(String(item.id)) || !['image/jpeg', 'image/png', 'image/webp'].includes(item.mimeType)) continue;
      const filePath = path.resolve(String(item.filePath || ''));
      if (!filePath.startsWith(proofRoot)) continue;
      try {
        await fs.access(filePath);
        proofFiles.set(item.id, { filePath, mimeType: item.mimeType });
      } catch { /* Evidência removida do disco: não carregar link quebrado. */ }
    }
  }
  console.log(`Estado carregado (${statePool ? 'PostgreSQL' : 'arquivo local'}): ${promotionHistory.length} histórico(s), ${promotionCooldowns.size} CDP(s) de promotor e ${cdpRecords.size} CDP(s) de militar.`);
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

async function fetchGroupRoles(groupId = GROUP_ID) {
  if (!ROBLOX_API_KEY) throw new Error('ROBLOX_API_KEY não está configurada para consultar as funções Open Cloud.');

  // Use the same Open Cloud role IDs that assignRole/unassignRole expect.
  // For unified groups, the legacy groups.roblox.com endpoint can expose old/different IDs.
  const allRoles = [];
  let pageToken = '';
  let pages = 0;
  do {
    const params = new URLSearchParams({ maxPageSize: '100' });
    if (pageToken) params.set('pageToken', pageToken);
    const response = await fetch(`https://apis.roblox.com/cloud/v2/groups/${groupId}/roles?${params}`, {
      headers: { accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
      signal: AbortSignal.timeout(10000)
    });
    const data = await readJsonResponse(response);
    const pageRoles = Array.isArray(data.groupRoles) ? data.groupRoles : (Array.isArray(data.roles) ? data.roles : []);
    if (!pageRoles.length && pages === 0) {
      throw new Error('A API Open Cloud não retornou funções para o grupo. Verifique group:read/group:write e o grupo autorizado na API Key.');
    }
    allRoles.push(...pageRoles);
    pageToken = typeof data.nextPageToken === 'string' ? data.nextPageToken : '';
    pages++;
    if (pages >= 20 && pageToken) throw new Error('A lista de funções excedeu o limite de páginas esperado.');
  } while (pageToken);

  return allRoles.map((r, order) => {
    const id = r.id != null ? String(r.id) : parseRoleId(r.path);
    return {
      id,
      name: String(r.displayName || r.name || `Patente ${r.rank ?? ''}`),
      rank: Number(r.rank ?? 0),
      order,
      memberCount: Number(r.memberCount ?? 0)
    };
  }).filter(r => /^\d+$/.test(r.id));
}

async function findMembership(userId, groupId = GROUP_ID) {
  const filter = `user == 'users/${userId}'`;
  const query = new URLSearchParams({ maxPageSize: '1', filter });
  const response = await fetch(`https://apis.roblox.com/cloud/v2/groups/${groupId}/memberships?${query}`, {
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
// Cargos autorizados para a aba Treinamentos / promoções do grupo principal.
// A lista usa os IDs de função Open Cloud fornecidos pelo proprietário do grupo.
// O intervalo permitido vai de [ASP] Aspirante a Oficial até [CR] Criador, inclusive.
const PROMOTION_AUTHORIZED_ROLE_IDS = new Set([
  '844150047', // [ASP] Aspirante a Oficial
  '844004101', // [2 TEN] Segundo Tenente
  '843780075', // [1 TEN] Primeiro Tenente
  '845208001', // [CAP] Capitão
  '843126091', // [MAJ] Major
  '845782001', // [TEN-CEL] Tenente Coronel
  '842292095', // [CEL] Coronel
  '843750090', // [GEN-BDA] General de Brigada
  '845856000', // [GEN-DIV] General de Divisão
  '842814077', // [GEN-EX] General do Exército
  '843044094', // [SCMT] Sub Comandante
  '842446075', // [CMT] Comandante
  '842498073', // [V-PRES] Vice Presidente
  '845218008', // [PRES] Presidente
  '845208002', // [SC] Sócios
  '843610097', // [EM] Elite Militar
  '845270007', // [ES] Elite Secreta
  '845586003', // [ER] Elite Real
  '849818027', // [CGEx] Corregedoria
  '842292096', // [MOD] Moderador
  '843414108', // [ADM] Administrador
  '843610099', // [ADM-G] Administrador geral
  '843780076', // [S-CR] Sub Criador
  '844132065'  // [CR] Criador
]);
function authorizedPromotionRole(roles, membership) {
  return roleIdsOf(membership)
    .filter(id => PROMOTION_AUTHORIZED_ROLE_IDS.has(String(id)))
    .map(id => rankForRole(roles, id))
    .filter(Boolean)[0] || null;
}

function rankForRole(roles, id) { return roles.find(r => String(r.id) === String(id)) || null; }
function nextHigherRole(roles, currentRole) {
  if (!currentRole) return null;
  // A ordenação da Open Cloud é de função mais alta para mais baixa; escolha a imediatamente anterior.
  return roles.filter(role => Number(role.order) < Number(currentRole.order)).sort((a, b) => b.order - a.order)[0] || null;
}
function highestMembershipRole(roles, membership) {
  // Desde a unificação das funções dos grupos, a hierarquia é a posição na lista,
  // não o número `rank`. Posição menor = função mais alta (mais autoridade).
  return roleIdsOf(membership)
    .map(id => rankForRole(roles, id))
    .filter(Boolean)
    .sort((a, b) => a.order - b.order)[0] || null;
}

app.get('/api/promotions/status', async (req, res) => {
  const user = sessionUser(req);
  if (!user) return jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
  let canManagePromotions = false, roleName = null, rankCheckError = '';
  if (ROBLOX_API_KEY) {
    try {
      const roles = await fetchGroupRoles();
      const membership = await findMembership(user.sub);
      const authorizedRole = membership ? authorizedPromotionRole(roles, membership) : null;
      const actorRole = authorizedRole || (membership ? highestMembershipRole(roles, membership) : null);
      canManagePromotions = Boolean(authorizedRole);
      roleName = (authorizedRole || actorRole)?.name || null;
    } catch (e) { rankCheckError = 'Não foi possível consultar a patente agora.'; console.error('promotions/status rank check:', e.status || '', e.message); }
  }
  const now = Date.now();
  const creatorAdmin = roleName && normalizeRoleName(roleName).includes('criador');
  return res.json({ ok: true, isAdmin: canManagePromotions, isConfiguredAdmin: false, creatorAdmin: Boolean(creatorAdmin), canManagePromotions, roleName, integrationConfigured: Boolean(ROBLOX_API_KEY), groupId: GROUP_ID, userId: String(user.sub), cooldownRemainingMs: cooldownRemaining(user.sub), cooldownUntil: Number(promotionCooldowns.get(String(user.sub)) || 0), serverTime: now, storageBackend: statePool ? 'postgresql' : 'arquivo local', persistentStorageConfigured: Boolean(statePool || process.env.EB_DATA_DIR), storageWarning: !statePool && !process.env.EB_DATA_DIR ? 'O armazenamento está no disco local. No Render Free, os arquivos somem quando o serviço reinicia ou adormece; configure DATABASE_URL para PostgreSQL persistente.' : '', setupMissing: [...(!ROBLOX_API_KEY ? ['ROBLOX_API_KEY'] : [])], rankCheckError });
});

app.get('/api/promotions/roles' , async (req, res) => {
  const actor = await promotionAccessWithRank(req, res, true);
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
  const actor = await promotionAccessWithRank(req, res, true);
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
    if (currentRole && normalizeRoleName(currentRole.name) === 'elite real') {
      return jsonError(res, 403, `@${target.name} está na Elite Real e não pode ser promovido.`);
    }
    if (!currentRole) {
      console.error('Membership response has no matching role reference:', JSON.stringify(membership).slice(0, 800));
      return jsonError(res, 502, 'A API encontrou o membro, mas não retornou uma patente reconhecida. A resposta pode usar um formato de função diferente; confira a API Key e os logs do Render.');
    }
    const cdp = ensureCdpRecord(target.id, target.name, currentRole, roles);
    if (cdp.changed) await savePersistentState();
    const nextRole = nextHigherRole(roles, currentRole);
    return res.json({ ok: true, member: { id: target.id, username: target.name, displayName: target.displayName, profileUrl: `https://www.roblox.com/users/${target.id}/profile`, currentRole: { id: currentRole.id, name: currentRole.name, rank: currentRole.rank, order: currentRole.order }, nextRole: nextRole ? { id: nextRole.id, name: nextRole.name, rank: nextRole.rank, order: nextRole.order } : null, cdp: cdp.status }, roles });
  } catch (e) {
    console.error('promotions/search:', e.status || '', e.message);
    if (e.status === 401 || e.status === 403) return jsonError(res, 502, 'A API Key do Roblox não tem permissão para consultar os membros. Confira no Render se a chave está correta e autorizada para o grupo.');
    if (e.status === 429) return jsonError(res, 429, 'O Roblox limitou as consultas. Aguarde um pouco e tente novamente.');
    return jsonError(res, 502, 'Não consegui consultar o membro no grupo Roblox. Confira a configuração da API Key e tente novamente.');
  }
});

app.post('/api/promotions/execute', async (req, res) => {
  const actor = await promotionAccessWithRank(req, res, true);
  if (!actor) return;

  const username = cleanUsername(req.body?.username);
  const targetRoleId = typeof req.body?.targetRoleId === 'string' || typeof req.body?.targetRoleId === 'number' ? String(req.body.targetRoleId) : '';
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 300) : '';
  if (!username) return jsonError(res, 400, 'Nome de usuário inválido. Pesquise o membro novamente.');
  if (!/^\d+$/.test(targetRoleId)) return jsonError(res, 400, 'Selecione uma patente válida.');
  if (reason.length < 3) return jsonError(res, 400, 'Informe o motivo da promoção (mínimo de 3 caracteres).');
  if (!beginPromotionOperation(actor.sub, res)) return;

  let promotionPhase = 'validar membro e patente';
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
    if (currentRole && normalizeRoleName(currentRole.name) === 'elite real') return jsonError(res, 403, `@${target.name} está na Elite Real e não pode ser promovido.`);
    const targetRole = rankForRole(roles, targetRoleId);
    if (!currentRole || !targetRole) return jsonError(res, 400, 'A patente atual ou a patente escolhida não foi encontrada no grupo. Atualize e pesquise novamente.');

    const cdp = ensureCdpRecord(target.id, target.name, currentRole, roles);
    if (cdp.changed) await savePersistentState();
    if (!cdp.status.eligible) {
      return jsonError(res, 403, `CDP do site ainda não concluído para @${target.name}. Tempo exigido na patente ${currentRole.name}: ${formatDuration(cdp.status.requiredMs)}. Faltam ${formatDuration(cdp.status.remainingMs)}; liberação em ${new Date(cdp.status.eligibleAt).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })}.`);
    }

    const expectedNextRole = nextHigherRole(roles, currentRole);
    if (!expectedNextRole) return jsonError(res, 400, `@${target.name} já está na patente mais alta do grupo; não existe promoção acima dela.`);
    if (targetRole.id !== expectedNextRole.id) return jsonError(res, 400, `Por segurança, só é permitida a próxima patente acima da atual (${currentRole.name} → ${expectedNextRole.name}). Pesquise novamente e tente outra vez.`);

    const url = `https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships/${encodeURIComponent(membershipId)}:assignRole`;
    promotionPhase = 'atribuir nova patente (assignRole)';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
      body: JSON.stringify({ role: `groups/${GROUP_ID}/roles/${targetRole.id}` }),
      signal: AbortSignal.timeout(12000)
    });
    const result = await readJsonResponse(response);

    let cleanupWarning = '';
    try {
      promotionPhase = 'remover patente anterior (unassignRole)';
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

    const now = Date.now();
    const entry = {
      id: crypto.randomBytes(5).toString('hex'), at: new Date(now).toISOString(),
      actorId: String(actor.sub), actorUsername: actor.username,
      targetId: String(target.id), targetUsername: target.name,
      fromRole: currentRole.name, toRole: targetRole.name, reason, cleanupWarning
    };
    promotionHistory.unshift(entry);
    if (promotionHistory.length > 100) promotionHistory.length = 100;
    promotionCooldowns.set(String(actor.sub), now + PROMOTION_COOLDOWN_MS);
    cdpRecords.set(String(target.id), {
      userId: String(target.id), username: target.name, roleId: String(targetRole.id),
      roleName: targetRole.name, roleOrder: Number(targetRole.order), startedAt: now
    });
    promotionPhase = 'salvar histórico, CDP e intervalo';
    let persistenceWarning = '';
    try { await savePersistentState(); }
    catch (saveError) {
      console.error('promotions/execute/save:', saveError.message);
      persistenceWarning = ' Atenção: não consegui salvar os dados. Confira a conexão DATABASE_URL do PostgreSQL no Render.';
    }

    return res.json({ ok: true, message: `Promoção aplicada no Roblox: @${target.name} agora está em ${targetRole.name}.${cleanupWarning} Você poderá promover novamente em 30 minutos.${persistenceWarning}`, promotion: entry, result, partial: Boolean(cleanupWarning), cooldownRemainingMs: PROMOTION_COOLDOWN_MS });
  } catch (e) {
    console.error(`promotions/execute [${promotionPhase}]:`, e.status || '', e.message);
    if (e.status === 401 || e.status === 403) return jsonError(res, 502, 'O Roblox recusou a promoção. Confira a API Key (permissão group:write), o grupo autorizado e se sua conta pode atribuir essa patente.');
    if (e.status === 404) return jsonError(res, 404, 'Membro ou patente não encontrado no grupo Roblox. Pesquise novamente.');
    if (e.status === 400) return jsonError(res, 400, 'O Roblox rejeitou a alteração (HTTP 400). Confira os Logs do Render.');
    if (e.status === 429) return jsonError(res, 429, 'O Roblox limitou as alterações. Aguarde antes de tentar novamente.');
    return jsonError(res, 502, 'Não foi possível concluir a promoção no Roblox. Confira a API Key e as permissões de grupo no Render.');
  } finally {
    endPromotionOperation(actor.sub);
  }
});

function parseEvidenceDataUrl(value) {
  if (typeof value !== 'string' || value.length > 2_100_000) throw new Error('A foto ficou muito grande. Escolha outra imagem menor.');
  const match = value.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
  if (!match) throw new Error('Envie uma foto nos formatos JPG, PNG ou WebP.');
  const buffer = Buffer.from(match[2], 'base64');
  if (!buffer.length || buffer.length > 1_500_000) throw new Error('A foto precisa ter até 1,5 MB depois da compressão.');
  const mimeType = `image/${match[1]}`;
  const validSignature = (mimeType === 'image/jpeg' && buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff)
    || (mimeType === 'image/png' && buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])))
    || (mimeType === 'image/webp' && buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP');
  if (!validSignature) throw new Error('O arquivo enviado não parece ser uma imagem válida. Selecione a foto novamente.');
  const extension = match[1] === 'jpeg' ? 'jpg' : match[1];
  return { buffer, mimeType, extension };
}
async function storePromotionEvidence(dataUrl) {
  const parsed = parseEvidenceDataUrl(dataUrl);
  await fs.mkdir(PROOF_DIR, { recursive: true });
  const id = crypto.randomBytes(12).toString('hex');
  const filePath = path.join(PROOF_DIR, `${id}.${parsed.extension}`);
  await fs.writeFile(filePath, parsed.buffer, { flag: 'wx' });
  proofFiles.set(id, { filePath, mimeType: parsed.mimeType });
  return { id, mimeType: parsed.mimeType };
}
function promotionErrorFor(e) {
  if (e.status === 401 || e.status === 403) return 'Roblox recusou a operação. Confira a API Key, o grupo autorizado e as permissões da conta que criou a chave.';
  if (e.status === 404) return 'Membro ou associação não encontrado no grupo. Confira o nome e tente novamente.';
  if (e.status === 400) return `Roblox rejeitou a operação (HTTP 400): ${e.message}`;
  if (e.status === 429) return 'Roblox limitou as operações temporariamente. Aguarde e tente novamente.';
  return e.message || 'Não foi possível concluir esta promoção.';
}

app.post('/api/promotions/execute-batch', async (req, res) => {
  const actor = await promotionAccessWithRank(req, res, true);
  if (!actor) return;

  const cooldown = cooldownRemaining(actor.sub);
  if (cooldown > 0) return jsonError(res, 429, cooldownMessage(cooldown));

  const rawNames = req.body?.usernames;
  if (!Array.isArray(rawNames) || rawNames.length < 1 || rawNames.length > 20) {
    return jsonError(res, 400, 'Adicione de 1 a 20 militares por lote.');
  }

  const usernames = [];
  const seenNames = new Set();
  for (const rawName of rawNames) {
    const username = cleanUsername(rawName);
    if (!username) return jsonError(res, 400, 'Um dos nomes de usuário é inválido. Remova-o da lista e tente novamente.');
    const key = username.toLowerCase();
    if (!seenNames.has(key)) { seenNames.add(key); usernames.push(username); }
  }

  const trainingType = req.body?.trainingType;
  if (!['Treinamento Básico', 'TAF'].includes(trainingType)) {
    return jsonError(res, 400, 'Selecione Treinamento Básico ou TAF.');
  }
  const note = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 200) : '';

  let evidence;
  try { evidence = await storePromotionEvidence(req.body?.evidenceDataUrl); }
  catch (e) { return jsonError(res, 400, e.message); }

  let roles;
  try { roles = await fetchGroupRoles(); }
  catch (e) {
    console.error('promotions/execute-batch roles:', e.status || '', e.message);
    return jsonError(res, 502, 'Não consegui carregar a hierarquia do grupo. Confira as permissões group:read/group:write da API Key.');
  }

  if (!beginPromotionOperation(actor.sub, res)) return;
  try {
    const results = [];

    for (const username of usernames) {
      let phase = 'localizar militar';
      try {
        const target = await robloxUserByUsername(username);
        if (!target) throw Object.assign(new Error('Não encontrei esse usuário no Roblox.'), { status: 404 });
        if (String(target.id) === String(actor.sub)) {
          results.push({ username, ok: false, error: 'Você não pode promover sua própria conta por este painel.' });
          continue;
        }

        phase = 'consultar associação e patente';
        const membership = await findMembership(target.id);
        if (!membership) {
          results.push({ username: target.name, id: target.id, ok: false, error: `@${target.name} não é membro do grupo ${GROUP_ID}.` });
          continue;
        }
        const membershipId = membershipIdOf(membership, target.id);
        if (!membershipId) throw new Error('A API do Roblox não retornou o identificador da associação.');

        const currentRole = highestMembershipRole(roles, membership);
        if (!currentRole) throw new Error('Não consegui identificar a patente atual desse militar.');
        if (normalizeRoleName(currentRole.name) === 'elite real') {
          results.push({ username: target.name, id: target.id, ok: false, currentRole: currentRole.name, error: `@${target.name} está na Elite Real e não pode ser promovido.` });
          continue;
        }

        const cdp = ensureCdpRecord(target.id, target.name, currentRole, roles);
        if (cdp.changed) await savePersistentState();
        if (!cdp.status.eligible) {
          results.push({
            username: target.name, id: target.id, ok: false,
            currentRole: currentRole.name,
            cdpRemainingMs: cdp.status.remainingMs,
            cdpEligibleAt: cdp.status.eligibleAt,
            error: `CDP do site: precisa permanecer ${formatDuration(cdp.status.requiredMs)} na patente ${currentRole.name}. Faltam ${formatDuration(cdp.status.remainingMs)}; liberação em ${new Date(cdp.status.eligibleAt).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })}.`
          });
          continue;
        }

        const targetRole = nextHigherRole(roles, currentRole);
        if (!targetRole) {
          results.push({ username: target.name, id: target.id, ok: false, currentRole: currentRole.name, error: `@${target.name} já está na patente mais alta do grupo.` });
          continue;
        }

        phase = 'atribuir próxima patente';
        const assignResponse = await fetch(`https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships/${encodeURIComponent(membershipId)}:assignRole`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
          body: JSON.stringify({ role: `groups/${GROUP_ID}/roles/${targetRole.id}` }),
          signal: AbortSignal.timeout(12000)
        });
        const assignResult = await readJsonResponse(assignResponse);

        let cleanupWarning = '';
        try {
          phase = 'remover patente anterior';
          const removeResponse = await fetch(`https://apis.roblox.com/cloud/v2/groups/${GROUP_ID}/memberships/${encodeURIComponent(membershipId)}:unassignRole`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY },
            body: JSON.stringify({ role: `groups/${GROUP_ID}/roles/${currentRole.id}` }),
            signal: AbortSignal.timeout(12000)
          });
          await readJsonResponse(removeResponse);
        } catch (removeError) {
          console.error('promotions/batch/unassign-old-role:', removeError.status || '', removeError.message);
          cleanupWarning = 'A nova patente foi atribuída, mas a patente anterior não pôde ser removida automaticamente.';
        }

        const now = Date.now();
        const auditReason = `${trainingType}${note ? ' — ' + note : ''}`.slice(0, 300);
        const entry = {
          id: crypto.randomBytes(5).toString('hex'), at: new Date(now).toISOString(),
          actorId: String(actor.sub), actorUsername: actor.username,
          targetId: String(target.id), targetUsername: target.name,
          fromRole: currentRole.name, toRole: targetRole.name,
          reason: auditReason, trainingType, evidenceId: evidence.id,
          evidenceUrl: `/api/promotions/evidence/${evidence.id}`, cleanupWarning
        };

        promotionHistory.unshift(entry);
        if (promotionHistory.length > 100) promotionHistory.length = 100;
        cdpRecords.set(String(target.id), {
          userId: String(target.id), username: target.name, roleId: String(targetRole.id),
          roleName: targetRole.name, roleOrder: Number(targetRole.order), startedAt: now
        });
        // Ative o intervalo assim que uma promoção for aplicada com sucesso.
        // Assim, se uma etapa posterior do lote falhar, o promotor ainda fica bloqueado.
        promotionCooldowns.set(String(actor.sub), now + PROMOTION_COOLDOWN_MS);
        results.push({ username: target.name, id: target.id, ok: true, fromRole: currentRole.name, toRole: targetRole.name, warning: cleanupWarning, evidenceUrl: entry.evidenceUrl, result: assignResult });
      } catch (e) {
        console.error(`promotions/execute-batch [@${username}; ${phase}]:`, e.status || '', e.message);
        results.push({ username, ok: false, error: promotionErrorFor(e), phase });
      }
    }

    const successful = results.filter(result => result.ok).length;
    const failed = results.length - successful;
    let persistenceWarning = '';
    if (successful > 0) {
      promotionCooldowns.set(String(actor.sub), Date.now() + PROMOTION_COOLDOWN_MS);
      try { await savePersistentState(); }
      catch (saveError) {
        console.error('promotions/execute-batch/save:', saveError.message);
        persistenceWarning = ' Atenção: não consegui salvar os prazos. Confira a conexão DATABASE_URL do PostgreSQL no Render.';
      }
    }

    return res.json({
      ok: true,
      message: `Lote concluído: ${successful} promoção(ões) aplicada(s) e ${failed} falha(s).${successful ? ' Você poderá promover novamente em 30 minutos.' : ''}${persistenceWarning}`,
      trainingType, evidenceUrl: `/api/promotions/evidence/${evidence.id}`, successful, failed, results,
      cooldownRemainingMs: successful ? PROMOTION_COOLDOWN_MS : cooldownRemaining(actor.sub)
    });
  } finally {
    endPromotionOperation(actor.sub);
  }
});

app.get('/api/promotions/evidence/:id', async (req, res) => {
  // Qualquer usuário autenticado pode consultar a foto de uma atividade; a alteração da patente continua protegida.
  const user = sessionUser(req);
  if (!user) return jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
  const id = String(req.params.id || '');
  if (!/^[a-f0-9]{24}$/.test(id)) return jsonError(res, 400, 'Identificador de evidência inválido.');
  const proof = proofFiles.get(id);
  if (!proof) return jsonError(res, 404, 'Esta foto não está mais disponível no armazenamento temporário do servidor.');
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.type(proof.mimeType);
  return res.sendFile(proof.filePath);
});

app.get('/api/promotions/history', async (req, res) => {
  // O histórico de treinamentos é para todos os usuários autenticados, sem lista de IDs administrativos.
  const user = sessionUser(req);
  if (!user) return jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
  const history = promotionHistory.slice(0, 20).map(entry => ({ ...entry, evidenceAvailable: Boolean(entry.evidenceId && proofFiles.has(entry.evidenceId)), evidenceUrl: entry.evidenceId && proofFiles.has(entry.evidenceId) ? `/api/promotions/evidence/${entry.evidenceId}` : '' }));
  return res.json({ ok: true, history });
});


const DEFAULT_DIVISION_GROUPS = [
  { key: 'bip', name: 'BIP — Brigada de Infantaria Paraquedista', groupId: '' },
  { key: 'bpe', name: 'BPE — Batalhão de Polícia do Exército', groupId: '226820203' },
  { key: 'bac', name: 'BAC — Batalhão de Ações de Comandos', groupId: '' },
  { key: 'b-op-psc', name: 'B Op Psc — Batalhão de Operações Psicológicas', groupId: '' },
  { key: 'bfesp', name: 'BFEsp — Batalhão de Forças Especiais', groupId: '' },
  { key: 'bdqbrn', name: 'BDQBRN — Batalhão de Defesa Química, Biológica, Radiológica e Nuclear', groupId: '' }
];
function normalizeDivisionKey(value) {
  return String(value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
}
function readDivisionGroups() {
  const defaults = DEFAULT_DIVISION_GROUPS;
  const raw = process.env.DIVISION_GROUPS;
  if (!raw) return defaults;
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('esperada uma lista JSON');
    const configured = parsed.map((item, index) => {
      const groupId = String(item?.groupId ?? item?.id ?? '').trim();
      const name = String(item?.name ?? item?.key ?? ('Divisão ' + (index + 1))).trim().slice(0, 100);
      const key = normalizeDivisionKey(item?.key ?? name);
      if (!key || (groupId && !/^\d+$/.test(groupId))) return null;
      return { key, name, groupId };
    }).filter(Boolean);
    const byKey = new Map(configured.map(item => [item.key, item]));
    const merged = defaults.map(item => {
      const override = byKey.get(item.key);
      if (!override) return item;
      byKey.delete(item.key);
      return { key: item.key, name: override.name || item.name, groupId: override.groupId || item.groupId };
    });
    // Preserva divisões extras cadastradas pelo dono, além das seis padrão.
    for (const item of byKey.values()) merged.push(item);
    return merged.slice(0, 20);
  } catch (error) {
    console.error('DIVISION_GROUPS inválida; usando a lista padrão de divisões:', error.message);
    return defaults;
  }
}
const DIVISION_GROUPS = readDivisionGroups();
function divisionByKey(key) { return DIVISION_GROUPS.find(item => item.key === String(key || '').toLowerCase()) || null; }
function roleIsAtOrAboveDivisionSubcommander(roles, actorRole) {
  if (!actorRole) return false;
  const threshold = roles.find(role => normalizeRoleName(role.name).replace(/[\s_-]/g, '').includes('subcomandante'));
  return Boolean(threshold && actorRole.order <= threshold.order);
}
async function divisionAccess(req, res, key) {
  const user = sessionUser(req); if (!user) { jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.'); return null; }
  if (!ROBLOX_API_KEY) { jsonError(res, 503, 'Adicione ROBLOX_API_KEY nas variáveis do Render.'); return null; }
  const division = divisionByKey(key); if (!division) { jsonError(res, 404, 'Esta divisão não está configurada no site.'); return null; }
  if (!division.groupId) { jsonError(res, 503, 'O ID do grupo Roblox da divisão ' + division.name + ' ainda não foi configurado em DIVISION_GROUPS no Render.'); return null; }
  try {
    const roles = await fetchGroupRoles(division.groupId); const membership = await findMembership(user.sub, division.groupId);
    const actorRole = membership ? highestMembershipRole(roles, membership) : null;
    if (!membership || !roleIsAtOrAboveDivisionSubcommander(roles, actorRole)) { jsonError(res, 403, 'Somente Subcomandante ou patente superior no grupo desta divisão pode gerenciar promoções.'); return null; }
    return { user, division, roles, membership, actorRole };
  } catch (error) { console.error('divisionAccess [' + division.key + ']:', error.status || '', error.message); jsonError(res, 502, 'Não foi possível conferir sua patente nesta divisão. Confira a API Key e as permissões do grupo no Render.'); return null; }
}
app.get('/api/divisions/status', async (req, res) => {
  const user = sessionUser(req); if (!user) return jsonError(res, 401, 'Sua sessão expirou. Entre novamente pelo Roblox.');
  if (!ROBLOX_API_KEY) return res.json({ ok: true, divisions: DIVISION_GROUPS.map(d => ({ key: d.key, name: d.name, groupId: d.groupId, canManage: false, roleName: null, error: d.groupId ? 'A integração do Roblox não está configurada.' : 'ID do grupo Roblox pendente: configure esta divisão em DIVISION_GROUPS no Render.' })) });
  const divisions = await Promise.all(DIVISION_GROUPS.map(async division => {
    if (!division.groupId) return { key: division.key, name: division.name, groupId: '', canManage: false, roleName: null, error: 'ID do grupo Roblox pendente: configure esta divisão em DIVISION_GROUPS no Render.' };
    try { const roles = await fetchGroupRoles(division.groupId); const membership = await findMembership(user.sub, division.groupId); const actorRole = membership ? highestMembershipRole(roles, membership) : null; return { key: division.key, name: division.name, groupId: division.groupId, canManage: roleIsAtOrAboveDivisionSubcommander(roles, actorRole), roleName: actorRole?.name || null, error: membership ? '' : 'Você não faz parte do grupo desta divisão.' }; }
    catch (error) { console.error('divisions/status [' + division.key + ']:', error.status || '', error.message); return { key: division.key, name: division.name, groupId: division.groupId, canManage: false, roleName: null, error: 'Não foi possível consultar esta divisão.' }; }
  })); return res.json({ ok: true, divisions });
});
app.get('/api/divisions/:key/roles', async (req, res) => { const access = await divisionAccess(req, res, req.params.key); if (!access) return; return res.json({ ok: true, division: access.division, actorRole: access.actorRole, roles: access.roles }); });
app.post('/api/divisions/:key/search', async (req, res) => {
  const access = await divisionAccess(req, res, req.params.key); if (!access) return;
  const username = cleanUsername(req.body?.username); if (!username) return jsonError(res, 400, 'Digite um nome de usuário Roblox válido.');
  try {
    const target = await robloxUserByUsername(username); if (!target) return jsonError(res, 404, 'Não encontrei esse usuário no Roblox.');
    const membership = await findMembership(target.id, access.division.groupId); if (!membership) return jsonError(res, 404, '@' + target.name + ' não faz parte do grupo ' + access.division.name + '.');
    const currentRole = highestMembershipRole(access.roles, membership); if (!currentRole) return jsonError(res, 502, 'Não consegui identificar a patente atual deste membro.');
    const allowedRoles = access.roles.filter(role => role.order > access.actorRole.order && role.order < currentRole.order).map(role => ({ id: role.id, name: role.name, rank: role.rank, order: role.order }));
    return res.json({ ok: true, division: access.division, member: { id: target.id, username: target.name, displayName: target.displayName, currentRole: { id: currentRole.id, name: currentRole.name, order: currentRole.order } }, allowedRoles });
  } catch (error) { console.error('divisions/search [' + access.division.key + ']:', error.status || '', error.message); return jsonError(res, 502, 'Não consegui consultar o militar nesta divisão. Confira a API Key no Render.'); }
});
app.post('/api/divisions/:key/promote', async (req, res) => {
  const access = await divisionAccess(req, res, req.params.key); if (!access) return;
  const username = cleanUsername(req.body?.username); const targetRoleId = String(req.body?.targetRoleId ?? ''); const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 200) : '';
  if (!username) return jsonError(res, 400, 'Nome de usuário inválido. Pesquise novamente o militar.'); if (!/^\d+$/.test(targetRoleId)) return jsonError(res, 400, 'Selecione uma patente válida da divisão.');
  if (!beginPromotionOperation(access.user.sub, res)) return; let phase = 'consultar militar';
  try {
    const target = await robloxUserByUsername(username); if (!target) return jsonError(res, 404, 'Não encontrei esse usuário no Roblox.');
    if (String(target.id) === String(access.user.sub)) return jsonError(res, 403, 'Você não pode promover sua própria conta.');
    const membership = await findMembership(target.id, access.division.groupId); if (!membership) return jsonError(res, 404, '@' + target.name + ' não faz parte do grupo desta divisão.');
    const membershipId = membershipIdOf(membership, target.id); if (!membershipId) return jsonError(res, 502, 'A API do Roblox não retornou a associação deste membro.');
    const currentRole = highestMembershipRole(access.roles, membership); const targetRole = rankForRole(access.roles, targetRoleId);
    if (!currentRole || !targetRole) return jsonError(res, 400, 'A patente atual ou escolhida não existe nesta divisão.');
    if (targetRole.order <= access.actorRole.order) return jsonError(res, 403, 'Você só pode promover para uma patente abaixo da sua própria hierarquia na divisão.');
    if (targetRole.order >= currentRole.order) return jsonError(res, 400, 'A patente escolhida precisa ser superior à patente atual do militar.');
    phase = 'atribuir patente da divisão'; const groupId = access.division.groupId;
    const assignResponse = await fetch('https://apis.roblox.com/cloud/v2/groups/' + groupId + '/memberships/' + encodeURIComponent(membershipId) + ':assignRole', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY }, body: JSON.stringify({ role: 'groups/' + groupId + '/roles/' + targetRole.id }), signal: AbortSignal.timeout(12000) });
    const result = await readJsonResponse(assignResponse); let cleanupWarning = '';
    try { const removeResponse = await fetch('https://apis.roblox.com/cloud/v2/groups/' + groupId + '/memberships/' + encodeURIComponent(membershipId) + ':unassignRole', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', 'x-api-key': ROBLOX_API_KEY }, body: JSON.stringify({ role: 'groups/' + groupId + '/roles/' + currentRole.id }), signal: AbortSignal.timeout(12000) }); await readJsonResponse(removeResponse); }
    catch (removeError) { console.error('divisions/promote/unassign-old-role:', removeError.status || '', removeError.message); cleanupWarning = ' A nova patente foi aplicada, mas a antiga não pôde ser removida automaticamente; confira os cargos do membro.'; }
    const now = Date.now(); const entry = { id: crypto.randomBytes(5).toString('hex'), at: new Date(now).toISOString(), actorId: String(access.user.sub), actorUsername: access.user.username, targetId: String(target.id), targetUsername: target.name, fromRole: currentRole.name, toRole: targetRole.name, reason: ('Promoção por divisão — ' + access.division.name + (reason ? ' — ' + reason : '')).slice(0, 300), divisionKey: access.division.key, divisionName: access.division.name, trainingType: 'Promoção por divisão', cleanupWarning };
    promotionHistory.unshift(entry); if (promotionHistory.length > 100) promotionHistory.length = 100; promotionCooldowns.set(String(access.user.sub), now + PROMOTION_COOLDOWN_MS);
    try { await savePersistentState(); } catch (saveError) { console.error('divisions/promote/save:', saveError.message); }
    return res.json({ ok: true, message: '@' + target.name + ' foi promovido de ' + currentRole.name + ' para ' + targetRole.name + ' na divisão ' + access.division.name + '.' + cleanupWarning + ' Você poderá promover novamente em 30 minutos.', promotion: entry, result, cooldownRemainingMs: PROMOTION_COOLDOWN_MS });
  } catch (error) { console.error('divisions/promote [' + access.division.key + '; ' + phase + ']:', error.status || '', error.message); if (error.status === 401 || error.status === 403) return jsonError(res, 502, 'O Roblox recusou a alteração. Confira as permissões group:write da API Key.'); if (error.status === 404) return jsonError(res, 404, 'Membro ou patente não encontrado na divisão.'); if (error.status === 429) return jsonError(res, 429, 'O Roblox limitou as alterações. Aguarde.'); return jsonError(res, 502, 'Não foi possível concluir a promoção na divisão. Confira os Logs do Render.'); }
  finally { endPromotionOperation(access.user.sub); }
});

// Remove expired challenges and old rate-limit buckets.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
  for (const [k, v] of attempts) if (v.until < now) attempts.delete(k);
}, 60_000).unref();

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

(async () => {
  try {
    await loadPersistentState();
    app.listen(PORT, '0.0.0.0', () => console.log(`EB Manager — Emerson rodando na porta ${PORT}; armazenamento: ${statePool ? 'PostgreSQL persistente' : DATA_DIR}`));
  } catch (error) {
    console.error('Falha ao preparar o armazenamento do EB Manager:', error.message);
    process.exitCode = 1;
  }
})();
