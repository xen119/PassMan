const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const { nanoid } = require('nanoid');
const fs = require('fs');
const path = require('path');
const jwksClient = require('jwks-rsa');
const https = require('https');
const selfsigned = require('selfsigned');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-later-secret';
const DB_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DB_DIR, 'db.json');
const ENV_MS_CLIENT_ID = process.env.MS_CLIENT_ID;
const ENV_MS_TENANT_ID = process.env.MS_TENANT_ID || 'common';
const ENV_MS_CLIENT_SECRET = process.env.MS_CLIENT_SECRET || null;
const MS_STATE_TTL_MS = 5 * 60 * 1000;

fs.mkdirSync(DB_DIR, { recursive: true });

const adapter = new JSONFile(DB_PATH);
const db = new Low(adapter, { users: [], vaults: [], sharedVaults: [] });

async function ensureDb() {
  await db.read();
  db.data ||= {};
  db.data.users ||= [];
  db.data.vaults ||= [];
  db.data.sharedVaults ||= [];
  db.data.msStates ||= [];
  db.data.config ||= {};
}

function cleanupMsStates() {
  const cutoff = Date.now() - MS_STATE_TTL_MS;
  db.data.msStates = (db.data.msStates || []).filter((entry) => entry.createdAt >= cutoff);
}

function popMsState(stateId) {
  cleanupMsStates();
  const index = db.data.msStates.findIndex((entry) => entry.state === stateId);
  if (index === -1) {
    return null;
  }
  const [entry] = db.data.msStates.splice(index, 1);
  return entry;
}

function storeMsState(entry) {
  db.data.msStates.push(entry);
}

function mapMemberWrappers(memberWrappers = [], users = []) {
  const map = {};
  memberWrappers.forEach(({ userId, wrappedKey, role = 'member', status = 'active', invitedBy }) => {
    if (!userId || !wrappedKey) {
      return;
    }

    const resolvedUser = users.find((user) => user.id === userId || user.username === userId);
    const resolvedId = resolvedUser?.id ?? userId;
    const identifier = resolvedUser?.username ?? userId;

    map[resolvedId] = {
      identifier,
      wrappedKey,
      role,
      status,
      invitedBy,
      invitedAt: new Date().toISOString(),
    };
  });

  return map;
}

function getConfig() {
  return db.data.config || {};
}

function hasConfigValue(key) {
  return Object.prototype.hasOwnProperty.call(db.data.config || {}, key);
}

function updateConfig(values = {}) {
  const nextConfig = { ...(db.data.config || {}) };
  if (Object.prototype.hasOwnProperty.call(values, 'msClientId')) {
    nextConfig.msClientId = values.msClientId;
  }
  if (Object.prototype.hasOwnProperty.call(values, 'msTenantId')) {
    nextConfig.msTenantId = values.msTenantId;
  }
  if (Object.prototype.hasOwnProperty.call(values, 'msClientSecret')) {
    nextConfig.msClientSecret = values.msClientSecret;
  }
  db.data.config = nextConfig;
}

function getMsClientId() {
  return getConfig().msClientId || ENV_MS_CLIENT_ID;
}

function getMsTenantId() {
  return getConfig().msTenantId || ENV_MS_TENANT_ID;
}

function getMsClientSecret() {
  const configSecret = getConfig().msClientSecret;
  if (configSecret) {
    return configSecret;
  }
  if (ENV_MS_CLIENT_SECRET) {
    return ENV_MS_CLIENT_SECRET;
  }
  return null;
}

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function createMsStateEntry() {
  const state = nanoid();
  const codeVerifier = base64UrlEncode(crypto.randomBytes(64));
  const codeChallenge = base64UrlEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  );
  return { state, codeVerifier, codeChallenge, createdAt: Date.now() };
}

function createMsJwksClient() {
  const tenant = getMsTenantId();
  return jwksClient({
    jwksUri: `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
  });
}

function getMsSigningKey(header, callback) {
  const client = createMsJwksClient();
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    callback(null, key.getPublicKey());
  });
}

async function verifyMsIdToken(idToken) {
  const msClientId = getMsClientId();
  if (!msClientId) {
    throw new Error('Microsoft SSO client ID not configured');
  }
  const tenant = getMsTenantId();
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      getMsSigningKey,
      {
        audience: msClientId,
        issuer,
      },
      (err, payload) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(payload);
      }
    );
  });
}

function findMemberEntry(vault, identity = {}) {
  const normalized =
    typeof identity === 'object' && identity !== null
      ? identity
      : { userId: identity, username: identity };
  const { userId, username } = normalized;
  const members = vault?.memberKeys || {};
  for (const [key, info] of Object.entries(members)) {
    if (
      key === userId ||
      key === username ||
      info.identifier === userId ||
      info.identifier === username
    ) {
      return { key, info };
    }
  }
  return null;
}

function hasSharedAccess(vault, identity) {
  const entry = findMemberEntry(vault, identity);
  if (!entry) {
    return false;
  }
  return entry.info.status === 'active' || entry.info.status === 'invited';
}

function ensureUniqueUsername(base) {
  let candidate = base;
  let suffix = 1;
  while (db.data.users.some((entry) => entry.username === candidate)) {
    candidate = `${base}${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function createMsUser(payload) {
  const msOid = payload.sub;
  const email = payload.email ?? payload.preferred_username;
  const base = email ?? `ms-${msOid.slice(-6)}`;
  const username = ensureUniqueUsername(base);
  const user = {
    id: nanoid(),
    username,
    passwordHash: '',
    createdAt: new Date().toISOString(),
    msOid,
    msEmail: email,
    msName: payload.name ?? payload.preferred_username ?? username,
  };
  db.data.users.push(user);
  return user;
}

function findMsUser(payload) {
  return (
    db.data.users.find((entry) => entry.msOid === payload.sub) ||
    db.data.users.find((entry) => entry.username === payload.email) ||
    null
  );
}

function renderSsoResult(res, message) {
  const payload = JSON.stringify(message);
  const html = `<!doctype html>
<html>
  <body>
    <script>
      const payload = ${payload};
      if (window.opener) {
        window.opener.postMessage(payload, '*');
      }
      window.close();
    </script>
  </body>
</html>`;
  res.send(html);
}

const app = express();
app.set('trust proxy', true);

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use('/admin', express.static(path.join(__dirname, 'public')));

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization?.split(' ');
  if (!authHeader || authHeader[0] !== 'Bearer' || !authHeader[1]) {
    return res.status(401).json({ error: 'Missing Authorization token' });
  }

  try {
    const decoded = jwt.verify(authHeader[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/register', async (req, res) => {
  await ensureDb();
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const exists = db.data.users.find((user) => user.username === username);
  if (exists) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: nanoid(),
    username,
    passwordHash,
    createdAt: new Date().toISOString(),
  };

  db.data.users.push(user);
  await db.write();

  res.status(201).json({
    user: {
      id: user.id,
      username: user.username,
      createdAt: user.createdAt,
    },
  });
});

app.post('/login', async (req, res) => {
  await ensureDb();
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = db.data.users.find((entry) => entry.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  user.lastLogin = new Date().toISOString();
  await db.write();

  const token = createToken({ userId: user.id, username: user.username });
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
    },
  });
});

app.get('/vault', authMiddleware, async (req, res) => {
  await ensureDb();
  const vault = db.data.vaults.find((entry) => entry.userId === req.user.userId);
  if (!vault) {
    return res.json({ vault: null });
  }

  res.json({
    vault: {
      encryptedVault: vault.encryptedVault,
      iv: vault.iv,
      salt: vault.salt,
      updatedAt: vault.updatedAt,
      version: vault.version,
    },
  });
});

app.get('/shared-vaults', authMiddleware, async (req, res) => {
  await ensureDb();
  const sharedVaults = Array.isArray(db.data.sharedVaults) ? db.data.sharedVaults : [];
  const shared = sharedVaults
    .map((vault) => {
      const identity = { userId: req.user.userId, username: req.user.username };
      if (!hasSharedAccess(vault, identity)) {
        return null;
      }
      const entry = findMemberEntry(vault, {
        userId: req.user.userId,
        username: req.user.username,
      });
      if (!entry) {
        return null;
      }
      const { info } = entry;
      return {
        id: vault.id,
        name: vault.name,
        ownerId: vault.ownerId,
        role: info.role ?? 'member',
        status: info.status ?? 'active',
        wrappedKey: info.wrappedKey,
        updatedAt: vault.updatedAt,
      };
    })
    .filter(Boolean);

  res.json({ sharedVaults: shared });
});

app.get('/shared-vaults/:vaultId', authMiddleware, async (req, res) => {
  await ensureDb();
  const vault = db.data.sharedVaults.find((entry) => entry.id === req.params.vaultId);
  const identity = { userId: req.user.userId, username: req.user.username };
  if (!vault || !hasSharedAccess(vault, identity)) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  const memberEntry = findMemberEntry(vault, {
    userId: req.user.userId,
    username: req.user.username,
  });
  if (!memberEntry) {
    return res.status(404).json({ error: 'Shared vault access denied' });
  }

  const { info: memberInfo } = memberEntry;
  res.json({
    vault: {
      id: vault.id,
      name: vault.name,
      ownerId: vault.ownerId,
      encryptedVault: vault.encryptedVault,
      iv: vault.iv,
      salt: vault.salt,
      version: vault.version,
      updatedAt: vault.updatedAt,
      memberKeys: vault.memberKeys,
      wrappedKey: memberInfo.wrappedKey,
      members: Object.entries(vault.memberKeys).map(([identifier, info]) => ({
        identifier,
        role: info.role,
        status: info.status,
      })),
    },
  });
});

app.post('/shared-vaults', authMiddleware, async (req, res) => {
  await ensureDb();
  const { name, encryptedVault, iv, salt, memberWrappers } = req.body;
  if (!name || !encryptedVault || !iv || !salt || !Array.isArray(memberWrappers)) {
    return res.status(400).json({ error: 'name, encryptedVault, iv, salt, and memberWrappers are required' });
  }

  const memberMap = mapMemberWrappers(memberWrappers, db.data.users);
  if (!memberMap[req.user.userId]) {
    memberMap[req.user.userId] = {
      wrappedKey: memberWrappers[0]?.wrappedKey ?? '',
      role: 'owner',
      status: 'active',
      invitedBy: req.user.userId,
      invitedAt: new Date().toISOString(),
      identifier: req.user.username ?? req.user.userId,
    };
  }

  const vault = {
    id: nanoid(),
    name,
    ownerId: req.user.userId,
    encryptedVault,
    iv,
    salt,
    version: 1,
    updatedAt: new Date().toISOString(),
    memberKeys: memberMap,
  };

  db.data.sharedVaults.push(vault);
  await db.write();

  res.status(201).json({
    vaultId: vault.id,
    updatedAt: vault.updatedAt,
    version: vault.version,
  });
});

app.post('/shared-vaults/:vaultId', authMiddleware, async (req, res) => {
  await ensureDb();
  const { encryptedVault, iv, salt, memberWrappers } = req.body;
  if (!encryptedVault || !iv || !salt) {
    return res.status(400).json({ error: 'encryptedVault, iv, and salt are required' });
  }

  const vault = db.data.sharedVaults.find((entry) => entry.id === req.params.vaultId);
  if (!vault || !hasSharedAccess(vault, { userId: req.user.userId, username: req.user.username })) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  vault.encryptedVault = encryptedVault;
  vault.iv = iv;
  vault.salt = salt;
  vault.version += 1;
  vault.updatedAt = new Date().toISOString();

  if (Array.isArray(memberWrappers) && memberWrappers.length) {
    const wrappers = mapMemberWrappers(memberWrappers, db.data.users);
    vault.memberKeys = { ...vault.memberKeys, ...wrappers };
  }

  await db.write();

  res.json({
    success: true,
    updatedAt: vault.updatedAt,
    version: vault.version,
  });
});

app.patch('/shared-vaults/:vaultId', authMiddleware, async (req, res) => {
  await ensureDb();
  const { name, memberWrappers } = req.body;
  const vault = db.data.sharedVaults.find((entry) => entry.id === req.params.vaultId);
  if (!vault) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  if (vault.ownerId !== req.user.userId) {
    return res.status(403).json({ error: 'Only the owner can edit a shared vault' });
  }

  if (name !== undefined) {
    const trimmed = name.trim();
    if (!trimmed) {
      return res.status(400).json({ error: 'Vault name cannot be empty' });
    }
    vault.name = trimmed;
  }

  if (Array.isArray(memberWrappers)) {
    const wrappers = mapMemberWrappers(memberWrappers, db.data.users);
    if (!wrappers[req.user.userId]) {
      wrappers[req.user.userId] = {
        wrappedKey:
          vault.memberKeys?.[req.user.userId]?.wrappedKey ??
          vault.memberKeys?.[req.user.username]?.wrappedKey ??
          vault.salt ??
          '',
        role: 'owner',
        status: 'active',
        invitedBy: req.user.userId,
        invitedAt: new Date().toISOString(),
        identifier: req.user.username ?? req.user.userId,
      };
    }
    vault.memberKeys = wrappers;
  }

  vault.updatedAt = new Date().toISOString();
  vault.version = (vault.version ?? 0) + 1;
  await db.write();

  res.json({
    success: true,
    updatedAt: vault.updatedAt,
    version: vault.version,
  });
});

app.delete('/shared-vaults/:vaultId', authMiddleware, async (req, res) => {
  await ensureDb();
  const vaultIndex = db.data.sharedVaults.findIndex((entry) => entry.id === req.params.vaultId);
  if (vaultIndex === -1) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  const vault = db.data.sharedVaults[vaultIndex];
  if (vault.ownerId !== req.user.userId) {
    return res.status(403).json({ error: 'Only the owner can delete a shared vault' });
  }

  db.data.sharedVaults.splice(vaultIndex, 1);
  await db.write();

  res.json({
    success: true,
    deletedAt: new Date().toISOString(),
  });
});
app.post('/vault', authMiddleware, async (req, res) => {
  await ensureDb();
  const { encryptedVault, iv, salt } = req.body;
  if (!encryptedVault || !iv || !salt) {
    return res.status(400).json({ error: 'Ciphertext, IV, and salt are required' });
  }

  let vault = db.data.vaults.find((entry) => entry.userId === req.user.userId);
  if (!vault) {
    vault = {
      id: nanoid(),
      userId: req.user.userId,
      encryptedVault,
      iv,
      salt,
      version: 1,
      updatedAt: new Date().toISOString(),
    };
    db.data.vaults.push(vault);
  } else {
    vault.encryptedVault = encryptedVault;
    vault.iv = iv;
    vault.salt = salt;
    vault.version += 1;
    vault.updatedAt = new Date().toISOString();
  }

  await db.write();

  res.json({
    success: true,
    updatedAt: vault.updatedAt,
    version: vault.version,
  });
});

app.get('/sso/ms/start', async (req, res) => {
  const msClientId = getMsClientId();
  if (!msClientId) {
    res.status(500).send('Microsoft SSO client ID is not configured');
    return;
  }

  await ensureDb();
  const entry = createMsStateEntry();
  storeMsState(entry);
  await db.write();
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const redirectUri = `${baseUrl}/sso/ms/callback`;
  const params = new URLSearchParams({
    client_id: msClientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email',
    state: entry.state,
    code_challenge: entry.codeChallenge,
    code_challenge_method: 'S256',
  });
  const tenant = getMsTenantId();
  const authorizeUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?${params.toString()}`;
  res.redirect(authorizeUrl);
});

app.get('/sso/ms/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Missing code or state from Microsoft' });
    return;
  }

  await ensureDb();
  const stored = popMsState(state);
  await db.write();
  if (!stored) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Invalid or expired state' });
    return;
  }

  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const redirectUri = `${baseUrl}/sso/ms/callback`;
  const tenant = getMsTenantId();
  const msClientId = getMsClientId();
  if (!msClientId) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Microsoft SSO client ID is not configured' });
    return;
  }
  const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const form = new URLSearchParams({
    client_id: msClientId,
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: stored.codeVerifier,
  });
  const msClientSecret = getMsClientSecret();
  if (msClientSecret) {
    form.append('client_secret', msClientSecret);
  }

  let tokenResponse;
  try {
    tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
  } catch (error) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Failed to contact Microsoft token endpoint' });
    return;
  }

  if (!tokenResponse.ok) {
    const payload = await tokenResponse.text();
    renderSsoResult(res, { type: 'ms-sso', error: `Microsoft token error: ${payload}` });
    return;
  }

  const tokenPayload = await tokenResponse.json();
  if (!tokenPayload.id_token) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Microsoft did not return an ID token' });
    return;
  }

  let msClaims;
  try {
    msClaims = await verifyMsIdToken(tokenPayload.id_token);
  } catch (err) {
    renderSsoResult(res, { type: 'ms-sso', error: 'Invalid Microsoft ID token' });
    return;
  }

  let user = findMsUser(msClaims);
  if (!user) {
    user = createMsUser(msClaims);
  } else if (!user.msOid) {
    user.msOid = msClaims.sub;
  }
  user.lastLogin = new Date().toISOString();
  await db.write();

  const token = createToken({ userId: user.id, username: user.username });
  renderSsoResult(res, {
    type: 'ms-sso',
    token,
    user: { id: user.id, username: user.username },
  });
});

app.get('/admin/config', async (_req, res) => {
  await ensureDb();
  const config = getConfig();
  res.json({
    msClientId: config.msClientId || ENV_MS_CLIENT_ID || '',
    msTenantId: config.msTenantId || ENV_MS_TENANT_ID || 'common',
    msClientSecretSet: Boolean(config.msClientSecret || ENV_MS_CLIENT_SECRET),
  });
});

app.post('/admin/config', async (req, res) => {
  await ensureDb();
  const { msClientId, msTenantId, msClientSecret, clearMsClientSecret } = req.body || {};
  const updates = {};
  if (msClientId !== undefined) {
    updates.msClientId = msClientId ? String(msClientId).trim() : null;
  }
  if (msTenantId !== undefined) {
    const value = String(msTenantId ?? '').trim();
    updates.msTenantId = value ? value : null;
  }
  if (clearMsClientSecret) {
    updates.msClientSecret = null;
  } else if (msClientSecret !== undefined && msClientSecret !== null) {
    const secretValue = String(msClientSecret ?? '').trim();
    if (secretValue) {
      updates.msClientSecret = secretValue;
    }
  }
  updateConfig(updates);
  await db.write();
  const config = getConfig();
  res.json({
    msClientId: config.msClientId || ENV_MS_CLIENT_ID || '',
    msTenantId: config.msTenantId || ENV_MS_TENANT_ID || 'common',
    msClientSecretSet: Boolean(config.msClientSecret || ENV_MS_CLIENT_SECRET),
  });
});

app.get('/admin/users', authMiddleware, async (_req, res) => {
  await ensureDb();
  const users = (db.data.users || [])
    .map((user) => ({
      id: user.id,
      username: user.username,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin || null,
    }))
    .sort((a, b) => a.username.localeCompare(b.username));
  res.json({ users });
});

app.get('/config', async (_req, res) => {
  await ensureDb();
  res.json({
    msClientId: getMsClientId() || '',
    msTenantId: getMsTenantId() || 'common',
    msClientSecretSet: Boolean(getMsClientSecret()),
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const USE_HTTPS = process.env.USE_HTTPS !== 'false';

const startServer = () => {
  if (USE_HTTPS) {
    const { SSL_KEY_PATH, SSL_CERT_PATH, SSL_PASSPHRASE } = process.env;
    let credentials;
    if (SSL_KEY_PATH && SSL_CERT_PATH) {
      credentials = {
        key: fs.readFileSync(path.resolve(SSL_KEY_PATH)),
        cert: fs.readFileSync(path.resolve(SSL_CERT_PATH)),
        passphrase: SSL_PASSPHRASE,
      };
    } else {
      const attrs = [{ name: 'commonName', value: 'localhost' }];
      const pems = selfsigned.generate(attrs, { days: 365, keySize: 2048 });
      credentials = {
        key: pems.private,
        cert: pems.cert,
      };
    }

    https
      .createServer(credentials, app)
      .listen(PORT, () => {
        console.log(`Zero knowledge vault API listening on https://localhost:${PORT}`);
      });
  } else {
    app.listen(PORT, () => {
      console.log(`Zero knowledge vault API listening on http://localhost:${PORT}`);
    });
  }
};

startServer();
