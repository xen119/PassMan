const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const { nanoid } = require('nanoid');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-later-secret';
const DB_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DB_DIR, 'db.json');

fs.mkdirSync(DB_DIR, { recursive: true });

const adapter = new JSONFile(DB_PATH);
const db = new Low(adapter, { users: [], vaults: [], sharedVaults: [] });

async function ensureDb() {
  await db.read();
  db.data ||= {};
  db.data.users ||= [];
  db.data.vaults ||= [];
  db.data.sharedVaults ||= [];
}

function mapMemberWrappers(memberWrappers = []) {
  const map = {};
  memberWrappers.forEach(({ userId, wrappedKey, role = 'member', status = 'active', invitedBy }) => {
    if (!userId || !wrappedKey) {
      return;
    }

    map[userId] = {
      identifier: userId,
      wrappedKey,
      role,
      status,
      invitedBy,
      invitedAt: new Date().toISOString(),
    };
  });

  return map;
}

function findMemberEntry(vault, { userId, username }) {
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

const app = express();

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
  const shared = db.data.sharedVaults
    .filter((vault) => hasSharedAccess(vault, req.user.userId))
    .map((vault) => {
      const member = vault.memberKeys[req.user.userId];
      return {
        id: vault.id,
        name: vault.name,
        ownerId: vault.ownerId,
        role: member.role ?? 'member',
        status: member.status ?? 'active',
        wrappedKey: member.wrappedKey,
        updatedAt: vault.updatedAt,
      };
    });

  res.json({ sharedVaults: shared });
});

app.get('/shared-vaults/:vaultId', authMiddleware, async (req, res) => {
  await ensureDb();
  const vault = db.data.sharedVaults.find((entry) => entry.id === req.params.vaultId);
  if (!vault || !hasSharedAccess(vault, req.user.userId)) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  const member = vault.memberKeys[req.user.userId];
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
      wrappedKey: member.wrappedKey,
      members: Object.entries(vault.memberKeys).map(([userId, info]) => ({
        userId,
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

  const memberMap = mapMemberWrappers(memberWrappers);
  if (!memberMap[req.user.userId]) {
    memberMap[req.user.userId] = {
      wrappedKey: memberWrappers[0]?.wrappedKey ?? '',
      role: 'owner',
      status: 'active',
      invitedBy: req.user.userId,
      invitedAt: new Date().toISOString(),
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
  if (!vault || !hasSharedAccess(vault, req.user.userId)) {
    return res.status(404).json({ error: 'Shared vault not found' });
  }

  vault.encryptedVault = encryptedVault;
  vault.iv = iv;
  vault.salt = salt;
  vault.version += 1;
  vault.updatedAt = new Date().toISOString();

  if (Array.isArray(memberWrappers) && memberWrappers.length) {
    const wrappers = mapMemberWrappers(memberWrappers);
    vault.memberKeys = { ...vault.memberKeys, ...wrappers };
  }

  await db.write();

  res.json({
    success: true,
    updatedAt: vault.updatedAt,
    version: vault.version,
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

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Zero knowledge vault API listening on http://localhost:${PORT}`);
});
