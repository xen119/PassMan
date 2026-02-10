import { generateTotp } from './scripts/crypto.js';

const DEFAULT_AUTO_LOCK_MINUTES = 5;
const AUTO_LOCK_PREF_KEY = 'autoLockMinutes';
const AUTO_LOCK_STATUS_MESSAGE = 'Locked after inactivity. Please sign in again.';

const session = {
  token: null,
  username: null,
  salt: null,
  masterKey: null,
  expiresAt: null,
  entries: [],
};

const vaultCache = session.entries;

let autoLockTimeoutMs = DEFAULT_AUTO_LOCK_MINUTES * 60 * 1000;
let autoLockTimerId = null;

function updateEntries(entries = []) {
  vaultCache.splice(0, vaultCache.length, ...(entries || []));
}

function hasSessionExpired() {
  return session.expiresAt && Date.now() >= session.expiresAt;
}

function restartAutoLockTimer() {
  if (autoLockTimerId) {
    clearTimeout(autoLockTimerId);
    autoLockTimerId = null;
  }

  if (!session.token) {
    session.expiresAt = null;
    return;
  }

  session.expiresAt = Date.now() + autoLockTimeoutMs;
  autoLockTimerId = setTimeout(() => {
    clearSession(AUTO_LOCK_STATUS_MESSAGE, true);
  }, autoLockTimeoutMs);
}

function clearSession(reason = 'user-logout', notify = false) {
  session.token = null;
  session.username = null;
  session.salt = null;
  session.masterKey = null;
  session.expiresAt = null;
  updateEntries([]);

  if (autoLockTimerId) {
    clearTimeout(autoLockTimerId);
    autoLockTimerId = null;
  }

  if (notify && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ type: 'session-locked', reason });
  }
}

function updateAutoLockTimeout(minutes = DEFAULT_AUTO_LOCK_MINUTES) {
  const parsed = Number(minutes);
  const base = Number.isNaN(parsed) ? DEFAULT_AUTO_LOCK_MINUTES : parsed;
  const normalized = Math.min(60, Math.max(1, Math.round(base)));
  autoLockTimeoutMs = normalized * 60 * 1000;
  restartAutoLockTimer();
}

chrome.storage.local.get(AUTO_LOCK_PREF_KEY, (result) => {
  updateAutoLockTimeout(result?.[AUTO_LOCK_PREF_KEY] ?? DEFAULT_AUTO_LOCK_MINUTES);
});

function findEntryForHost(hostname) {
  return vaultCache.find((entry) => {
    if (!entry.url) {
      return false;
    }

    try {
      const entryHost = new URL(entry.url).hostname;
      return entryHost === hostname;
    } catch {
      return entry.url.includes(hostname);
    }
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message?.type) {
    return;
  }

  if (message.type === 'session-status') {
    if (hasSessionExpired()) {
      clearSession(AUTO_LOCK_STATUS_MESSAGE, true);
    }

    sendResponse({
      active: Boolean(session.token),
      token: session.token,
      username: session.username,
      salt: session.salt,
      masterKey: session.masterKey,
      entries: session.entries,
    });

    return;
  }

  if (message.type === 'session-sync') {
    session.token = message.token;
    session.username = message.username;
    session.salt = message.salt;
    session.masterKey = message.masterKey;
    updateEntries(message.entries);
    restartAutoLockTimer();
    sendResponse?.({ ok: true });
    return;
  }

  if (message.type === 'session-keepalive') {
    if (hasSessionExpired()) {
      clearSession(AUTO_LOCK_STATUS_MESSAGE, true);
    } else {
      restartAutoLockTimer();
    }
    sendResponse?.({ ok: true });
    return;
  }

  if (message.type === 'session-clear') {
    const reason = message.reason ?? 'user-logout';
    clearSession(reason, reason === AUTO_LOCK_STATUS_MESSAGE);
    sendResponse?.({ ok: true });
    return;
  }

  if (message.type === 'auto-lock-update') {
    updateAutoLockTimeout(message?.minutes ?? DEFAULT_AUTO_LOCK_MINUTES);
    sendResponse?.({ ok: true });
    return;
  }

  if (message.type === 'sync-vault') {
    updateEntries(message.entries);
    return;
  }

  if (message.type === 'password-detected') {
    const { credential } = message;
    if (!credential?.password) {
      sendResponse({ stored: false });
      return;
    }

    const lookupHostname = credential.hostname || (() => {
      try {
        return new URL(credential.url).hostname;
      } catch {
        return '';
      }
    })();
    const existingEntry = lookupHostname ? findEntryForHost(lookupHostname) : null;
    if (existingEntry && existingEntry.password === credential.password) {
      sendResponse({ stored: false });
      return;
    }

    const pending = {
      id: crypto.randomUUID?.() ?? String(Date.now()),
      label: credential.label ?? credential.hostname ?? 'New password',
      username: credential.username ?? '',
      password: credential.password,
      url: credential.url ?? '',
      hostname: credential.hostname ?? '',
      otpSecret: credential.otpSecret ?? '',
      detectedAt: Date.now(),
      existingEntryId: existingEntry?.id ?? null,
      existingEntryLabel: existingEntry?.label ?? existingEntry?.url ?? null,
    };

    chrome.storage.local.set({ pendingSave: pending }, () => {
      sendResponse({ stored: true });
    });

    return true;
  }

  if (message.type === 'autofill-request') {
    const { hostname } = message;
    const entry = findEntryForHost(hostname);
    if (!entry) {
      sendResponse({ found: false });
      return;
    }

    (async () => {
      let otp = null;
      if (entry.otpSecret) {
        try {
          otp = await generateTotp(entry.otpSecret);
        } catch {
          otp = null;
        }
      }

      sendResponse({ found: true, entry: { ...entry, otp } });
    })();
    return true;
  }
});
