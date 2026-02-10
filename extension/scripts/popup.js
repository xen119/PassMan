import {
  deriveKey,
  decryptVault,
  encryptVault,
  ensureCryptoUUID,
  exportCryptoKey,
  importCryptoKey,
  generateSalt,
  generateTotp,
} from './crypto.js';

const API_BASE = 'http://localhost:4000';

const authSection = document.getElementById('auth-section');
const vaultSection = document.getElementById('vault-section');
const statusEl = document.getElementById('status');
const currentUserEl = document.getElementById('current-user');
const entriesEl = document.getElementById('entries');
const authForm = document.getElementById('auth-form');

const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const logoutBtn = document.getElementById('logout-btn');
const entryForm = document.getElementById('entry-form');
const cancelEditButton = document.getElementById('cancel-edit-btn');
const saveEntryButton = document.getElementById('save-entry-btn');

const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');

const entryLabel = document.getElementById('entry-label');
const entryUsername = document.getElementById('entry-username');
const entryPassword = document.getElementById('entry-password');
const entryNotes = document.getElementById('entry-notes');
const entryUrl = document.getElementById('entry-url');
const entryOtpSecret = document.getElementById('entry-otp-secret');
const pendingPrompt = document.getElementById('pending-prompt');
const generatePasswordButton = document.getElementById('generate-password-btn');
const copyEntryPasswordButton = document.getElementById('copy-entry-password-btn');
const autoLockInput = document.getElementById('auto-lock-input');
const autoLockSaveButton = document.getElementById('auto-lock-save-btn');
const entryModal = document.getElementById('entry-modal');
const entryModalButton = document.getElementById('open-entry-modal-btn');
const entryModalClose = document.getElementById('entry-modal-close');
const autoLockModal = document.getElementById('auto-lock-modal');
const autoLockModalButton = document.getElementById('auto-lock-modal-btn');
const autoLockModalCancel = document.getElementById('auto-lock-modal-cancel');
const autoLockModalClose = document.getElementById('auto-lock-modal-close');
const autoLockValueDisplay = document.getElementById('auto-lock-value');
const sharedVaultListEl = document.getElementById('shared-vault-list');
const sharedVaultStatusEl = document.getElementById('shared-vault-status');
const sharedVaultEmptyEl = document.getElementById('shared-vault-empty');

const DEFAULT_AUTO_LOCK_MINUTES = 5;
const AUTO_LOCK_PREF_KEY = 'autoLockMinutes';
const OTP_REFRESH_MS = 15 * 1000;
let autoLockMinutes = DEFAULT_AUTO_LOCK_MINUTES;

if (autoLockInput) {
  autoLockInput.value = String(autoLockMinutes);
}
let otpRefreshInterval = null;

const state = {
  token: null,
  username: null,
  userId: null,
  masterPassword: null,
  masterKey: null,
  salt: null,
  entries: [],
  editingEntryId: null,
  pendingCandidate: null,
  sharedVaults: [],
  sharedVaultFetching: false,
  sharedVaultError: null,
  selectedSharedVaultId: null,
  activeSharedVault: null,
  sharedVaultKeyBase: null,
  sharedVaultKey: null,
};

function setStatus(message, isError = false) {
  statusEl.textContent = message ?? '';
  statusEl.style.color = isError ? '#c53030' : '#1a202c';
}

function escapeHtml(value) {
  if (!value) {
    return '';
  }

  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/"/g, '&quot;');
}

async function ensureSharedCryptoKey(base64Key) {
  if (!base64Key) {
    throw new Error('Shared vault key missing');
  }

  if (state.sharedVaultKeyBase === base64Key && state.sharedVaultKey) {
    return state.sharedVaultKey;
  }

  const key = await importCryptoKey(base64Key);
  state.sharedVaultKeyBase = base64Key;
  state.sharedVaultKey = key;
  return key;
}

function getMemberWrappedKey(vault) {
  const memberKeys = vault?.memberKeys ?? {};
  return (
    memberKeys?.[state.userId]?.wrappedKey ??
    memberKeys?.[state.username]?.wrappedKey ??
    vault?.wrappedKey
  );
}

function generateStrongPassword(length = 16) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
  const values = new Uint32Array(length);
  crypto.getRandomValues(values);
  return Array.from(values, (v) => charset[v % charset.length]).join('');
}

function updateAutoLockSetting(value, { persist = false, notifyBackground = false } = {}) {
  const minutes = Number(value ?? autoLockMinutes);
  if (Number.isNaN(minutes)) {
    return autoLockMinutes;
  }

  autoLockMinutes = Math.min(60, Math.max(1, Math.round(minutes)));
  if (autoLockInput) {
    autoLockInput.value = String(autoLockMinutes);
  }

  if (persist && chrome.storage?.local) {
    chrome.storage.local.set({ [AUTO_LOCK_PREF_KEY]: autoLockMinutes });
  }

  if (notifyBackground && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ type: 'auto-lock-update', minutes: autoLockMinutes }, () => {});
  }

  updateAutoLockDisplay();

  return autoLockMinutes;
}

function updateAutoLockDisplay() {
  if (autoLockValueDisplay) {
    autoLockValueDisplay.textContent = String(autoLockMinutes);
  }
}

function loadAutoLockPreference() {
  if (!chrome.storage?.local) {
    updateAutoLockSetting(autoLockMinutes, { notifyBackground: true });
    return;
  }

  chrome.storage.local.get(AUTO_LOCK_PREF_KEY, (result) => {
    const stored = Number(result?.[AUTO_LOCK_PREF_KEY]);
    const minutes = Number.isNaN(stored) ? autoLockMinutes : stored;
    updateAutoLockSetting(minutes, { notifyBackground: true });
  });
}

function handleAutoLockSave() {
  if (!autoLockInput) {
    return;
  }

  const minutes = Number(autoLockInput.value);
  if (Number.isNaN(minutes) || minutes < 1 || minutes > 60) {
    setStatus('Auto-lock timeout must be between 1 and 60 minutes', true);
    updateAutoLockSetting(autoLockMinutes, { notifyBackground: true });
    return;
  }

  updateAutoLockSetting(minutes, { persist: true, notifyBackground: true });
  closeAutoLockModal();
  setStatus(`Auto-lock timeout set to ${autoLockMinutes} minutes`);
}

function openAutoLockModal() {
  if (!autoLockModal) {
    return;
  }

  autoLockModal.removeAttribute('hidden');
  autoLockInput?.focus({ preventScroll: true });
  autoLockInput?.select();
}

function closeAutoLockModal() {
  if (!autoLockModal) {
    return;
  }

  autoLockModal.setAttribute('hidden', '');
}

function openEntryModal() {
  if (!entryModal) {
    return;
  }
  entryModal.removeAttribute('hidden');
  entryLabel?.focus();
}

function closeEntryModal() {
  if (!entryModal) {
    return;
  }
  entryModal.setAttribute('hidden', '');
}

function sendMessageToBackground(message) {
  return new Promise((resolve) => {
    if (!chrome.runtime?.sendMessage) {
      resolve(undefined);
      return;
    }

    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve(undefined);
        return;
      }
      resolve(response);
    });
  });
}

async function syncSessionToBackground() {
  if (!state.token || !state.masterKey) {
    return;
  }

  let exportedKey;
  try {
    exportedKey = await exportCryptoKey(state.masterKey);
  } catch {
    return;
  }

  await sendMessageToBackground({
    type: 'session-sync',
    token: state.token,
    username: state.username,
    salt: state.salt,
    masterKey: exportedKey,
    entries: state.entries,
  });
}

async function restoreSessionFromBackground() {
  const response = await sendMessageToBackground({ type: 'session-status' });
  if (!response?.active || !response.token || !response.masterKey) {
    return;
  }

  try {
    state.token = response.token;
    state.username = response.username;
    state.salt = response.salt ?? state.salt;
    state.entries = response.entries ?? [];
    state.masterKey = await importCryptoKey(response.masterKey);

    renderEntries();
    updateView();
    resetAutoLockTimer();
    setStatus('Session restored');
    await fetchSharedVaults();
  } catch (error) {
    console.warn('Failed to restore session', error);
  }
}

function setPendingCandidate(candidate) {
  state.pendingCandidate = candidate;
  renderPendingPrompt();
}

function clearPendingCandidate() {
  state.pendingCandidate = null;
  renderPendingPrompt();
  chrome.storage.local.remove('pendingSave');
}

function renderPendingPrompt() {
  if (!pendingPrompt) {
    return;
  }

  if (!state.pendingCandidate) {
    pendingPrompt.textContent = '';
    pendingPrompt.hidden = true;
    return;
  }

  pendingPrompt.hidden = false;

  const label = state.pendingCandidate.label || state.pendingCandidate.url || 'Saved site';
  const hostname = state.pendingCandidate.hostname ?? new URL(state.pendingCandidate.url).hostname;
  pendingPrompt.innerHTML = `
    <h3>Detected new password for ${escapeHtml(hostname)}</h3>
    <p>${escapeHtml(label)}</p>
    <div class="pending-actions">
      <button type="button" data-action="apply-candidate">Save this password</button>
      <button type="button" data-action="dismiss-candidate">Dismiss</button>
    </div>
  `;
}

function loadPendingCandidate() {
  chrome.storage.local.get('pendingSave', (data) => {
    if (chrome.runtime.lastError) {
      return;
    }
    if (data?.pendingSave) {
      setPendingCandidate(data.pendingSave);
    }
  });
}

function applyPendingToForm() {
  if (!state.pendingCandidate) {
    return;
  }

  const pickup = state.pendingCandidate;
  entryLabel.value = pickup.label || new URL(pickup.url ?? location.href).hostname;
  entryUsername.value = pickup.username ?? '';
  entryPassword.value = pickup.password ?? '';
  entryNotes.value = '';
  entryUrl.value = pickup.url ?? '';
  entryOtpSecret.value = pickup.otpSecret ?? '';
  setStatus('Loaded detected password — save to your vault when ready.');
  prepareEntryFormForAdd();
  clearPendingCandidate();
}

function setPasswordVisible(span) {
  if (!span) {
    return;
  }
  span.textContent = span.dataset.password;
}

function setPasswordMasked(span) {
  if (!span) {
    return;
  }
  span.textContent = span.dataset.mask;
}

function updateView() {
  const signedIn = Boolean(state.token);
  authSection.hidden = signedIn;
  vaultSection.hidden = !signedIn;
  currentUserEl.textContent = state.username ?? '';
  renderSharedVaultList();
}

function renderSharedVaultList() {
  if (!sharedVaultListEl) {
    return;
  }

  sharedVaultListEl.innerHTML = '';
  if (sharedVaultStatusEl) {
    if (state.sharedVaultFetching) {
      sharedVaultStatusEl.textContent = 'Loading shared vaults…';
    } else if (state.sharedVaultError) {
      sharedVaultStatusEl.textContent = state.sharedVaultError;
    } else {
      sharedVaultStatusEl.textContent = '';
    }
  }

  const hasVaults = state.sharedVaults.length > 0;
  if (sharedVaultEmptyEl) {
    sharedVaultEmptyEl.hidden = hasVaults || state.sharedVaultFetching;
  }

  if (!hasVaults) {
    return;
  }

  state.sharedVaults.forEach((vault) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'shared-vault-item';
    if (state.selectedSharedVaultId === vault.id) {
      item.classList.add('selected');
    }

    const statusText = vault.status ? `${vault.status}` : vault.role ?? 'member';
    item.innerHTML = `
      <span>${escapeHtml(vault.name)}</span>
      <span class="shared-vault-item-meta">${escapeHtml(statusText)}</span>
    `;

    item.addEventListener('click', () => selectSharedVault(vault).catch((err) => setStatus(err.message, true)));
    sharedVaultListEl.appendChild(item);
  });
}

async function selectSharedVault(vault) {
  const vaultId = vault?.id ?? null;
  if (state.selectedSharedVaultId === vaultId) {
    state.selectedSharedVaultId = null;
    state.activeSharedVault = null;
    state.sharedVaultKeyBase = null;
    state.sharedVaultKey = null;
    renderSharedVaultList();
    await loadVault();
    setStatus('Switched back to your personal vault');
    return;
  }

  state.selectedSharedVaultId = vaultId;
  renderSharedVaultList();
  if (!vaultId) {
    return;
  }

  await loadSharedVault(vaultId);
}

async function fetchSharedVaults() {
  if (!state.token) {
    resetSharedVaultState();
    return;
  }

  state.sharedVaultFetching = true;
  state.sharedVaultError = null;
  renderSharedVaultList();

  try {
    const payload = await apiRequest('/shared-vaults', { method: 'GET' }, true);
    state.sharedVaults = payload.sharedVaults ?? [];
    if (state.selectedSharedVaultId && !state.sharedVaults.find((vault) => vault.id === state.selectedSharedVaultId)) {
      state.selectedSharedVaultId = null;
      state.activeSharedVault = null;
    }
  } catch (error) {
    state.sharedVaultError = error.message;
    state.sharedVaults = [];
  } finally {
    state.sharedVaultFetching = false;
    renderSharedVaultList();
  }
}

async function loadSharedVault(vaultId) {
  if (!state.token || !vaultId) {
    return;
  }

  setStatus('Loading shared vault...');
  try {
    const payload = await apiRequest(`/shared-vaults/${vaultId}`, { method: 'GET' }, true);
    const vault = payload.vault;
    if (!vault) {
      throw new Error('Shared vault data missing');
    }

    state.activeSharedVault = vault;
    const wrappedKey = getMemberWrappedKey(vault);
    await ensureSharedCryptoKey(wrappedKey);
    await decryptSharedVault(vault);
    setStatus(`Shared vault "${vault.name}" loaded`);
  } catch (error) {
    state.activeSharedVault = null;
    setStatus(error.message, true);
  }
}

async function decryptSharedVault(vault) {
  const key = state.sharedVaultKey;
  if (!key) {
    throw new Error('Missing shared vault key');
  }

  if (vault.encryptedVault) {
    try {
      state.entries = await decryptVault(vault.encryptedVault, vault.iv, key);
    } catch {
      state.entries = [];
      throw new Error('Unable to decrypt shared vault with the current key');
    }
  } else {
    state.entries = [];
  }

  renderEntries();
  resetAutoLockTimer();
}

function resetSharedVaultState() {
  state.sharedVaults = [];
  state.selectedSharedVaultId = null;
  state.sharedVaultError = null;
  state.sharedVaultFetching = false;
  state.activeSharedVault = null;
  state.sharedVaultKeyBase = null;
  state.sharedVaultKey = null;
  renderSharedVaultList();
}

function syncEntriesToBackground() {
  chrome.runtime.sendMessage({
    type: 'sync-vault',
    entries: state.entries.map((entry) => ({
      id: entry.id,
      label: entry.label,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      otpSecret: entry.otpSecret,
    })),
  });
}

function prepareEntryFormForAdd() {
  state.editingEntryId = null;
  entryUrl.value = '';
  entryOtpSecret.value = '';
  saveEntryButton.textContent = 'Save encrypted vault';
  cancelEditButton.hidden = true;
}

function beginEntryEdit(entry) {
  state.editingEntryId = entry.id;
  entryLabel.value = entry.label ?? '';
  entryUsername.value = entry.username ?? '';
  entryPassword.value = entry.password ?? '';
  entryNotes.value = entry.notes ?? '';
  entryUrl.value = entry.url ?? '';
  entryOtpSecret.value = entry.otpSecret ?? '';
  saveEntryButton.textContent = 'Update entry';
  cancelEditButton.hidden = false;
  openEntryModal();
}

function clearSessionState({ notifyBackground = true, reason = 'user-logout' } = {}) {
  state.token = null;
  state.username = null;
  state.masterPassword = null;
  state.masterKey = null;
  state.salt = null;
  state.editingEntryId = null;
  state.entries = [];
  entryForm.reset();
  prepareEntryFormForAdd();
  entriesEl.innerHTML = '';
  stopOtpRefresh();
  if (notifyBackground && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({ type: 'session-clear', reason }, () => {});
  }
  resetSharedVaultState();
  updateView();
}

function stopOtpRefresh() {
  if (otpRefreshInterval) {
    clearInterval(otpRefreshInterval);
    otpRefreshInterval = null;
  }
}

function startOtpRefresh() {
  stopOtpRefresh();
  refreshOtps().catch(() => {});
  otpRefreshInterval = setInterval(() => {
    refreshOtps().catch(() => {});
  }, OTP_REFRESH_MS);
}

async function refreshOtps() {
  const jobs = state.entries
    .filter((entry) => entry.otpSecret)
    .map(async (entry) => {
      const row = entriesEl.querySelector(`[data-entry-id="${entry.id}"]`);
      const otpValueEl = row?.querySelector('.otp-value');
      if (!otpValueEl) {
        return;
      }

      try {
        const code = await generateTotp(entry.otpSecret);
        otpValueEl.textContent = code;
      } catch (err) {
        otpValueEl.textContent = 'Invalid secret';
      }
    });

  await Promise.allSettled(jobs);
}

function resetAutoLockTimer() {
  if (!state.token) {
    return;
  }

  if (!chrome.runtime?.sendMessage) {
    return;
  }

  chrome.runtime.sendMessage({ type: 'session-keepalive' }, () => {});
}

function renderEntries() {
  if (!state.entries.length) {
    entriesEl.innerHTML = '<p>No entries yet. Add one below.</p>';
  } else {
    entriesEl.innerHTML = state.entries
      .map((entry) => {
        const label = escapeHtml(entry.label);
        const username = entry.username ? escapeHtml(entry.username) : '&mdash;';
        const passwordValue = entry.password ? entry.password : null;
        const notes = escapeHtml(entry.notes ?? '');
        const urlFragment = entry.url
          ? `<div><span>URL:</span> <a href="${escapeAttr(entry.url)}" target="_blank" rel="noreferrer">${escapeHtml(
              entry.url
            )}</a></div>`
          : '';
        const otpFragment = entry.otpSecret
          ? `<div class="entry-otp"><span>OTP</span><span class="otp-value">Loading…</span><button type="button" data-action="copy-otp">Copy OTP</button></div>`
          : '';

        return `
        <article class="entry-row" data-entry-id="${entry.id}">
          <div class="entry-row-top">
            <strong>${label}</strong>
            <div class="entry-row-actions">
              <button type="button" data-action="copy">Copy</button>
              <button type="button" data-action="edit">Edit</button>
              <button type="button" data-action="delete">Delete</button>
            </div>
          </div>
          <div><span>Username:</span> ${username}</div>
          <div>
            <span>Password:</span>
            ${
              passwordValue
                ? `<span class="password-value" data-password="${escapeAttr(passwordValue)}" data-mask="••••••••">••••••••</span>`
                : '&mdash;'
            }
            ${passwordValue ? '<button type="button" class="reveal-btn" data-action="reveal">Show</button>' : ''}
          </div>
          ${urlFragment}
          ${otpFragment}
          <div class="notes">${notes}</div>
        </article>
      `;
      })
      .join('');
  }

  startOtpRefresh();
  syncEntriesToBackground();
}

function handleRevealToggle(event, show) {
  const button = event.target.closest('button[data-action="reveal"]');
  if (!button) {
    return;
  }

  const span = button.closest('[data-entry-id]')?.querySelector('.password-value');
  if (!span) {
    return;
  }

  if (show) {
    setPasswordVisible(span);
  } else {
    setPasswordMasked(span);
  }
}

function handlePendingPromptClick(event) {
  const actionButton = event.target.closest('button[data-action]');
  if (!actionButton) {
    return;
  }
  const action = actionButton.dataset.action;
  if (action === 'apply-candidate') {
    applyPendingToForm();
  }
  if (action === 'dismiss-candidate') {
    clearPendingCandidate();
  }
}

async function apiRequest(path, options = {}, withAuth = false) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (withAuth && state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error ?? 'Network request failed');
  }

  return response.json();
}

async function handleAuthentication(mode) {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    setStatus('Username and password are required', true);
    return;
  }

  try {
    setStatus(mode === 'login' ? 'Logging in...' : 'Registering...');

    if (mode === 'register') {
      await apiRequest(
        '/register',
        {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        },
        false
      );
      setStatus('Account created. Please log in.', false);
      return;
    }

    const payload = await apiRequest(
      '/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      },
      false
    );

    state.token = payload.token;
    state.username = payload.user.username;
    state.userId = payload.user.id;
    state.masterPassword = password;
    state.masterKey = null;

    entryForm.reset();
    prepareEntryFormForAdd();

    updateView();
    await loadVault();
    await fetchSharedVaults();
  } catch (error) {
    setStatus(error.message, true);
  }
}

async function loadVault() {
  setStatus('Loading vault...');

  try {
    const payload = await apiRequest('/vault', { method: 'GET' }, true);

    state.salt = payload.vault?.salt ?? state.salt ?? generateSalt();
    state.masterKey = await deriveKey(state.masterPassword, state.salt);

    if (payload.vault?.encryptedVault) {
      try {
        state.entries = await decryptVault(
          payload.vault.encryptedVault,
          payload.vault.iv,
          state.masterKey
        );
      } catch (err) {
        state.entries = [];
        setStatus('Unable to decrypt vault. Check your master password.', true);
        return;
      }
    } else {
      state.entries = [];
    }

    renderEntries();
    await syncSessionToBackground();
    await fetchSharedVaults();
    setStatus('Vault ready');
    resetAutoLockTimer();
  } catch (error) {
    setStatus(`Failed to load vault: ${error.message}`, true);
  }
}

async function persistVault() {
  if (!state.masterKey && !state.masterPassword) {
    setStatus('Master password missing', true);
    return;
  }

  if (!state.masterKey && state.masterPassword) {
    state.masterKey = await deriveKey(state.masterPassword, state.salt ?? generateSalt());
  }
  state.salt ??= generateSalt();

  const encrypted = await encryptVault(state.entries, state.masterKey);

  try {
    if (state.selectedSharedVaultId && state.activeSharedVault && state.sharedVaultKey) {
      const sharedEncrypted = await encryptVault(state.entries, state.sharedVaultKey);

      const payload = {
        encryptedVault: sharedEncrypted.ciphertext,
        iv: sharedEncrypted.iv,
        salt: state.sharedVaultKeyBase, // reuse key base as salt for simplicity
        memberWrappers: buildMemberWrappers(),
      };

      const result = await apiRequest(
        `/shared-vaults/${state.selectedSharedVaultId}`,
        {
          method: 'POST',
          body: JSON.stringify(payload),
        },
        true
      );

      state.activeSharedVault.encryptedVault = sharedEncrypted.ciphertext;
      state.activeSharedVault.iv = sharedEncrypted.iv;
      state.activeSharedVault.salt = payload.salt;
      state.activeSharedVault.version = result.version ?? state.activeSharedVault.version;
      state.activeSharedVault.updatedAt = result.updatedAt ?? state.activeSharedVault.updatedAt;

      setStatus('Shared vault saved');
      resetAutoLockTimer();
      await syncSessionToBackground();
      return;
    }

    await apiRequest(
      '/vault',
      {
        method: 'POST',
        body: JSON.stringify({
          encryptedVault: encrypted.ciphertext,
          iv: encrypted.iv,
          salt: state.salt,
        }),
      },
      true
    );
    setStatus('Vault saved');
    resetAutoLockTimer();
    await syncSessionToBackground();
  } catch (error) {
    setStatus(`Failed to persist vault: ${error.message}`, true);
  }
}

function buildMemberWrappers() {
  return Object.entries(state.activeSharedVault?.memberKeys ?? {}).map(([userId, info]) => ({
    userId,
    wrappedKey: info.wrappedKey,
    role: info.role,
    status: info.status,
    invitedBy: info.invitedBy,
  }));
}

entryForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const label = entryLabel.value.trim();
  if (!label) {
    setStatus('Label is required', true);
    return;
  }

  const entryPayload = {
    label,
    username: entryUsername.value.trim(),
    password: entryPassword.value,
    notes: entryNotes.value.trim(),
    url: entryUrl.value.trim(),
    otpSecret: entryOtpSecret.value.trim(),
    updatedAt: new Date().toISOString(),
  };

  if (state.editingEntryId) {
    entryPayload.id = state.editingEntryId;
    state.entries = state.entries.map((entry) =>
      entry.id === state.editingEntryId ? { ...entry, ...entryPayload } : entry
    );
  } else {
    entryPayload.id = ensureCryptoUUID();
    state.entries = [entryPayload, ...state.entries];
  }

  entryForm.reset();
  prepareEntryFormForAdd();
  renderEntries();
  await persistVault();
  closeEntryModal();
});

entriesEl.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) {
    return;
  }

  const entryTarget = button.closest('[data-entry-id]');
  if (!entryTarget) {
    return;
  }

  const entryId = entryTarget.dataset.entryId;
  const entry = state.entries.find((item) => item.id === entryId);
  if (!entry) {
    return;
  }

  resetAutoLockTimer();

  const action = button.dataset.action;
  if (action === 'copy') {
    if (!entry.password) {
      setStatus('Entry has no password to copy', true);
      return;
    }

    try {
      await navigator.clipboard.writeText(entry.password);
      setStatus('Password copied to clipboard');
    } catch (err) {
      setStatus('Clipboard unavailable', true);
    }
    return;
  }

  if (action === 'reveal') {
    return;
  }

  if (action === 'copy-otp') {
    const otpValueEl = entryTarget.querySelector('.otp-value');
    const otpValue = otpValueEl?.textContent;
    if (!otpValue || otpValue === 'Loading…' || otpValue === 'Invalid secret') {
      setStatus('OTP not ready', true);
      return;
    }

    try {
      await navigator.clipboard.writeText(otpValue);
      setStatus('OTP copied to clipboard');
    } catch (err) {
      setStatus('Clipboard unavailable', true);
    }
    return;
  }

  if (action === 'edit') {
    beginEntryEdit(entry);
    setStatus(`Editing “${entry.label}”`);
    return;
  }

  if (action === 'delete') {
    if (!confirm(`Delete "${entry.label}" permanently?`)) {
      return;
    }
    state.entries = state.entries.filter((item) => item.id !== entryId);
    if (state.editingEntryId === entryId) {
      entryForm.reset();
      prepareEntryFormForAdd();
    }
    renderEntries();
    await persistVault();
    setStatus('Entry deleted');
  }
});

entriesEl.addEventListener('pointerdown', (event) => handleRevealToggle(event, true));
entriesEl.addEventListener('pointerup', (event) => handleRevealToggle(event, false));
entriesEl.addEventListener('pointerleave', (event) => handleRevealToggle(event, false));

pendingPrompt?.addEventListener('click', handlePendingPromptClick);

generatePasswordButton?.addEventListener('click', () => {
  const password = generateStrongPassword(20);
  entryPassword.value = password;
  if (navigator?.clipboard) {
    navigator.clipboard.writeText(password).catch(() => {});
  }
  setStatus('Generated a strong password and copied to clipboard.');
});

copyEntryPasswordButton?.addEventListener('click', async () => {
  if (!entryPassword.value) {
    setStatus('No password to copy', true);
    return;
  }
  try {
    await navigator.clipboard.writeText(entryPassword.value);
    setStatus('Password copied to clipboard');
  } catch {
    setStatus('Copy unavailable', true);
  }
});

cancelEditButton.addEventListener('click', () => {
  entryForm.reset();
  prepareEntryFormForAdd();
  setStatus('Edit canceled');
  resetAutoLockTimer();
  closeEntryModal();
});

registerBtn.addEventListener('click', () => handleAuthentication('register'));
authForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  handleAuthentication('login');
});

logoutBtn.addEventListener('click', () => {
  clearSessionState({ reason: 'user-logout' });
  setStatus('Signed out');
});

entryForm.addEventListener('input', resetAutoLockTimer);
document.addEventListener('mousemove', resetAutoLockTimer);
document.addEventListener('keydown', resetAutoLockTimer);
autoLockSaveButton?.addEventListener('click', handleAutoLockSave);
autoLockModalButton?.addEventListener('click', (event) => {
  event?.preventDefault();
  openAutoLockModal();
});
autoLockModalCancel?.addEventListener('click', () => closeAutoLockModal());
autoLockModalClose?.addEventListener('click', () => closeAutoLockModal());
autoLockModal?.addEventListener('click', (event) => {
  if (event.target === autoLockModal) {
    closeAutoLockModal();
  }
});
entryModalButton?.addEventListener('click', () => {
  prepareEntryFormForAdd();
  openEntryModal();
});
entryModalClose?.addEventListener('click', () => closeEntryModal());
entryModal?.addEventListener('click', (event) => {
  if (event.target === entryModal) {
    closeEntryModal();
  }
});
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') {
    return;
  }

  if (entryModal && !entryModal.hasAttribute('hidden')) {
    closeEntryModal();
    return;
  }

  if (autoLockModal && !autoLockModal.hasAttribute('hidden')) {
    closeAutoLockModal();
  }
});

loadPendingCandidate();

loadAutoLockPreference();
restoreSessionFromBackground().catch(() => {});

chrome.storage?.onChanged?.addListener?.((changes, area) => {
  if (area !== 'local' || !changes.pendingSave) {
    return;
  }

  if (changes.pendingSave.newValue) {
    setPendingCandidate(changes.pendingSave.newValue);
  } else {
    clearPendingCandidate();
  }
});

chrome.runtime?.onMessage?.addListener?.((message) => {
  if (message?.type === 'session-locked') {
    clearSessionState({ notifyBackground: false });
    setStatus(message.reason ?? 'Locked after inactivity. Please sign in again.');
  }
});

prepareEntryFormForAdd();
updateView();
