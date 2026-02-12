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

const API_BASES = ['https://localhost:4000', 'http://localhost:4000'];
let apiBaseIndex = 0;
const getApiBase = () => customApiBase?.trim() || API_BASES[apiBaseIndex];

function fallbackToHttp() {
  if (customApiBase) {
    return false;
  }
  if (apiBaseIndex >= API_BASES.length - 1) {
    return false;
  }
  apiBaseIndex += 1;
  setStatus(
    'Unable to reach the API over HTTPS—falling back to HTTP. Visit https://localhost:4000 once to trust the self-signed certificate for secure operation.',
    true
  );
  return true;
}

function applyCustomApiBase(value) {
  if (!value) {
    customApiBase = null;
  } else {
    customApiBase = value.trim().replace(/\/+$/, '');
  }
  if (customApiInput) {
    customApiInput.value = customApiBase ?? '';
  }
}

function persistCustomApiBase() {
  if (!chrome.storage?.local) {
    return;
  }
  chrome.storage.local.set({ [CUSTOM_API_KEY]: customApiBase });
}

function loadCustomApiBase() {
  if (!chrome.storage?.local) {
    return;
  }
  chrome.storage.local.get(CUSTOM_API_KEY, (result) => {
    applyCustomApiBase(result?.[CUSTOM_API_KEY] ?? null);
  });
}

function updateMsSsoVisibility() {
  if (!msSsoButton) {
    return;
  }
  if (msSsoRow) {
    msSsoRow.hidden = !msSsoConfigured;
  }
  msSsoButton.disabled = !msSsoConfigured;
}

async function loadMsSsoConfig() {
  try {
    const payload = await apiRequest('/config', {}, false);
    msSsoConfigured = Boolean(payload?.msClientId?.trim());
  } catch {
    msSsoConfigured = false;
  } finally {
    msSsoConfigLoaded = true;
    updateMsSsoVisibility();
  }
}

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
const rememberPasswordInput = document.getElementById('remember-password');

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
const sharedVaultEditButton = document.getElementById('shared-vault-edit-btn');
const sharedVaultEditor = document.getElementById('shared-vault-editor');
const sharedVaultNameInput = document.getElementById('shared-vault-name');
const sharedVaultMembersContainer = document.getElementById('shared-vault-members');
const sharedVaultAddMemberButton = document.getElementById('shared-vault-add-member');
const sharedVaultEditorSave = document.getElementById('shared-vault-editor-save');
const sharedVaultEditorCancel = document.getElementById('shared-vault-editor-cancel');
const vaultModal = document.getElementById('vault-modal');
const vaultModalToggle = document.getElementById('vault-modal-toggle');
const vaultModalClose = document.getElementById('vault-modal-close');
const vaultSelectorRow = document.getElementById('vault-selector-row');
const personalVaultButton = document.getElementById('personal-vault-btn');
const msSsoButton = document.getElementById('ms-sso-button');
const msSsoRow = document.querySelector('.ms-sso-row');
if (msSsoRow) {
  msSsoRow.hidden = true;
}
if (msSsoButton) {
  msSsoButton.disabled = true;
}
const scanOtpButton = document.getElementById('scan-otp-btn');
const headerUserEl = document.querySelector('.header-user');
const selectedVaultNameEl = document.getElementById('selected-vault-name');
const customApiInput = document.getElementById('custom-api-base');
const customApiSaveButton = document.getElementById('custom-api-save');
const customApiResetButton = document.getElementById('custom-api-reset');

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
  vaultModalOpen: false,
};
const CUSTOM_API_KEY = 'customApiBase';
let customApiBase = null;

function setStatus(message, isError = false) {
  statusEl.textContent = message ?? '';
  statusEl.style.color = isError ? '#c53030' : '#1a202c';
}

let msSsoWindow = null;
let msSsoConfigured = false;
let msSsoConfigLoaded = false;

function handleMsSsoMessage(event) {
  const expectedOrigin = (() => {
    try {
      return new URL(getApiBase()).origin;
    } catch {
      return null;
    }
  })();
  if (expectedOrigin && event.origin !== expectedOrigin) {
    return;
  }
  if (!event.data || event.data.type !== 'ms-sso') {
    return;
  }
  window.removeEventListener('message', handleMsSsoMessage);
  if (msSsoWindow && !msSsoWindow.closed) {
    msSsoWindow.close();
  }

  if (event.data.error) {
    setStatus(event.data.error, true);
    return;
  }

  const { token, user } = event.data;
  if (!token || !user) {
    setStatus('Microsoft sign-in failed', true);
    return;
  }

  state.token = token;
  state.username = user.username ?? '';
  state.userId = user.id ?? state.userId;
  state.masterPassword = null;
  state.masterKey = null;
  setStatus(`Signed in as ${state.username}`);
  updateView();
  loadVault().catch((error) => setStatus(error.message, true));
  fetchSharedVaults().catch(() => {});
  syncSessionToBackground().catch(() => {});
}

function startMicrosoftSSO() {
  if (msSsoWindow && !msSsoWindow.closed) {
    msSsoWindow.focus();
    return;
  }
  if (!msSsoConfigLoaded) {
    setStatus('Checking Microsoft SSO configuration…', true);
    return;
  }
  if (!msSsoConfigured) {
    setStatus('Microsoft SSO is not configured on the server', true);
    return;
  }
  const authUrl = `${getApiBase()}/sso/ms/start`;
  msSsoWindow = window.open(authUrl, 'ms-sso', 'width=500,height=700');
  if (!msSsoWindow) {
    setStatus('Please allow popups to use Microsoft sign-in', true);
    return;
  }
  window.addEventListener('message', handleMsSsoMessage);
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

function openVaultModal() {
  if (!vaultModal) {
    return;
  }
  vaultModal.removeAttribute('hidden');
  state.vaultModalOpen = true;
}

function closeVaultModal() {
  if (!vaultModal) {
    return;
  }
  vaultModal.setAttribute('hidden', '');
  state.vaultModalOpen = false;
}

function normalizeDomainUrl(value) {
  if (!value) {
    return '';
  }

  try {
    const parsed = new URL(value);
    return parsed.origin;
  } catch {
    return value;
  }
}

function findEntryByNormalizedUrl(url) {
  const normalized = normalizeDomainUrl(url ?? '');
  if (!normalized) {
    return null;
  }

  return state.entries.find((entry) => normalizeDomainUrl(entry.url ?? '') === normalized);
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

function loadOtpScanResult() {
  if (!chrome.storage?.local || !entryOtpSecret) {
    return;
  }

  chrome.storage.local.get('otpScanResult', (result) => {
    const secret = result?.otpScanResult;
    if (!secret) {
      return;
    }

    entryOtpSecret.value = secret;
    setStatus('OTP secret imported from scan');
    chrome.storage.local.remove('otpScanResult');
  });
}

function loadRememberedCredentials() {
  if (!chrome.storage?.local || !rememberPasswordInput) {
    return;
  }

  chrome.storage.local.get('rememberedCredentials', (result) => {
    const credentials = result?.rememberedCredentials;
    if (!credentials) {
      rememberPasswordInput.checked = false;
      return;
    }

    const { username, password } = credentials;
    usernameInput.value = username ?? '';
    passwordInput.value = password ?? '';
    rememberPasswordInput.checked = true;
  });
}

function saveRememberedCredentials(username, password) {
  if (!chrome.storage?.local) {
    return;
  }

  chrome.storage.local.set({
    rememberedCredentials: {
      username,
      password,
    },
  });
}

function clearRememberedCredentials() {
  if (!chrome.storage?.local) {
    return;
  }

  chrome.storage.local.remove('rememberedCredentials');
  if (rememberPasswordInput) {
    rememberPasswordInput.checked = false;
  }
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
  if (!candidate) {
    state.pendingCandidate = null;
    renderPendingPrompt();
    return;
  }

  const existingEntry = findEntryByNormalizedUrl(candidate.url ?? '');
  const isSamePassword = existingEntry && existingEntry.password === candidate.password;
  if (isSamePassword) {
    if (chrome.storage?.local) {
      chrome.storage.local.remove('pendingSave');
    }
    return;
  }

  if (existingEntry) {
    candidate.existingEntryId = existingEntry.id;
    candidate.existingEntryLabel = existingEntry.label;
  }

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
  let hostname = 'Saved site';
  try {
    hostname = state.pendingCandidate.hostname ?? new URL(state.pendingCandidate.url).hostname;
  } catch {
    hostname = state.pendingCandidate.hostname ?? hostname;
  }
  const isUpdate = Boolean(state.pendingCandidate.existingEntryId);
  const actionLabel = isUpdate ? 'Update this password' : 'Save this password';
  const headerText = isUpdate ? 'Detected password change' : 'Detected new password';

  pendingPrompt.innerHTML = `
    <h3>${headerText} for ${escapeHtml(hostname)}</h3>
    <p>${escapeHtml(label)}</p>
    <div class="pending-actions">
      <button type="button" data-action="apply-candidate">${escapeHtml(actionLabel)}</button>
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

async function savePendingCandidateToVault() {
  if (!state.pendingCandidate) {
    return;
  }

  const pickup = state.pendingCandidate;
  const hostname =
    (pickup.hostname ?? new URL(pickup.url ?? location.href).hostname) || 'Saved site';
  const normalizedUrl = normalizeDomainUrl(pickup.url ?? '');
  const updatedAt = new Date().toISOString();
  const existingEntryId = pickup.existingEntryId;
  let entryPayload;
  let isUpdate = false;
  if (existingEntryId) {
    const existingEntry = state.entries.find((entry) => entry.id === existingEntryId);
    if (existingEntry) {
      isUpdate = true;
      entryPayload = {
        ...existingEntry,
        label: pickup.label || existingEntry.label || hostname,
        username: pickup.username ?? existingEntry.username ?? '',
        password: pickup.password ?? existingEntry.password ?? '',
        url: normalizedUrl || existingEntry.url,
        otpSecret: pickup.otpSecret ?? existingEntry.otpSecret ?? '',
        updatedAt,
      };
      state.entries = [entryPayload, ...state.entries.filter((entry) => entry.id !== existingEntryId)];
    } else {
      entryPayload = {
        id: ensureCryptoUUID(),
        label: pickup.label || hostname,
        username: pickup.username ?? '',
        password: pickup.password ?? '',
        notes: '',
        url: normalizedUrl,
        otpSecret: pickup.otpSecret ?? '',
        updatedAt,
      };
      state.entries = [entryPayload, ...state.entries];
    }
  } else {
    entryPayload = {
      id: ensureCryptoUUID(),
      label: pickup.label || hostname,
      username: pickup.username ?? '',
      password: pickup.password ?? '',
      notes: '',
      url: normalizedUrl,
      otpSecret: pickup.otpSecret ?? '',
      updatedAt,
    };
    state.entries = [entryPayload, ...state.entries];
  }
  renderEntries();
  try {
    await persistVault();
    setStatus(isUpdate ? 'Detected password updated in your vault.' : 'Detected password saved to your vault.');
    clearPendingCandidate();
  } catch (error) {
    setStatus(error.message, true);
  }
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
  if (headerUserEl) {
    headerUserEl.hidden = !signedIn;
  }
  if (vaultSelectorRow) {
    vaultSelectorRow.hidden = !signedIn;
  }
  renderSharedVaultList();
  updateSelectedVaultName();
}

function updateSelectedVaultName() {
  if (!selectedVaultNameEl || !state.token) {
    return;
  }

  let name = state.activeSharedVault?.name;
  if (!name && state.selectedSharedVaultId) {
    name = 'Shared vault';
  }
  if (!name && !state.selectedSharedVaultId) {
    name = 'Personal vault';
  }

  if (!name) {
    selectedVaultNameEl.hidden = true;
    return;
  }

  selectedVaultNameEl.textContent = name;
  selectedVaultNameEl.hidden = false;
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

  if (personalVaultButton) {
    personalVaultButton.classList.toggle('selected', !state.selectedSharedVaultId);
  }

  if (!hasVaults) {
    updateSharedVaultEditorVisibility();
    return;
  }

  state.sharedVaults.forEach((vault) => {
    const item = document.createElement('div');
    item.className = 'shared-vault-item';
    if (state.selectedSharedVaultId === vault.id) {
      item.classList.add('selected');
    }

    const mainButton = document.createElement('button');
    mainButton.type = 'button';
    mainButton.className = 'shared-vault-item-main';
    const statusText = vault.status ? `${vault.status}` : vault.role ?? 'member';
    mainButton.innerHTML = `
      <span>${escapeHtml(vault.name)}</span>
      <span class="shared-vault-item-meta">${escapeHtml(statusText)}</span>
    `;
    mainButton.addEventListener('click', () =>
      selectSharedVault(vault)
        .catch((err) => setStatus(err.message, true))
        .finally(() => closeVaultModal())
    );
    item.appendChild(mainButton);

    const isOwner = vault.ownerId === state.userId;
    if (isOwner) {
      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'shared-vault-item-delete';
      deleteButton.textContent = 'Delete';
      deleteButton.addEventListener('click', (event) => {
        event.stopPropagation();
        deleteSharedVault(vault.id, vault.name).catch((err) => setStatus(err.message, true));
      });
      item.appendChild(deleteButton);
    }

    sharedVaultListEl.appendChild(item);
  });

  updateSharedVaultEditorVisibility();
}

function appendSharedVaultMemberRow(member = {}, { isOwner = false } = {}) {
  if (!sharedVaultMembersContainer) {
    return null;
  }

  const row = document.createElement('div');
  row.className = 'shared-vault-member-row';
  row.dataset.status = member.status ?? 'active';
  if (member.invitedBy) {
    row.dataset.invitedBy = member.invitedBy;
  }
  if (isOwner) {
    row.dataset.owner = 'true';
  }

  const input = document.createElement('input');
  input.placeholder = 'User ID';
  input.value = member.userId ?? '';
  if (isOwner) {
    input.readOnly = true;
    input.title = 'Owner identity cannot be changed';
  }

  const roleSelect = document.createElement('select');
  ['owner', 'admin', 'member', 'viewer'].forEach((role) => {
    const option = document.createElement('option');
    option.value = role;
    option.textContent = role.charAt(0).toUpperCase() + role.slice(1);
    roleSelect.appendChild(option);
  });
  roleSelect.value = member.role ?? (isOwner ? 'owner' : 'member');
  if (isOwner) {
    roleSelect.disabled = true;
  }

  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.textContent = 'Remove';
  removeButton.addEventListener('click', () => row.remove());
  if (isOwner) {
    removeButton.hidden = true;
  }

  row.append(input, roleSelect, removeButton);
  sharedVaultMembersContainer.appendChild(row);
  return row;
}

function renderSharedVaultEditor() {
  if (!sharedVaultEditor) {
    return;
  }

  const vault = state.activeSharedVault;
  const isOwner = vault && vault.ownerId === state.userId;
  if (!vault || !isOwner) {
    sharedVaultEditor.setAttribute('hidden', '');
    return;
  }

  sharedVaultEditor.removeAttribute('hidden');
  if (sharedVaultNameInput) {
    sharedVaultNameInput.value = vault.name ?? '';
  }
  if (sharedVaultMembersContainer) {
    sharedVaultMembersContainer.innerHTML = '';
    const memberMap = vault.memberKeys || {};
    Object.entries(memberMap).forEach(([userId, info]) => {
      appendSharedVaultMemberRow(
        {
          userId,
          role: info.role,
          status: info.status,
          invitedBy: info.invitedBy,
        },
        { isOwner: userId === vault.ownerId }
      );
    });
  }
}

function updateSharedVaultEditorVisibility() {
  const isOwner = state.activeSharedVault?.ownerId === state.userId;
  if (sharedVaultEditButton) {
    sharedVaultEditButton.hidden = !Boolean(isOwner);
  }
  if (!isOwner && sharedVaultEditor) {
    sharedVaultEditor.setAttribute('hidden', '');
  }
}

function collectSharedVaultMemberWrappers() {
  if (!sharedVaultMembersContainer) {
    return [];
  }

  const rows = Array.from(sharedVaultMembersContainer.children).filter(
    (row) => row instanceof HTMLElement
  );
  return rows
    .map((row) => {
      const input = row.querySelector('input');
      const select = row.querySelector('select');
      if (!input || !select) {
        return null;
      }
      const userId = input.value.trim();
      if (!userId) {
        return null;
      }
      return {
        userId,
        role: select.value,
        status: row.dataset.status ?? 'active',
        wrappedKey: state.sharedVaultKeyBase ?? state.activeSharedVault?.salt ?? '',
        invitedBy: row.dataset.invitedBy ?? state.userId,
      };
    })
    .filter(Boolean);
}

async function saveSharedVaultEditorChanges() {
  if (!state.activeSharedVault || !state.selectedSharedVaultId) {
    return;
  }

  const vaultId = state.selectedSharedVaultId;
  const name = sharedVaultNameInput?.value.trim();
  if (!name) {
    setStatus('Vault name is required', true);
    return;
  }

  const memberWrappers = collectSharedVaultMemberWrappers();
  if (!memberWrappers.some((member) => member.userId === state.userId)) {
    memberWrappers.push({
      userId: state.userId,
      role: 'owner',
      status: 'active',
      wrappedKey: state.sharedVaultKeyBase ?? state.activeSharedVault.salt ?? '',
      invitedBy: state.userId,
    });
  }

  try {
    await apiRequest(
      `/shared-vaults/${vaultId}`,
      {
        method: 'PATCH',
        body: JSON.stringify({
          name,
          memberWrappers,
        }),
      },
      true
    );
    setStatus('Shared vault updated');
    sharedVaultEditor?.setAttribute('hidden', '');
    await fetchSharedVaults();
    if (state.selectedSharedVaultId) {
      await loadSharedVault(state.selectedSharedVaultId);
    }
  } catch (error) {
    setStatus(`Failed to update shared vault: ${error.message}`, true);
  }
}

async function selectSharedVault(vault) {
  const vaultId = vault?.id ?? null;
  if (state.selectedSharedVaultId === vaultId) {
    state.selectedSharedVaultId = null;
    state.activeSharedVault = null;
    state.sharedVaultKeyBase = null;
    state.sharedVaultKey = null;
    renderSharedVaultList();
    updateSharedVaultEditorVisibility();
    await loadVault();
    updateSelectedVaultName();
    setStatus('Switched back to your personal vault');
    return;
  }

  state.selectedSharedVaultId = vaultId;
  state.activeSharedVault = null;
  renderSharedVaultList();
  if (!vaultId) {
    await loadVault();
    updateSelectedVaultName();
    setStatus('Switched back to your personal vault');
    return;
  }

  await loadSharedVault(vaultId);
}

async function deleteSharedVault(vaultId, vaultName = '') {
  if (!vaultId) {
    return;
  }

  const vault = state.sharedVaults.find((entry) => entry.id === vaultId);
  if (!vault) {
    return;
  }

  if (vault.ownerId !== state.userId) {
    setStatus('Only the owner can delete a shared vault', true);
    return;
  }

  const confirmed = confirm(
    `Delete shared vault "${vaultName || vault.name}" permanently? This cannot be undone.`
  );
  if (!confirmed) {
    return;
  }

  const wasSelected = state.selectedSharedVaultId === vaultId;
  state.sharedVaults = state.sharedVaults.filter((entry) => entry.id !== vaultId);
  if (wasSelected) {
    state.selectedSharedVaultId = null;
    state.activeSharedVault = null;
  }
  renderSharedVaultList();

  try {
    await apiRequest(`/shared-vaults/${vaultId}`, { method: 'DELETE' }, true);

    if (wasSelected) {
      await loadVault();
    } else {
      await fetchSharedVaults();
    }
    setStatus('Shared vault deleted');
  } catch (error) {
    setStatus(`Failed to delete shared vault: ${error.message}`, true);
  }
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
    updateSharedVaultEditorVisibility();
    updateSelectedVaultName();
  } catch (error) {
    state.activeSharedVault = null;
    updateSharedVaultEditorVisibility();
    updateSelectedVaultName();
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
  updateSharedVaultEditorVisibility();
  updateSelectedVaultName();
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
              <button type="button" data-action="auto-signin" class="${entry.autoSignIn ? 'active' : ''}">
                Auto-sign in ${entry.autoSignIn ? '• on' : ''}
              </button>
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
      savePendingCandidateToVault().catch((error) => setStatus(error.message, true));
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

  try {
    const response = await fetch(`${getApiBase()}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error ?? 'Network request failed');
    }

    return response.json();
  } catch (error) {
    if (fallbackToHttp()) {
      return apiRequest(path, options, withAuth);
    }
    throw error;
  }
}

async function handleAuthentication(mode) {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    setStatus('Username and password are required', true);
    return;
  }

  try {
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

    if (rememberPasswordInput?.checked) {
      saveRememberedCredentials(username, password);
    } else {
      clearRememberedCredentials();
    }

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

    const editingEntry = state.editingEntryId
      ? state.entries.find((item) => item.id === state.editingEntryId)
      : null;
    const entryPayload = {
      label,
      username: entryUsername.value.trim(),
      password: entryPassword.value,
      notes: entryNotes.value.trim(),
      url: entryUrl.value.trim(),
      otpSecret: entryOtpSecret.value.trim(),
      autoSignIn: editingEntry?.autoSignIn ?? false,
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

  if (action === 'auto-signin') {
    entry.autoSignIn = !entry.autoSignIn;
    renderEntries();
    persistVault().catch((error) => setStatus(`Failed to update auto sign-in: ${error.message}`, true));
    setStatus(entry.autoSignIn ? 'Auto sign-in enabled for this entry' : 'Auto sign-in disabled for this entry');
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

msSsoButton?.addEventListener('click', startMicrosoftSSO);
customApiSaveButton?.addEventListener('click', () => {
  const value = customApiInput?.value?.trim();
  if (!value) {
    setStatus('Enter a valid API endpoint URL', true);
    return;
  }
  applyCustomApiBase(value);
  persistCustomApiBase();
  setStatus('Custom API endpoint saved');
  loadMsSsoConfig().catch(() => {});
});

customApiResetButton?.addEventListener('click', () => {
  applyCustomApiBase(null);
  persistCustomApiBase();
  setStatus('Using default localhost endpoint');
  loadMsSsoConfig().catch(() => {});
});

logoutBtn.addEventListener('click', async () => {
  try {
    await apiRequest('/logout', { method: 'POST' }, true);
  } catch (error) {
    console.warn('Logout audit failed', error);
  }
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

scanOtpButton?.addEventListener('click', () => {
  const scanUrl = chrome.runtime.getURL('otp-scan.html');
  window.open(scanUrl, 'otp-scan', 'width=440,height=640');
});

vaultModalToggle?.addEventListener('click', (event) => {
  event.preventDefault();
  openVaultModal();
});

personalVaultButton?.addEventListener('click', (event) => {
  event.preventDefault();
  selectSharedVault(null)
    .catch((err) => setStatus(err.message, true))
    .finally(() => closeVaultModal());
});

vaultModal?.addEventListener('click', (event) => {
  if (event.target === vaultModal) {
    closeVaultModal();
  }
});

vaultModalClose?.addEventListener('click', () => closeVaultModal());

sharedVaultEditButton?.addEventListener('click', () => {
  renderSharedVaultEditor();
});

sharedVaultAddMemberButton?.addEventListener('click', () => {
  appendSharedVaultMemberRow();
});

sharedVaultEditorCancel?.addEventListener('click', () => {
  sharedVaultEditor?.setAttribute('hidden', '');
});

sharedVaultEditorSave?.addEventListener('click', () => {
  saveSharedVaultEditorChanges();
});

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') {
    return;
  }

  if (state.vaultModalOpen) {
    closeVaultModal();
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

loadRememberedCredentials();

loadAutoLockPreference();
loadOtpScanResult();
loadCustomApiBase();
loadMsSsoConfig();
restoreSessionFromBackground().catch(() => {});

chrome.storage?.onChanged?.addListener?.((changes, area) => {
  if (area !== 'local') {
    return;
  }

  if (changes.pendingSave) {
    if (changes.pendingSave.newValue) {
      setPendingCandidate(changes.pendingSave.newValue);
    } else {
      clearPendingCandidate();
    }
  }

  if (changes.otpScanResult?.newValue) {
    if (entryOtpSecret) {
      entryOtpSecret.value = changes.otpScanResult.newValue;
      setStatus('OTP secret imported from scan');
    }
    chrome.storage.local.remove('otpScanResult');
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
