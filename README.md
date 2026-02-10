# Zero Knowledge Password Manager

This workspace includes two halves:

- **Node.js backend (`server/`)** – Express + LowDB API that stores hashed credentials and ciphertext, but never sees your decrypted vault.
- **Chrome extension (`extension/`)** – UI, encryption helpers, and vault management that derive an AES-GCM key from your master password and keep all plaintext inside the browser.

## Server

1. `cd server`
2. `npm install`
3. `npm start`

The API runs at `http://localhost:4000`. It exposes:

- `POST /register` – creates a username with a bcrypt-hashed password.
- `POST /login` – returns a JWT.
- `GET /vault` & `POST /vault` – persist `encryptedVault`, `iv`, and `salt` for the authenticated user.
- `GET /shared-vaults`, `GET /shared-vaults/:vaultId`, and `POST /shared-vaults` – manage shared vault ciphertext plus per-user wrapped keys.
- `POST /shared-vaults/:vaultId` – update an existing shared vault (ciphertext + member wrappers).
- **Admin UI** – open `http://localhost:4000/admin` to reach the React-based shared-vault dashboard that lists vaults, shows members, and allows creating/inviting via your JWT.

Set `JWT_SECRET` (and optionally `PORT`) via environment variables before starting the server for production.

## Chrome Extension

1. Open `chrome://extensions/`.
2. Enable *Developer mode*.
3. Click *Load unpacked* and select the `extension/` folder.
4. Click the extension icon to register/log in using the API running on `localhost`.

The popup:

- Derives an AES-GCM key from your master password + salt.
- Encrypts/decrypts vault data locally using Web Crypto (`PBKDF2` → `AES-GCM`).
- Pushes/pulls ciphertext only when saving or fetching from the Node.js backend.
- Lets you associate entries with a site URL and an optional OTP secret that generates TOTP codes directly inside the popup, auto-fills saved credentials/OTP any time you visit the matching site, hides passwords until you hold the “Show” control, and offers a built-in strong-password generator plus a prompt to save new/changed passwords detected during form submissions.
- Supports in-popup entry editing, deletion, and clipboard copying, plus a five-minute auto-lock timer that clears decrypted data when idle.

## Zero Knowledge Notes

- Master passwords never leave the browser once entered (the server only sees a bcrypt hash).
- Vault contents stay encrypted while in transit and at rest on the server; only the extension can decrypt them.
- Salt and IV values are stored alongside ciphertext but reveal nothing about the plaintext.

## Shared Vault Model & API

These additions store shared encrypted vaults alongside the per-user vaults (`sharedVaults` in `db.json`) and expose a matching REST surface.

### Shared vault schema

Each shared vault holds the ciphertext/IV/salt for the shared data plus metadata about who can open it:

```jsonc
{
  "id": "vault_abc123",
  "name": "Team Vault",
  "ownerId": "user_john",
  "version": 1,
  "updatedAt": "2026-02-10T12:00:00.000Z",
  "encryptedVault": "base64-ciphertext",
  "iv": "base64-iv",
  "salt": "base64-salt",
  "memberKeys": {
    "user_john": {
      "wrappedKey": "base64-key",
      "role": "owner",
      "status": "active",
      "invitedBy": "user_john",
      "invitedAt": "2026-02-10T12:00:00.000Z"
    },
    "user_anna": {
      "wrappedKey": "base64-key",
      "role": "admin",
      "status": "active",
      "invitedBy": "user_john",
      "invitedAt": "2026-02-10T12:05:00.000Z"
    }
  }
}
```

`memberKeys` maps each collaborator to a wrapped shared-key blob plus role/status flags so new members can receive the vault key without decrypting everyone’s data. The owner retains the ability to invite, remove, or rotate the shared vault key.

### API payloads

All endpoints require `Authorization: Bearer <token>`.

#### `GET /shared-vaults`

- **Response**

```json
{
  "sharedVaults": [
    {
      "id": "vault_abc123",
      "name": "Team Vault",
      "ownerId": "user_john",
      "role": "admin",
      "status": "active",
      "wrappedKey": "base64-key",
      "updatedAt": "2026-02-10T12:00:00.000Z"
    }
  ]
}
```

Clients should use the returned `wrappedKey` to derive the shared AES key before decrypting the vault payload.

#### `POST /shared-vaults`

- **Request**

```json
{
  "name": "Team Vault",
  "encryptedVault": "...",
  "iv": "...",
  "salt": "...",
  "memberWrappers": [
    { "userId": "user_john", "wrappedKey": "...", "role": "owner" },
    { "userId": "user_anna", "wrappedKey": "...", "role": "admin" }
  ]
}
```

- **Response**

```json
{
  "vaultId": "vault_abc123",
  "updatedAt": "2026-02-10T12:00:00.000Z",
  "version": 1
}
```

#### `GET /shared-vaults/:vaultId`

- **Response**

```json
{
  "vault": {
    "id": "vault_abc123",
    "name": "Team Vault",
    "encryptedVault": "...",
    "iv": "...",
    "salt": "...",
    "version": 1,
    "updatedAt": "2026-02-10T12:00:00.000Z",
    "members": [
      { "userId": "user_john", "role": "owner", "status": "active" },
      { "userId": "user_anna", "role": "admin", "status": "active" }
    ],
    "wrappedKey": "..."
  }
}
```

#### `POST /shared-vaults/:vaultId`

- **Request:** same shape as the creation request (ciphertext + member wrappers) but only allowed for `active` members with edit rights.

#### `POST /shared-vaults/:vaultId/invite`

- **Request**

```json
{
  "userId": "user_mike",
  "wrappedKey": "...",
  "role": "editor"
}
```

- **Response**

```json
{ "memberId": "user_mike", "status": "invited" }
```

#### `POST /shared-vaults/:vaultId/members/:memberId/accept`

- Marks an invitation as `active`.
#### `POST /shared-vaults/:vaultId/members/:memberId/remove`

- Revokes access and (optionally) triggers a key rotation so remaining members receive new `wrappedKey` material.
