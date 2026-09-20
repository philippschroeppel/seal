# Seal — vault design

Seal is a small vault: named secrets, a session, pre-task grant, mid-task passphrase grant, and three agent calls. Plugins run inside Seal with the unsealed secret. The agent never receives credential bytes.

```
agent                      untrusted, speaks HTTP only
  │  use / put / request
  ▼
Seal session               grant check, consent, wipe
  │
  ▼
built-in plugin            ssh | http | sign
  │  (unsealed secret)
  ▼
peer / signature
```

```bash
seal --manifest examples/agent/manifest.json -- agent
```

## Agent calls

| Call | Role |
| --- | --- |
| `POST /v1/use` | `{ plugin, identity, input }` — unseal, run plugin, return plugin result |
| `POST /v1/put` | `{ name, plugin?, peers?, format? }` — human types the value; stored, **not** granted |
| `POST /v1/request` | `{ name, ... }` — passphrase consent to grant a name the session does not have |

A secret the agent `put`s is treated like a secret it was never granted at start: `use` fails until `request` succeeds.

Consent is entering a passphrase, not `[y/N]`. If the name is not in the store, the human also types the secret.

## Built-in plugins

| Plugin | Input | What Seal does |
| --- | --- | --- |
| `ssh` | `{ op: "sign", payload, namespace? }` or `{ op: "publicKey" }` | OpenSSH ed25519; git SSHSIG |
| `http` | `{ method, url, headers?, body? }` | attach bearer, fetch allowlisted peer |
| `sign` | `{ payload, format }` | hmac-sha256 or ed25519 |

GitHub is not a plugin. An agent-side helper calls `http` with `peers: ["https://api.github.com/"]`.

Plugins are registered in-process. Seal does not load user modules.

## What was removed

Cedar, OpenAPI, `getSecret` / the Unix-socket disclosure broker, sealed-box DEK wrapping, and kernel `http`/`sign` endpoints. Peer prefixes stay as identity/plugin config. Bubblewrap stays as opt-in confinement.
