# Seal — design handoff

This is the working design for what Seal should become. The code on this branch is a **typed demo of the crypto/grant broker**, not the product below. Read this first if you are continuing the work; then read the current code as the kernel that still applies (store, sealed box, TTL, process wrap).

## Origin

The first constraint was GPG: require signed commits so an agent cannot produce a valid commit unless the human (who holds the passphrase) allows the signature. That is two properties mixed together:

1. **Non-disclosure** — the key never enters the agent (or its transcript).
2. **Human gate** — some uses still need a live approval (passphrase, touch, prompt).

Seal generalizes that to other identities (tokens, SSH keys) and other uses (HTTP, signing), without turning into a catalog of Git/SSH/GitHub features.

The intended UX:

```bash
seal --manifest permissions.cedar -- agent
```

Everything after `--` is the child. Seal starts an authorized local HTTP server, injects `SEAL_URL` and `SEAL_TOKEN`, spawns the agent, tears down on exit.

## Problem with the current demo

Today a cooperating child calls `getSecret(name)` and receives **plaintext**. That is the right API for a script. It is the wrong API for an LLM agent: once a value is in tool results, traces, or the next prompt, it is not a secret.

A grant should authorize **use**, not **disclosure**.

Do not “fix” this by substituting placeholders into the agent’s own argv/env. If the agent can inspect that process, or place `{{secret}}` in a URL it controls, the secret is gone. Substitution only works in a process the agent cannot observe, or (better) never happens: Seal performs the use itself.

## Target shape

```
agent  +  plugins          untrusted, speak HTTP only
        │
        ▼
Seal HTTP server           the only child surface
        │
        ▼
Cedar (PDP)                permit / forbid
        │
        ▼
Seal (PEP)                 on Allow: unseal, use identity, wipe
                           on Deny:  403, no key material
        │
        ▼
peers / signing backends   GitHub, git, YubiKey, …
```

| Layer | Job |
| --- | --- |
| Agent + plugins | Propose work; never receive credential bytes |
| Seal HTTP | Session, token, structured intents |
| Cedar | *May* this principal do this action on this identity, in this context? |
| Seal broker | Unwrap DEK / talk to gpg / attach header / sign; wipe |
| Manifest | Policy (Cedar), not a git config |

Cedar does not hold keys. Seal does not become a policy language. Plugins are not loaded into Seal and are not a trust boundary.

## Generic kernel (no domain modules)

Seal’s closed set is **ops**, not products:

| Op | Meaning |
| --- | --- |
| `http` | Seal performs an HTTP request to an allowlisted peer and attaches the bound identity |
| `sign` | Seal signs a digest with a signing identity; returns the signature |

Git, SSH, GitHub, Stripe, Postgres are **clients and peers**. They do not get first-class schema (`git.signCommits`, `ssh.hosts`). A new system is a new identity + peer + policy line, or an agent-side plugin that calls `http` / `sign`.

Well-known protocols (ssh-agent, SOCKS) may exist **inside** Seal later as backends (e.g. YubiKey via ssh-agent). They are not the API toward the agent.

A raw `sign(any bytes)` or `getSecret` RPC to the agent undoes the model (confused deputy / disclosure). Policy constrains identity, peer, payload class, and approval.

## Agent-native HTTP API

The child sees only loopback HTTP, authorized by the session token.

| Endpoint | Role |
| --- | --- |
| `GET /v1/capabilities` | What this session may do (identities, peers, ops). Also serve OpenAPI. |
| `POST /v1/http` | `{ identity, method, url, headers?, body? }` → Seal fetches, attaches creds, returns status/headers/body |
| `POST /v1/sign` | `{ identity, payload, format }` → signature |

Refuse:

- any `GET /secrets/…` or a `value` field that is the credential
- `/v1/http` unless the identity is bound to that peer prefix
- in-process “plugin host” (GitHub.wasm next to the keys). Domain logic stays unprivileged and outside the TCB

`approve: each` is either a blocking local prompt that sets context for Cedar, or `403` until the human approves a pending intent.

## Plugins

A plugin is agent-side glue (skill, MCP server, OpenAPI client) that **only** calls Seal:

```ts
export async function createPullRequest(repo, body) {
  return seal.http({
    identity: "gh-token",
    method: "POST",
    url: `https://api.github.com/repos/${repo}/pulls`,
    body,
  });
}

export async function signCommit(digest) {
  return seal.sign({ identity: "me-sign", payload: digest, format: "ssh" });
}
```

Unmodified `git` / `ssh` CLIs are optional and not the v1 success metric. They work only if a helper calls `/v1/sign` or `/v1/http`. That is acceptable if the primary user is an agent.

## Cedar

Cedar is the PDP behind those endpoints. The informal grant becomes:

| Informal | Cedar |
| --- | --- |
| this agent session | `principal` (`Seal::Agent::"session-…"`) |
| `http` / `sign` | `action` |
| `gh-token`, `me-sign` | `resource` (`Seal::Identity`) |
| URL, method, path | `context` (optional `Peer` entity) |
| human gate | `when { context.userApproved == true }` |
| TTL / revoke | principal/grant gone, or `context.now < expiresAt` |

Example:

```cedar
permit (
  principal == Seal::Agent::"session-1",
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "https://api.github.com/repos/philippschroeppel/seal/*"
  && context.method in ["GET", "POST"]
};

forbid (
  principal,
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "https://api.github.com/user/keys*"
};

permit (
  principal == Seal::Agent::"session-1",
  action == Seal::Action::"Sign",
  resource == Seal::Identity::"me-sign"
) when {
  context.userApproved == true
};
```

`GET /v1/capabilities` should be derived from the same policies, not a second schema.

Cedar does not replace: sealed box, listen/wipe/spawn, header binding, the prompt that sets `userApproved`, or talking to gpg/YubiKey.

## TypeScript + Cedar

Seal stays TypeScript. Cedar’s engine is Rust; official integration is WASM:

- [`@cedar-policy/cedar-wasm`](https://www.npmjs.com/package/@cedar-policy/cedar-wasm) — evaluator + TS types
- [`@cedar-policy/cedar-authorization`](https://www.npmjs.com/package/@cedar-policy/cedar-authorization) — `isAuthorized(...)`; can generate a Cedar schema from OpenAPI

Policies remain `.cedar` files. TypeScript types the HTTP intent; Cedar types the policy. Glue is one `isAuthorized` call **before** unseal.

For a local `seal -- agent` session, embed WASM (offline, keys stay on the machine). Prefer `@cedar-policy/cedar-wasm/nodejs` under Node ESM; Vitest may need the `web` + `initSync` path.

Amazon Verified Permissions is the same language as a remote PDP. It is optional and a worse default for this CLI (network, extra trust).

## Session lifecycle

1. Parse Cedar policies + identity bindings (where keys live, how to attach them).
2. Unlock what the human must unlock (passphrase / touch) **in Seal**, not in the agent.
3. Listen on loopback HTTP; chmod/restrict as we do for the Unix socket today.
4. Spawn the child with `SEAL_URL` + `SEAL_TOKEN` only — no `~/.ssh`, no `GNUPGHOME`, no token values.
5. Each call: authenticate → Cedar → use or 403.
6. On exit (and TTL): revoke, wipe, unlisten. Same story as `runWithGrant`.

## What is already built (this branch)

Typed ESM package: `src/seal.ts` (X25519 + HKDF + ChaCha20-Poly1305), `src/store.ts` (AES-GCM at rest + grants), `src/broker.ts` (`startBroker` / `runWithGrant`), `src/client.ts` (`getSecret`), demo that grants `db/password` for 2s.

Reusable later: injectable `SecretStore`, grant TTL/revoke, wipe after use, process wrap, fail-closed fetch.

To replace: `getSecret` as the agent API; Unix-socket JSON as the only protocol; “read these names” as the meaning of a grant.

How to read the current code: `src/demo.ts` → `src/types.ts` → `src/seal.ts` → `src/store.ts` → `src/broker.ts` → `src/client.ts`. Skip `index.ts` until the end.

## Suggested implementation order

1. Keep the store/seal/broker kernel; add a loopback HTTP server next to (or instead of) the Unix decrypt RPC for agent sessions.
2. `POST /v1/http` + `POST /v1/sign` with a **hard-coded allowlist** (no Cedar yet) so the use-not-read path is real.
3. Plug Cedar WASM as the PDP; move the allowlist into `.cedar` + a small schema.
4. `GET /v1/capabilities` / OpenAPI from that schema.
5. CLI: `seal --manifest … -- <cmd>`.
6. One example plugin (e.g. GitHub HTTP) that never calls `getSecret`.
7. Human-approval context for `sign` (the original GPG story).
8. Optional: ssh-agent **backend** inside Seal; still not exposed to the agent.

Keep `getSecret` only for non-agent cooperating programs, or drop it from agent sessions entirely.

## Decisions already locked

- Agent sessions: use, not read.
- One child surface: authorized HTTP.
- Plugins are unprivileged clients, not Seal modules.
- Kernel ops: `http` and `sign` (maybe `connect` later).
- Cedar for authorization; Seal for enforcement and crypto.
- TypeScript app + Cedar via WASM.
- `seal --manifest -- agent` as the UX.
- Verifiers outside the sandbox still matter (e.g. GitHub requires signatures). A wrapper the agent can bypass is not enough by itself.

## Open questions

- **Approval default for signing:** `each` (true “not without me”) vs session-unlock after one passphrase?
- **How far to confine the child:** env-only (cooperating) vs network namespace so all TCP goes through Seal?
- **Identity sources:** files + passphrase first, then gpg-agent / 1Password / YubiKey as backends?
- **Keep `getSecret` at all** for non-agent children?
- **Manifest split:** Cedar-only vs Cedar + a small JSON file for “where is this key and how do we attach it?” (Cedar should not store key paths or binding templates if we can avoid it.)

## Out of scope / non-goals

- Seal as a production secret manager or KMS.
- Domain-specific TypeScript (`git.ts`, `github.ts`) in the core.
- Printing credentials into traces the model will later read.
- Treating “use without seeing” as least privilege: a live `gh-token` can still push or create keys unless Cedar forbids those paths.
- Redacting secret-shaped **responses** (new PATs, `SELECT password`) — still unsolved; policy must know dangerous fields.

## Pointers

- Current package README: [`../README.md`](../README.md)
- Cedar: [cedarpolicy.com](https://www.cedarpolicy.com/), [`@cedar-policy/cedar-authorization`](https://www.npmjs.com/package/@cedar-policy/cedar-authorization)
- This repo’s existing PR implements the demo broker only.
