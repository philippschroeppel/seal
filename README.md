# seal

A small TypeScript library that lets a parent process grant a child **temporary, named access** to secrets — without ever handing the child a decryption key.

There are two child surfaces:

1. **Cooperating programs** may call `getSecret(name)` over a Unix socket and receive plaintext.
2. **Agent sessions** may only call loopback HTTP (`POST /v1/http`, `POST /v1/sign`). Seal performs the use after Cedar allows it. The agent never receives credential bytes.

The design constraints are in [`docs/handoff.md`](docs/handoff.md).

## Agent session (use, not read)

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
```

```bash
seal --manifest examples/agent/manifest.json -- agent
```

Seal starts an authorized loopback server, injects `SEAL_URL` and `SEAL_TOKEN` only, spawns the child, and tears down on exit. A plugin talks to Seal, not to GitHub with a raw token:

```ts
import { agent } from "seal";

export async function createPullRequest(repo: string, body: unknown) {
  return agent.http({
    identity: "gh-token",
    method: "POST",
    url: `https://api.github.com/repos/${repo}/pulls`,
    body,
  });
}
```

`GET /v1/capabilities` (and `/v1/openapi.json`) describe what the session may do. Those answers are probed from the same Cedar policies that gate each call. There is no `GET /secrets`.

## How the kernel works

```
┌──────────────────── parent ────────────────────┐
│  MemorySecretStore                             │
│    secret ──► random DEK ──► AES-256-GCM       │
│                                                │
│  grant: wrap each DEK to the broker's X25519   │
│         public key (sealed box)                │
│                                                │
│  Unix socket  ◄── { token, name }  (scripts)   │
│  loopback HTTP◄── /v1/http, /v1/sign (agents)  │
│    1. check token + grant + Cedar              │
│    2. unseal DEK with broker secret key        │
│    3. use the value, wipe DEK                  │
└────────────────────────────────────────────────┘
```

A sealed box is ephemeral X25519 + HKDF-SHA-256 + ChaCha20-Poly1305. The child never sees a DEK or the broker key.

## Decisions

| Choice | Default |
| --- | --- |
| Shape | One package, a few modules — not a monorepo |
| Store | `SecretStore` interface + in-memory stand-in |
| Agent API | `startAgentSession` / `runWithManifest` + `agent.http` / `agent.sign` |
| Script API | `startBroker` / `runWithGrant` + `getSecret` |
| Policy | Cedar via `@cedar-policy/cedar-wasm` (one `isAuthorized` before unseal) |
| Manifest | JSON identity bindings + a `.cedar` file (Cedar does not store key paths) |
| Env names | `SEAL_URL` + `SEAL_TOKEN` for agents; `SEAL_SOCK` + `SEAL_TOKEN` for scripts |
| Crypto | Noble v2 throughout, including AES-GCM for payloads |
| Tooling | ESM, TypeScript `NodeNext`, Node 20.19+, Vitest, Biome, `tsx` |

## Quick start

```bash
npm install
npm test
npm run demo
npm run demo:agent
```

`demo` grants `db/password` for two seconds over the Unix socket. `demo:agent` starts a mock peer and shows HTTP use, a Cedar deny, a detached `getSecret`, and an approved signature.

## Library usage

Agent session:

```ts
import { agent, MemorySecretStore, runWithManifest } from "seal";

const store = new MemorySecretStore();
store.put("gh-token", process.env.GITHUB_TOKEN ?? "");

await runWithManifest({
  store,
  manifest,
  command: process.execPath,
  args: ["agent.js"],
});
```

Cooperating script (plaintext, on purpose):

```ts
import { MemorySecretStore, runWithGrant, getSecret } from "seal";

const store = new MemorySecretStore();
store.put("db/password", "hunter2");

await runWithGrant({
  store,
  secretNames: ["db/password"],
  ttlMs: 2_000,
  command: process.execPath,
  args: ["worker.js"],
});
```

`startAgentSession` and `startBroker` are the same grants without spawning.

## Module map

| File | Role |
| --- | --- |
| `src/seal.ts` | Sealed-box wrap / unwrap |
| `src/store.ts` | Encrypt-at-rest + grants |
| `src/broker.ts` | Unix socket, TTL, child spawn |
| `src/agent.ts` | Loopback HTTP session, Cedar gate, use-not-read |
| `src/pdp.ts` | Cedar WASM PDP |
| `src/client.ts` / `src/agent-client.ts` | What a child calls |
| `src/cli.ts` | `seal --manifest … -- <cmd>` |
| `src/demo.ts` / `src/demo-agent.ts` | End-to-end walkthroughs |
| `examples/github-plugin.ts` | Unprivileged GitHub glue |

## Scripts

| Script | What it does |
| --- | --- |
| `npm test` | Unit + broker + agent tests |
| `npm run demo` | Unix-socket walkthrough |
| `npm run demo:agent` | Use-not-read walkthrough |
| `npm run build` | Emit `dist/` |
| `npm run lint` | Biome |
| `npm run typecheck` | `tsc --noEmit` |

## Security notes

- Agent sessions authorize **use**, not disclosure. A live `gh-token` can still push or create keys unless Cedar forbids those paths.
- Peer prefixes on an identity are a second gate: `/v1/http` is refused unless the URL is bound to that identity.
- The session token is in the child's environment. Anyone who can read that env can propose uses until expiry.
- Child env is stripped of `SEAL_SOCK` and common token variables. This is not a network namespace.
- `wipe()` is best-effort. JavaScript runtimes can copy bytes.
- `MemorySecretStore` keeps DEKs in process memory for its lifetime. Treat it as a stand-in.
- Response bodies are not redacted. Policy must know dangerous fields.
