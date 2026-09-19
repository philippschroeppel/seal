# seal

A small TypeScript library that lets a parent process grant a child **temporary, named access** to secrets — without ever handing the child a decryption key.

The parent holds the unsealing key and serves plaintext over a local Unix socket. The grant is a subset of secrets, a TTL, and a bearer token. When the TTL elapses the key is wiped and further requests fail.

This is an architecture demo, not a production secret manager.

## How it works

```
┌──────────────────── parent ────────────────────┐
│  MemorySecretStore                             │
│    secret ──► random DEK ──► AES-256-GCM       │
│                                                │
│  grant: wrap each DEK to the broker's X25519   │
│         public key (sealed box)                │
│                                                │
│  Unix socket  ◄── { token, name }              │
│    1. check token + grant + name               │
│    2. unseal DEK with broker secret key        │
│    3. decrypt value, wipe DEK, return plaintext│
└────────────────────────────────────────────────┘
         ▲
         │ SEAL_SOCK + SEAL_TOKEN
         │
    cooperating child
    getSecret("db/password")
```

A sealed box is ephemeral X25519 + HKDF-SHA-256 + ChaCha20-Poly1305. The child never sees a DEK or the broker key.

## Decisions

The draft was a single file. A few choices were settled so the split could stay small:

| Choice | Default |
| --- | --- |
| Shape | One package, a few modules — not a monorepo |
| Store | `SecretStore` interface + in-memory stand-in (the DEK would live in a KMS in production) |
| Public API | `startBroker` / `runWithGrant` for the parent, `getSecret` for the child |
| Wire format | Line-delimited JSON with `{ ok: true, value }` / `{ ok: false, error, message }` |
| Env names | `SEAL_SOCK`, `SEAL_TOKEN` |
| Crypto | Noble v2 throughout, including AES-GCM for payloads |
| TTL | Revoke + wipe the key; leave the socket up so the child gets `grant_expired` |
| Tooling | ESM, TypeScript `NodeNext`, Node 20.19+, Vitest, Biome, `tsx` |

Those are easy to change if you want a different split (separate client package, a real backend, etc.).

## Quick start

```bash
npm install
npm test
npm run demo
```

The demo grants `db/password` for two seconds, denies `db/root-password`, then shows the TTL taking effect.

## Library usage

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

In the child:

```ts
import { getSecret } from "seal";

const password = await getSecret("db/password");
```

`startBroker` is the same grant + socket without spawning, which is what the tests use.

## Module map

| File | Role |
| --- | --- |
| `src/seal.ts` | Sealed-box wrap / unwrap |
| `src/store.ts` | Encrypt-at-rest + grants |
| `src/broker.ts` | Unix socket, TTL, child spawn |
| `src/client.ts` | What a cooperating child calls |
| `src/protocol.ts` | Shared request / response types |
| `src/demo.ts` | End-to-end walkthrough |

## Scripts

| Script | What it does |
| --- | --- |
| `npm test` | Unit + broker tests |
| `npm run demo` | Run the walkthrough |
| `npm run build` | Emit `dist/` |
| `npm run lint` | Biome |
| `npm run typecheck` | `tsc --noEmit` |

## Security notes

- The child receives **plaintext** for names it was granted. Isolation is “this process, these names, this long” — not “the child cannot see secrets.”
- The bearer token is in the child’s environment. Anyone who can read that env or connect to the socket with the token can ask for granted names until expiry.
- The socket is `0600` under `os.tmpdir()`.
- `wipe()` is best-effort. JavaScript runtimes can copy bytes; this is not constant-time memory hygiene.
- `MemorySecretStore` keeps DEKs in process memory for its lifetime. Treat it as a stand-in.
