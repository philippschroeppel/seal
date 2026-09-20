# seal

A small vault that holds secrets, takes passphrase consent, and lets an agent **use or deposit** values through plugins without seeing them.

```bash
seal --manifest examples/agent/manifest.json -- agent
```

Seal starts an authorized loopback server, injects `SEAL_URL` and `SEAL_TOKEN` only, spawns the child, and tears down on exit.

## Agent API

The child has three calls:

```ts
import { agent } from "seal";

await agent.use({
  plugin: "http",
  identity: "gh-token",
  input: { method: "GET", url: "https://api.github.com/user" },
});

await agent.put({ name: "deploy-token", plugin: "http", peers: ["https://api.example.com/"] });
await agent.request({ name: "deploy-token" });
```

| Call | What happens |
| --- | --- |
| `use` | Seal unseals the granted identity and runs a built-in plugin. The secret never comes back. |
| `put` | The human types a value into Seal. The name is stored and **not** granted. |
| `request` | Mid-task grant. The human types a passphrase. New names also take a secret value. |

A secret created with `put` is treated like one the user never granted at start. The agent must `request` it before `use`.

There is no `getSecret`. `/secrets` is 404.

## Built-in plugins

| Plugin | Job |
| --- | --- |
| `http` | Fetch an allowlisted peer and attach a bearer token |
| `sign` | HMAC-SHA-256 or ed25519 over a payload |
| `github` | GitHub API (`path` or `createPullRequest`) |

```ts
import { createPullRequest } from "./examples/github-plugin.ts";

await createPullRequest("acme/seal", {
  title: "demo",
  head: "feature",
  base: "main",
});
```

`examples/github-plugin.ts` is agent-side glue. The real github plugin runs inside Seal.

## Manifest

Pre-task grant is the identity list. Secrets come from env/file (or a parent `store.put`). No Cedar file.

```json
{
  "session": { "ttlMs": 300000 },
  "identities": [
    {
      "name": "gh-token",
      "source": { "env": "GITHUB_TOKEN" },
      "plugins": ["http", "github"],
      "peers": ["https://api.github.com/"]
    }
  ]
}
```

Mid-task, `request` can grant a name that was not in this list after the human enters a passphrase.

## Sandbox

`--sandbox` wraps the child in [bubblewrap](https://github.com/containers/bubblewrap) (Linux): empty `$HOME`, no host env, and by default `--unshare-net`. Seal listens on a Unix socket bind-mounted into the jail. Pass `--sandbox-network host` if the child must reach the network itself.

Without `--sandbox`, Seal only strips a few env keys. That is not a jail.

## Quick start

```bash
npm install
npm test
npm run demo:agent
```

## Library usage

```ts
import { agent, MemorySecretStore, runWithManifest } from "seal";

const store = new MemorySecretStore();
store.put("gh-token", process.env.GITHUB_TOKEN ?? "");

await runWithManifest({
  store,
  manifest,
  command: process.execPath,
  args: ["agent.js"],
  passphrase: "correct-horse",
  consent: async (intent) => ({
    granted: true,
    passphrase: "correct-horse",
    ...(intent.needsSecret ? { secret: "typed-into-seal" } : {}),
  }),
});
```

## Module map

| File | Role |
| --- | --- |
| `src/store.ts` | Named encrypt-at-rest vault |
| `src/session.ts` | Token, TTL, wipe |
| `src/agent.ts` | `use` / `put` / `request` |
| `src/plugins/` | Built-in http, sign, github |
| `src/sandbox.ts` | bubblewrap jail |
| `src/cli.ts` | `seal --manifest … -- <cmd>` |
| `examples/github-plugin.ts` | Agent-side GitHub helpers |

## Security notes

- Agent sessions authorize **use**, not disclosure. A live token can still do whatever its plugin allows.
- Peer prefixes on an identity are the http/github allowlist.
- The session token is in the child's environment.
- `wipe()` is best-effort. JavaScript runtimes can copy bytes.
- Response bodies are not redacted.
