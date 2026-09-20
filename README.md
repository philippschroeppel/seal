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
import { signGit, sshPublicKey } from "./examples/ssh-plugin.ts";

await sshPublicKey();
await signGit(commitPayload);

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

## SSH keys (the main path)

The private key stays in the parent. The manifest only names the file:

```json
{
  "session": { "ttlMs": 300000 },
  "identities": [
    {
      "name": "me-ssh",
      "source": { "file": "~/.ssh/id_ed25519" },
      "plugins": ["ssh"]
    }
  ]
}
```

```bash
seal --manifest examples/agent/ssh.json -- agent
```

If the key is encrypted, Seal asks for **that key's passphrase** on first `use` — not `[y/N]`. The agent never receives the PEM.

```ts
import { signGit, sshPublicKey } from "./examples/ssh-plugin.ts";

const { publicKey, fingerprint } = await sshPublicKey();
const { signature } = await signGit(commitPayload);
```

`signature` is an OpenSSH `SSHSIG` (namespace `git` by default). `ssh-keygen -Y verify` accepts it. ed25519 only for now.

`--sandbox` hides host `~/.ssh` from the child, so the agent cannot open the file itself.

## Built-in plugins

| Plugin | Job |
| --- | --- |
| `ssh` | OpenSSH ed25519: public key + git SSH signatures |
| `http` | Fetch an allowlisted peer and attach a bearer token |
| `sign` | HMAC-SHA-256 or raw ed25519 over a payload |
| `github` | GitHub API (`path` or `createPullRequest`) |

`examples/ssh-plugin.ts` and `examples/github-plugin.ts` are agent-side glue. The plugins run inside Seal.

## Manifest

Pre-task grant is the identity list. Secrets come from a parent file/env (or `store.put`). `~` in `source.file` expands to `$HOME`.

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
| `src/plugins/` | Built-in ssh, http, sign, github |
| `src/ssh-key.ts` | OpenSSH parse / unlock / SSHSIG |
| `src/sandbox.ts` | bubblewrap jail |
| `src/cli.ts` | `seal --manifest … -- <cmd>` |
| `examples/ssh-plugin.ts` | Agent-side SSH helpers |

## Security notes

- Agent sessions authorize **use**, not disclosure. A live token can still do whatever its plugin allows.
- Peer prefixes on an identity are the http/github allowlist.
- The session token is in the child's environment.
- `wipe()` is best-effort. JavaScript runtimes can copy bytes.
- Response bodies are not redacted.
