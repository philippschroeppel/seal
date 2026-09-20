import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runWithManifest } from "./agent.js";
import { agent } from "./agent-client.js";
import { isSealError } from "./errors.js";
import type { Manifest } from "./manifest.js";
import { MemorySecretStore } from "./store.js";

const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "demo-hmac-key";
const EXTRA = "deposited-without-the-agent-seeing";

async function runAsChild(): Promise<void> {
  console.log("[child] ssh public key (no private material)...");
  const published = await agent.use<{
    publicKey: string;
    fingerprint: string;
  }>({
    plugin: "ssh",
    identity: "me-ssh",
    input: { op: "publicKey" },
  });
  console.log("[child] fingerprint", published.fingerprint);
  if (published.publicKey.includes("BEGIN OPENSSH")) {
    console.log("[child] leaked the private key into publicKey");
  }

  console.log("[child] git SSH signature...");
  const ssh = await agent.use<{ signature: string }>({
    plugin: "ssh",
    identity: "me-ssh",
    input: { op: "sign", namespace: "git", payload: "demo-commit" },
  });
  console.log("[child] sshsig", ssh.signature.split("\n")[0]);

  console.log("[child] use http on the pre-granted identity...");
  const allowed = await agent.use<{ status: number; body: string }>({
    plugin: "http",
    identity: "gh-token",
    input: {
      method: "GET",
      url: `${requiredEnv("PEER_URL")}/repos/acme/seal/issues`,
    },
  });
  console.log("[child] peer status", allowed.status, "body", allowed.body);
  if (allowed.body.includes(TOKEN)) {
    console.log("[child] leaked the token into the agent response");
  }

  console.log("[child] http outside the peer prefix...");
  try {
    await agent.use({
      plugin: "http",
      identity: "gh-token",
      input: {
        method: "GET",
        url: "https://example.com/user/keys",
      },
    });
    console.log("[child] unexpectedly allowed a foreign peer");
  } catch (error) {
    console.log("[child] correctly denied:", describe(error));
  }

  console.log("[child] sign with the pre-granted key...");
  const signed = await agent.use<{ signature: string }>({
    plugin: "sign",
    identity: "me-sign",
    input: { payload: "deadbeef", format: "hmac-sha256" },
  });
  console.log("[child] signature", signed.signature);

  console.log("[child] put a new secret (not granted)...");
  const deposited = await agent.put({
    name: "extra-token",
    plugin: "http",
    peers: [requiredEnv("PEER_URL")],
  });
  console.log("[child] stored", deposited.name);

  console.log("[child] use before request should fail...");
  try {
    await agent.use({
      plugin: "http",
      identity: "extra-token",
      input: {
        method: "GET",
        url: `${requiredEnv("PEER_URL")}/repos/acme/seal/issues`,
      },
    });
    console.log("[child] unexpectedly used an ungranted put secret");
  } catch (error) {
    console.log("[child] correctly ungranted:", describe(error));
  }

  console.log("[child] request access to the deposited secret...");
  const granted = await agent.request({
    name: "extra-token",
    reason: "need the extra token for the peer",
  });
  console.log("[child] granted", granted.name);

  const after = await agent.use<{ status: number; body: string }>({
    plugin: "http",
    identity: "extra-token",
    input: {
      method: "GET",
      url: `${requiredEnv("PEER_URL")}/repos/acme/seal/issues`,
    },
  });
  console.log("[child] extra-token status", after.status);
}

async function runAsCli(): Promise<void> {
  const peer = await startPeer();
  try {
    const store = new MemorySecretStore();
    store.put("gh-token", TOKEN);
    store.put("me-sign", SIGNING_KEY);
    store.put("me-ssh", generateDemoSshKey());

    const self = process.argv[1];
    if (!self) {
      throw new Error(
        "cannot re-invoke this program: process.argv[1] is missing",
      );
    }

    console.log("[cli] starting a vault session (use / put / request)...\n");

    const { exitCode } = await runWithManifest({
      store,
      manifest: demoManifest(peer.url),
      command: process.execPath,
      args: [...process.execArgv, self, "child"],
      env: { PEER_URL: peer.url },
      passphrase: "demo-pass",
      consent: async (intent) => ({
        granted: true,
        passphrase: "demo-pass",
        ...(intent.needsSecret ? { secret: EXTRA } : {}),
      }),
    });

    console.log(`\n[cli] child exited with code ${exitCode}`);
  } finally {
    peer.close();
  }
}

function demoManifest(peerUrl: string): Manifest {
  return {
    ttlMs: 10_000,
    identities: [
      {
        name: "gh-token",
        secret: "gh-token",
        plugins: ["http", "github"],
        peers: [peerUrl],
      },
      {
        name: "me-sign",
        secret: "me-sign",
        plugins: ["sign"],
        format: "hmac-sha256",
      },
      {
        name: "me-ssh",
        secret: "me-ssh",
        plugins: ["ssh"],
      },
    ],
  };
}

function startPeer(): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    const auth = req.headers.authorization;
    if (auth !== `Bearer ${TOKEN}` && auth !== `Bearer ${EXTRA}`) {
      res.writeHead(401);
      res.end("missing identity");
      return;
    }
    if (req.url === "/repos/acme/seal/issues") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, issues: [] }));
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });
  return listen(server);
}

function listen(server: Server): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind peer"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => {
          server.close();
        },
      });
    });
  });
}

function generateDemoSshKey(): string {
  const dir = mkdtempSync(join(tmpdir(), "seal-demo-ssh-"));
  const file = join(dir, "id_ed25519");
  const result = spawnSync(
    "ssh-keygen",
    ["-t", "ed25519", "-f", file, "-N", "", "-C", "seal-demo", "-q"],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(result.stderr || "ssh-keygen failed");
  }
  return readFileSync(file, "utf8");
}

function describe(error: unknown): string {
  if (isSealError(error)) {
    return `${error.code}: ${error.message}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing ${name}`);
  }
  return value;
}

const mode = process.argv[2];
if (mode === "child") {
  await runAsChild();
} else {
  await runAsCli();
}
