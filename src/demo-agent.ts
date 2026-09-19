import { createServer, type Server } from "node:http";
import { runWithManifest } from "./agent.js";
import { agent } from "./agent-client.js";
import { getSecret } from "./client.js";
import { isSealError } from "./errors.js";
import type { Manifest } from "./manifest.js";
import { MemorySecretStore } from "./store.js";

const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "demo-hmac-key";

async function runAsChild(): Promise<void> {
  const caps = await agent.capabilities();
  console.log("[child] capabilities:", JSON.stringify(caps.identities));

  console.log("[child] use-not-read HTTP to the allowlisted peer...");
  const allowed = await agent.http({
    identity: "gh-token",
    method: "GET",
    url: `${requiredEnv("PEER_URL")}/repos/acme/seal/issues`,
  });
  console.log("[child] peer status", allowed.status, "body", allowed.body);
  if (allowed.body.includes(TOKEN)) {
    console.log("[child] leaked the token into the agent response");
  }

  console.log("[child] forbidden path /user/keys...");
  try {
    await agent.http({
      identity: "gh-token",
      method: "GET",
      url: `${requiredEnv("PEER_URL")}/user/keys`,
    });
    console.log("[child] unexpectedly allowed /user/keys");
  } catch (error) {
    console.log("[child] correctly denied:", describe(error));
  }

  console.log("[child] getSecret should not be attached...");
  try {
    await getSecret("gh-token");
    console.log("[child] unexpectedly received plaintext");
  } catch (error) {
    console.log("[child] correctly detached:", describe(error));
  }

  console.log("[child] sign with approval...");
  const signed = await agent.sign({
    identity: "me-sign",
    payload: "deadbeef",
    format: "hmac-sha256",
  });
  console.log("[child] signature", signed.signature);
}

async function runAsCli(): Promise<void> {
  const peer = await startPeer();
  try {
    const store = new MemorySecretStore();
    store.put("gh-token", TOKEN);
    store.put("me-sign", SIGNING_KEY);

    const self = process.argv[1];
    if (!self) {
      throw new Error(
        "cannot re-invoke this program: process.argv[1] is missing",
      );
    }

    const manifest = demoManifest(peer.url);
    console.log("[cli] starting an agent session (use, not read)...\n");

    const { exitCode } = await runWithManifest({
      store,
      manifest,
      command: process.execPath,
      args: [...process.execArgv, self, "child"],
      env: { PEER_URL: peer.url },
      approve: async () => true,
    });

    console.log(`\n[cli] child exited with code ${exitCode}`);
  } finally {
    peer.close();
  }
}

function demoManifest(peerUrl: string): Manifest {
  return {
    ttlMs: 10_000,
    policies: `
permit (
  principal is Seal::Agent,
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "${peerUrl}/repos/acme/seal/*"
  && ["GET", "POST"].contains(context.method)
};

forbid (
  principal,
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "${peerUrl}/user/keys*"
};

permit (
  principal is Seal::Agent,
  action == Seal::Action::"Sign",
  resource == Seal::Identity::"me-sign"
) when {
  context.userApproved == true
};
`,
    identities: [
      {
        name: "gh-token",
        secret: "gh-token",
        attach: { type: "bearer" },
        peers: [peerUrl],
      },
      {
        name: "me-sign",
        secret: "me-sign",
        attach: { type: "hmac-sha256" },
        approve: "each",
      },
    ],
  };
}

function startPeer(): Promise<{ url: string; close: () => void }> {
  const server = createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) {
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
