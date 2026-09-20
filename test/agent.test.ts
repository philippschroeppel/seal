import { createServer, type IncomingMessage, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  type AgentSession,
  runWithManifest,
  startAgentSession,
} from "../src/agent.js";
import { agent } from "../src/agent-client.js";
import type { SealError } from "../src/errors.js";
import type { Manifest } from "../src/manifest.js";
import { MemorySecretStore } from "../src/store.js";

const probePath = fileURLToPath(new URL("./agent-probe.ts", import.meta.url));
const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "unit-test-hmac-key";
const PASS = "session-pass";

const sessions: AgentSession[] = [];
const servers: Server[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    session.close();
  }
  for (const server of servers.splice(0)) {
    server.close();
  }
});

describe("agent session", () => {
  it("uses a granted identity through a plugin and never returns the secret", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);

    const result = await agent.use<{
      status: number;
      body: string;
    }>(
      {
        plugin: "http",
        identity: "gh-token",
        input: {
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
      },
      session,
    );

    expect(result.status).toBe(200);
    expect(JSON.parse(result.body)).toEqual({ ok: true, issues: [] });
    expect(result.body).not.toContain(TOKEN);
    expect(peer.seen.at(-1)?.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("refuses a foreign peer and /secrets", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "gh-token",
          input: { method: "GET", url: "https://example.com/user/keys" },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "forbidden" } satisfies Partial<SealError>);
    expect(peer.seen).toHaveLength(0);

    const denied = await fetch(`${session.url}/secrets/gh-token`, {
      headers: { authorization: `Bearer ${session.token}` },
    });
    expect(denied.status).toBe(404);
    const body = (await denied.json()) as { error: string };
    expect(body.error).toBe("not_granted");
  });

  it("signs a payload without returning the key", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);
    const signature = await agent.use<{ signature: string }>(
      {
        plugin: "sign",
        identity: "me-sign",
        input: { payload: "digest", format: "hmac-sha256" },
      },
      session,
    );
    expect(signature.signature).toMatch(/^[0-9a-f]+$/);
    expect(signature.signature).not.toContain(SIGNING_KEY);
  });

  it("stores a put secret without granting it until request", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url, async (intent) => ({
      granted: true,
      passphrase: PASS,
      ...(intent.needsSecret ? { secret: TOKEN } : {}),
    }));

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "extra-token",
          input: {
            method: "GET",
            url: `${peer.url}/repos/acme/seal/issues`,
          },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "not_granted" });

    const put = await agent.put(
      { name: "extra-token", plugin: "http", peers: [peer.url] },
      session,
    );
    expect(put).toEqual({ name: "extra-token" });

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "extra-token",
          input: {
            method: "GET",
            url: `${peer.url}/repos/acme/seal/issues`,
          },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "not_granted" });

    const granted = await agent.request({ name: "extra-token" }, session);
    expect(granted).toEqual({ granted: true, name: "extra-token" });

    const result = await agent.use<{ status: number }>(
      {
        plugin: "http",
        identity: "extra-token",
        input: {
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
      },
      session,
    );
    expect(result.status).toBe(200);
    expect(peer.seen.at(-1)?.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("grants a brand-new name through request after a passphrase", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url, async (intent) => ({
      granted: true,
      passphrase: PASS,
      ...(intent.needsSecret ? { secret: TOKEN } : {}),
    }));

    await agent.request(
      {
        name: "fresh-token",
        plugin: "http",
        peers: [peer.url],
        reason: "need a new token",
      },
      session,
    );

    const result = await agent.use<{ status: number }>(
      {
        plugin: "http",
        identity: "fresh-token",
        input: {
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
      },
      session,
    );
    expect(result.status).toBe(200);
  });

  it("rejects a wrong passphrase and a value field from the agent", async () => {
    const peer = await openPeer();
    const session = await startAgentSession({
      store: seededStore(),
      manifest: testManifest(peer.url),
      passphrase: PASS,
      consent: async () => ({
        granted: true,
        passphrase: "nope",
        secret: TOKEN,
      }),
    });
    sessions.push(session);

    await expect(
      agent.request({ name: "fresh-token", plugin: "http" }, session),
    ).rejects.toMatchObject({ code: "approval_required" });

    const raw = await fetch(`${session.url}/v1/put`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${session.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ name: "leaked", value: "hunter2" }),
    });
    expect(raw.status).toBe(400);
    expect(await raw.json()).toMatchObject({ error: "bad_request" });
  });

  it("rejects a request with the wrong token and after TTL", async () => {
    const peer = await openPeer();
    const session = await startAgentSession({
      store: seededStore(),
      manifest: testManifest(peer.url),
      ttlMs: 40,
      passphrase: PASS,
      consent: async () => ({ granted: true, passphrase: PASS }),
    });
    sessions.push(session);

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "gh-token",
          input: {
            method: "GET",
            url: `${peer.url}/repos/acme/seal/issues`,
          },
        },
        { url: session.url, token: "nope" },
      ),
    ).rejects.toMatchObject({ code: "unauthorized" });

    await new Promise((resolve) => setTimeout(resolve, 50));
    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "gh-token",
          input: {
            method: "GET",
            url: `${peer.url}/repos/acme/seal/issues`,
          },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "grant_expired" });
  });

  it("strips secret env from the child and refuses leftover disclosure paths", async () => {
    const peer = await openPeer();
    const result = await runWithManifest({
      store: seededStore(),
      manifest: testManifest(peer.url),
      command: process.execPath,
      args: ["--import", "tsx", probePath, "env"],
      stdio: "pipe",
      env: { GITHUB_TOKEN: TOKEN },
      passphrase: PASS,
      consent: async () => ({ granted: true, passphrase: PASS }),
    });

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      ok: true,
      hasUrl: true,
      hasToken: true,
      hasSock: false,
      hasGithubToken: false,
    });
  });

  it("lets a child perform http through SEAL_URL", async () => {
    const peer = await openPeer();
    const result = await runWithManifest({
      store: seededStore(),
      manifest: testManifest(peer.url),
      command: process.execPath,
      args: [
        "--import",
        "tsx",
        probePath,
        "http",
        `${peer.url}/repos/acme/seal/issues`,
      ],
      stdio: "pipe",
      passphrase: PASS,
      consent: async () => ({ granted: true, passphrase: PASS }),
    });

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      ok: true,
      status: 200,
      body: JSON.stringify({ ok: true, issues: [] }),
    });
    expect(peer.seen.at(-1)?.authorization).toBe(`Bearer ${TOKEN}`);
  });
});

async function openSession(
  peerUrl: string,
  consent: (intent: { op: string; needsSecret: boolean }) => Promise<{
    granted: boolean;
    passphrase: string;
    secret?: string;
  }> = async () => ({
    granted: true,
    passphrase: PASS,
  }),
): Promise<AgentSession> {
  const session = await startAgentSession({
    store: seededStore(),
    manifest: testManifest(peerUrl),
    passphrase: PASS,
    consent,
  });
  sessions.push(session);
  return session;
}

function seededStore(): MemorySecretStore {
  const store = new MemorySecretStore();
  store.put("gh-token", TOKEN);
  store.put("me-sign", SIGNING_KEY);
  return store;
}

function testManifest(peerUrl: string): Manifest {
  return {
    ttlMs: 5_000,
    sessionId: "session-1",
    identities: [
      {
        name: "gh-token",
        secret: "gh-token",
        source: { env: "GITHUB_TOKEN" },
        plugins: ["http", "github"],
        peers: [peerUrl],
      },
      {
        name: "me-sign",
        secret: "me-sign",
        plugins: ["sign"],
        format: "hmac-sha256",
      },
    ],
  };
}

interface TestPeer {
  readonly url: string;
  readonly seen: { authorization?: string; url?: string }[];
}

function openPeer(): Promise<TestPeer> {
  const seen: { authorization?: string; url?: string }[] = [];
  const server = createServer((req: IncomingMessage, res) => {
    seen.push({
      ...(typeof req.headers.authorization === "string"
        ? { authorization: req.headers.authorization }
        : {}),
      ...(req.url ? { url: req.url } : {}),
    });
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
  servers.push(server);

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind peer"));
        return;
      }
      resolve({ url: `http://127.0.0.1:${addr.port}`, seen });
    });
  });
}
