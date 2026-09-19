import { createServer, type IncomingMessage, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  type AgentSession,
  runWithManifest,
  startAgentSession,
} from "../src/agent.js";
import { agent } from "../src/agent-client.js";
import { getSecret } from "../src/client.js";
import type { SealError } from "../src/errors.js";
import type { Manifest } from "../src/manifest.js";
import { MemorySecretStore } from "../src/store.js";

const probePath = fileURLToPath(new URL("./agent-probe.ts", import.meta.url));
const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "unit-test-hmac-key";

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
  it("attaches a credential to an allowlisted peer and never returns it", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);

    const result = await agent.http(
      {
        identity: "gh-token",
        method: "GET",
        url: `${peer.url}/repos/acme/seal/issues`,
      },
      session,
    );

    expect(result.status).toBe(200);
    expect(JSON.parse(result.body)).toEqual({ ok: true, issues: [] });
    expect(result.body).not.toContain(TOKEN);
    expect(peer.seen.at(-1)?.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("returns 403 for a forbidden path and for /secrets", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);

    await expect(
      agent.http(
        {
          identity: "gh-token",
          method: "GET",
          url: `${peer.url}/user/keys`,
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

  it("signs after approval and refuses without it", async () => {
    const peer = await openPeer();
    const denied = await startAgentSession({
      store: seededStore(),
      manifest: testManifest(peer.url),
      approve: async () => false,
    });
    sessions.push(denied);

    await expect(
      agent.sign(
        { identity: "me-sign", payload: "digest", format: "hmac-sha256" },
        denied,
      ),
    ).rejects.toMatchObject({
      code: "approval_required",
    } satisfies Partial<SealError>);

    const allowed = await openSession(peer.url, async () => true);
    const signature = await agent.sign(
      { identity: "me-sign", payload: "digest", format: "hmac-sha256" },
      allowed,
    );
    expect(signature.signature).toMatch(/^[0-9a-f]+$/);
    expect(signature.signature).not.toContain(SIGNING_KEY);
  });

  it("derives capabilities from Cedar and serves OpenAPI", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);
    const caps = await agent.capabilities(session);
    expect(caps.session).toBe(session.sessionId);
    expect(caps.identities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "gh-token", ops: ["http"] }),
        expect.objectContaining({
          name: "me-sign",
          ops: ["sign"],
          approve: "each",
        }),
      ]),
    );

    const spec = (await agent.openapi(session)) as {
      paths: Record<string, unknown>;
    };
    expect(spec.paths["/v1/http"]).toBeDefined();
    expect(spec.paths["/v1/sign"]).toBeDefined();
    expect(spec.paths["/v1/check"]).toBeDefined();
  });

  it("lists http from attach type without GitHub URL probes", async () => {
    const store = new MemorySecretStore();
    store.put("stripe", "sk_test");
    const session = await startAgentSession({
      store,
      manifest: {
        ttlMs: 5_000,
        policies: `permit (principal, action, resource);`,
        identities: [
          {
            name: "stripe",
            secret: "stripe",
            attach: { type: "bearer" },
            peers: ["https://api.stripe.com/"],
          },
        ],
      },
    });
    sessions.push(session);

    const caps = await agent.capabilities(session);
    expect(caps.identities).toEqual([
      expect.objectContaining({
        name: "stripe",
        ops: ["http"],
        peers: ["https://api.stripe.com/"],
      }),
    ]);
  });

  it("checks an intent against Cedar without unsealing", async () => {
    const peer = await openPeer();
    const session = await openSession(peer.url);

    await expect(
      agent.check(
        {
          op: "http",
          identity: "gh-token",
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
        session,
      ),
    ).resolves.toEqual({ allowed: true });

    await expect(
      agent.check(
        {
          op: "http",
          identity: "gh-token",
          method: "GET",
          url: `${peer.url}/user/keys`,
        },
        session,
      ),
    ).resolves.toEqual({ allowed: false, reason: "forbidden" });

    await expect(
      agent.check(
        { op: "sign", identity: "me-sign", format: "hmac-sha256" },
        session,
      ),
    ).resolves.toEqual({ allowed: false, reason: "approval_required" });

    expect(peer.seen).toHaveLength(0);
  });

  it("rejects a request with the wrong token and after TTL", async () => {
    const peer = await openPeer();
    const session = await startAgentSession({
      store: seededStore(),
      manifest: testManifest(peer.url),
      ttlMs: 40,
      approve: async () => true,
    });
    sessions.push(session);

    await expect(
      agent.http(
        {
          identity: "gh-token",
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
        { url: session.url, token: "nope" },
      ),
    ).rejects.toMatchObject({ code: "unauthorized" });

    await new Promise((resolve) => setTimeout(resolve, 50));
    await expect(
      agent.http(
        {
          identity: "gh-token",
          method: "GET",
          url: `${peer.url}/repos/acme/seal/issues`,
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "grant_expired" });
  });

  it("does not attach getSecret and strips secret env from the child", async () => {
    const peer = await openPeer();
    const store = seededStore();
    const result = await runWithManifest({
      store,
      manifest: testManifest(peer.url),
      command: process.execPath,
      args: ["--import", "tsx", probePath, "env"],
      stdio: "pipe",
      env: { GITHUB_TOKEN: TOKEN },
      approve: async () => true,
    });

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      ok: true,
      hasUrl: true,
      hasToken: true,
      hasSock: false,
      hasGithubToken: false,
    });

    const session = await openSession(peer.url);
    await expect(
      getSecret("gh-token", { socketPath: "missing", token: session.token }),
    ).rejects.toThrow();
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
      approve: async () => true,
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
  approve: () => Promise<boolean> = async () => true,
): Promise<AgentSession> {
  const session = await startAgentSession({
    store: seededStore(),
    manifest: testManifest(peerUrl),
    approve,
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
        source: { env: "GITHUB_TOKEN" },
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
