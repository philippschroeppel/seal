import { afterEach, describe, expect, it } from "vitest";
import {
  type AgentSession,
  agent,
  assertCompatible,
  MemorySecretStore,
  type PluginContract,
  type SessionCapabilities,
  startAgentSession,
} from "../src/index.js";
import {
  createPullRequest,
  githubPlugin,
  signCommit,
} from "../examples/github-plugin.js";

const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "unit-test-hmac-key";

const sessions: AgentSession[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    session.close();
  }
});

describe("github plugin", () => {
  it("only talks to Seal HTTP and never asks for plaintext", async () => {
    await expect(
      createPullRequest("philippschroeppel/seal", {
        title: "demo",
        head: "feature",
        base: "main",
      }),
    ).rejects.toMatchObject({ code: "not_attached" });

    await expect(signCommit("abc123")).rejects.toMatchObject({
      code: "not_attached",
    });
  });

  it("is compatible with a GitHub session and performs use-not-read calls", async () => {
    const seen: string[] = [];
    const session = await openGithubSession(async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push(headers.get("authorization") ?? "");
      expect(String(input)).toBe(
        "https://api.github.com/repos/philippschroeppel/seal/pulls",
      );
      return new Response(JSON.stringify({ number: 1 }), { status: 201 });
    });

    const caps = await agent.capabilities(session);
    assertCompatible(githubPlugin, caps);

    const pr = await createPullRequest(
      "philippschroeppel/seal",
      { title: "demo", head: "feature", base: "main" },
      session,
    );
    expect(pr.status).toBe(201);
    expect(pr.body).not.toContain(TOKEN);
    expect(seen).toEqual([`Bearer ${TOKEN}`]);

    const signed = await signCommit("abc123", session);
    expect(signed.signature).toMatch(/^[0-9a-f]+$/);
    expect(signed.signature).not.toContain(SIGNING_KEY);
  });

  it("fails closed when the session is missing a required identity", () => {
    const caps: SessionCapabilities = {
      session: "session-1",
      ops: ["http"],
      identities: [
        {
          name: "gh-token",
          ops: ["http"],
          approve: "never",
          peers: ["https://api.github.com/"],
        },
      ],
      openapi: "/v1/openapi.json",
    };

    expect(() => assertCompatible(githubPlugin, caps)).toThrow(
      /no identity me-sign/,
    );
  });

  it("fails closed when a declared peer is not bound", () => {
    const plugin: PluginContract = {
      name: "github",
      version: "0.1.0",
      identities: [
        {
          name: "gh-token",
          ops: ["http"],
          peers: ["https://api.github.com/"],
        },
      ],
    };
    const caps: SessionCapabilities = {
      session: "session-1",
      ops: ["http"],
      identities: [
        {
          name: "gh-token",
          ops: ["http"],
          approve: "never",
          peers: ["https://api.github.com/repos/acme/"],
        },
      ],
      openapi: "/v1/openapi.json",
    };

    expect(() => assertCompatible(plugin, caps)).toThrow(/not bound/);
  });
});

async function openGithubSession(
  fetchImpl: typeof fetch,
): Promise<AgentSession> {
  const store = new MemorySecretStore();
  store.put("gh-token", TOKEN);
  store.put("me-sign", SIGNING_KEY);
  const session = await startAgentSession({
    store,
    approve: async () => true,
    fetch: fetchImpl,
    manifest: {
      ttlMs: 5_000,
      sessionId: "session-1",
      policies: `
permit (
  principal is Seal::Agent,
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "https://api.github.com/repos/philippschroeppel/seal/*"
  && ["GET", "POST"].contains(context.method)
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
          peers: ["https://api.github.com/"],
        },
        {
          name: "me-sign",
          secret: "me-sign",
          attach: { type: "hmac-sha256" },
          approve: "each",
        },
      ],
    },
  });
  sessions.push(session);
  return session;
}
