import { afterEach, describe, expect, it } from "vitest";
import {
  createPullRequest,
  githubRequest,
  signCommit,
} from "../examples/github-plugin.js";
import {
  type AgentSession,
  agent,
  MemorySecretStore,
  startAgentSession,
} from "../src/index.js";

const TOKEN = "secret-pat-do-not-leak";
const SIGNING_KEY = "unit-test-hmac-key";

const sessions: AgentSession[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    session.close();
  }
});

describe("github example (http glue)", () => {
  it("only talks to Seal and never asks for plaintext", async () => {
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

  it("calls http through Seal with the unsealed token", async () => {
    const seen: { url: string; authorization: string }[] = [];
    const session = await openGithubSession(async (input, init) => {
      const headers = new Headers(init?.headers);
      seen.push({
        url: String(input),
        authorization: headers.get("authorization") ?? "",
      });
      return new Response(JSON.stringify({ number: 1 }), { status: 201 });
    });

    const pr = await createPullRequest(
      "philippschroeppel/seal",
      { title: "demo", head: "feature", base: "main" },
      session,
    );
    expect(pr.status).toBe(201);
    expect(pr.body).not.toContain(TOKEN);
    expect(seen[0]).toEqual({
      url: "https://api.github.com/repos/philippschroeppel/seal/pulls",
      authorization: `Bearer ${TOKEN}`,
    });

    const generic = await githubRequest("/user", { method: "GET" }, session);
    expect(generic.status).toBe(201);
    expect(seen[1]?.url).toBe("https://api.github.com/user");

    const signed = await signCommit("abc123", session);
    expect(signed.signature).toMatch(/^[0-9a-f]+$/);
    expect(signed.signature).not.toContain(SIGNING_KEY);
  });

  it("refuses an http call when the identity is not granted", async () => {
    const store = new MemorySecretStore();
    store.put("gh-token", TOKEN);
    const session = await startAgentSession({
      store,
      manifest: {
        ttlMs: 5_000,
        identities: [],
      },
      consent: async () => ({ granted: false }),
    });
    sessions.push(session);

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "gh-token",
          input: { method: "GET", url: "https://api.github.com/user" },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "not_granted" });
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
    fetch: fetchImpl,
    manifest: {
      ttlMs: 5_000,
      sessionId: "session-1",
      identities: [
        {
          name: "gh-token",
          secret: "gh-token",
          plugins: ["http"],
          peers: ["https://api.github.com/"],
        },
        {
          name: "me-sign",
          secret: "me-sign",
          plugins: ["sign"],
          format: "hmac-sha256",
        },
      ],
    },
  });
  sessions.push(session);
  return session;
}
