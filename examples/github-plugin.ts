import { type AgentConnection, agent } from "../src/index.js";

const GITHUB_API = "https://api.github.com";

/**
 * Agent-side GitHub helpers. They only call `agent.use` with the http
 * plugin. Seal attaches the token; this module never sees it.
 */
export async function githubRequest(
  path: string,
  init: { method?: string; body?: unknown } = {},
  connection?: AgentConnection,
): Promise<{ status: number; body: string }> {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return agent.use(
    {
      plugin: "http",
      identity: "gh-token",
      input: {
        method: init.method ?? "GET",
        url: `${GITHUB_API}${suffix}`,
        headers: { Accept: "application/vnd.github+json" },
        ...(init.body === undefined ? {} : { body: init.body }),
      },
    },
    connection,
  );
}

export function createPullRequest(
  repo: string,
  body: { title: string; head: string; base: string; body?: string },
  connection?: AgentConnection,
): Promise<{ status: number; body: string }> {
  return githubRequest(
    `/repos/${repo}/pulls`,
    {
      method: "POST",
      body: {
        title: body.title,
        head: body.head,
        base: body.base,
        ...(body.body === undefined ? {} : { body: body.body }),
      },
    },
    connection,
  );
}

export function signCommit(
  digest: string,
  connection?: AgentConnection,
): Promise<{ signature: string }> {
  return agent.use(
    {
      plugin: "sign",
      identity: "me-sign",
      input: { payload: digest, format: "hmac-sha256" },
    },
    connection,
  );
}
