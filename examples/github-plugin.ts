import { agent } from "../src/agent-client.js";

/**
 * Agent-side glue. Talks only to Seal HTTP; never calls getSecret.
 */
export async function githubRequest(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<{ status: number; body: string }> {
  const result = await agent.http({
    identity: "gh-token",
    method: init.method ?? "GET",
    url: `https://api.github.com${path}`,
    ...(init.body === undefined ? {} : { body: init.body }),
  });
  return { status: result.status, body: result.body };
}

export function createPullRequest(
  repo: string,
  body: { title: string; head: string; base: string; body?: string },
): Promise<{ status: number; body: string }> {
  return githubRequest(`/repos/${repo}/pulls`, { method: "POST", body });
}

export function signCommit(digest: string): Promise<{ signature: string }> {
  return agent.sign({
    identity: "me-sign",
    payload: digest,
    format: "hmac-sha256",
  });
}
