import {
  agent,
  type AgentConnection,
  type PluginContract,
} from "../src/index.js";

/**
 * Agent-side GitHub glue. Talks only to Seal HTTP; never calls getSecret.
 * Seal does not load this module.
 */
export const githubPlugin: PluginContract = {
  name: "github",
  version: "0.1.0",
  identities: [
    {
      name: "gh-token",
      ops: ["http"],
      peers: ["https://api.github.com/"],
    },
    {
      name: "me-sign",
      ops: ["sign"],
      formats: ["hmac-sha256"],
    },
  ],
};

export async function githubRequest(
  path: string,
  init: { method?: string; body?: unknown } = {},
  connection?: AgentConnection,
): Promise<{ status: number; body: string }> {
  const result = await agent.http(
    {
      identity: "gh-token",
      method: init.method ?? "GET",
      url: `https://api.github.com${path}`,
      ...(init.body === undefined ? {} : { body: init.body }),
    },
    connection,
  );
  return { status: result.status, body: result.body };
}

export function createPullRequest(
  repo: string,
  body: { title: string; head: string; base: string; body?: string },
  connection?: AgentConnection,
): Promise<{ status: number; body: string }> {
  return githubRequest(`/repos/${repo}/pulls`, { method: "POST", body }, connection);
}

export function signCommit(
  digest: string,
  connection?: AgentConnection,
): Promise<{ signature: string }> {
  return agent.sign(
    {
      identity: "me-sign",
      payload: digest,
      format: "hmac-sha256",
    },
    connection,
  );
}
