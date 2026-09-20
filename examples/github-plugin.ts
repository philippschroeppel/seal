import { type AgentConnection, agent } from "../src/index.js";

/**
 * Agent-side GitHub helpers. They only call `agent.use`; Seal loads the
 * github plugin and attaches the token.
 */
export async function githubRequest(
  path: string,
  init: { method?: string; body?: unknown } = {},
  connection?: AgentConnection,
): Promise<{ status: number; body: string }> {
  return agent.use(
    {
      plugin: "github",
      identity: "gh-token",
      input: {
        path,
        ...(init.method === undefined ? {} : { method: init.method }),
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
  return agent.use(
    {
      plugin: "github",
      identity: "gh-token",
      input: {
        op: "createPullRequest",
        repo,
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
