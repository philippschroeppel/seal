import { type AgentConnection, agent } from "../src/index.js";

/**
 * Agent-side SSH helpers. They only call `agent.use`; Seal holds the
 * OpenSSH private key and returns a public key or an SSH signature.
 */
export function sshPublicKey(
  identity = "me-ssh",
  connection?: AgentConnection,
): Promise<{
  publicKey: string;
  type: string;
  comment: string;
  fingerprint: string;
}> {
  return agent.use(
    { plugin: "ssh", identity, input: { op: "publicKey" } },
    connection,
  );
}

export function signGit(
  payload: string,
  identity = "me-ssh",
  connection?: AgentConnection,
): Promise<{ signature: string; namespace: string }> {
  return agent.use(
    {
      plugin: "ssh",
      identity,
      input: { op: "sign", namespace: "git", payload },
    },
    connection,
  );
}
