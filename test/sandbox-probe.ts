import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { agent } from "../src/agent-client.js";

const canary = process.argv[2];
const peerUrl = process.argv[3];

let fetchOk = false;
try {
  const response = await fetch("https://example.com");
  fetchOk = response.ok;
} catch {
  fetchOk = false;
}

let http: { status: number; body: string } | { error: string } | undefined;
if (peerUrl) {
  try {
    const result = await agent.http({
      identity: "gh-token",
      method: "GET",
      url: `${peerUrl}/repos/acme/seal/issues`,
    });
    http = { status: result.status, body: result.body };
  } catch (error) {
    http = {
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

process.stdout.write(
  `${JSON.stringify({
    home: homedir(),
    githubToken: Boolean(process.env.GITHUB_TOKEN),
    hasCanary: canary ? existsSync(canary) : false,
    fetchOk,
    http,
    sealUrl: process.env.SEAL_URL ?? null,
  })}\n`,
);
