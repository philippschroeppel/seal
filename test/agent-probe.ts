import { agent } from "../src/agent-client.js";
import { isSealError } from "../src/errors.js";

const mode = process.argv[2];
const url = process.argv[3];

try {
  if (mode === "http") {
    if (!url) {
      throw new Error("usage: agent-probe http <url>");
    }
    const result = await agent.http({
      identity: "gh-token",
      method: "GET",
      url,
    });
    process.stdout.write(
      `${JSON.stringify({ ok: true, status: result.status, body: result.body })}\n`,
    );
  } else if (mode === "sign") {
    const result = await agent.sign({
      identity: "me-sign",
      payload: "commit-digest",
      format: "hmac-sha256",
    });
    process.stdout.write(
      `${JSON.stringify({ ok: true, signature: result.signature })}\n`,
    );
  } else if (mode === "env") {
    process.stdout.write(
      `${JSON.stringify({
        ok: true,
        hasUrl: Boolean(process.env.SEAL_URL),
        hasToken: Boolean(process.env.SEAL_TOKEN),
        hasSock: Boolean(process.env.SEAL_SOCK),
        hasGithubToken: Boolean(process.env.GITHUB_TOKEN),
      })}\n`,
    );
  } else {
    throw new Error("usage: agent-probe http|sign|env");
  }
} catch (error) {
  const payload = isSealError(error)
    ? { ok: false, error: error.code, message: error.message }
    : {
        ok: false,
        message: error instanceof Error ? error.message : String(error),
      };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = 1;
}
