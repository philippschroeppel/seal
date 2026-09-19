import { runWithGrant } from "./broker.js";
import { getSecret } from "./client.js";
import { isSealError } from "./errors.js";
import { MemorySecretStore } from "./store.js";

async function runAsChild(): Promise<void> {
  console.log("[child] fetching granted secret 'db/password'...");
  console.log("[child] got:", await getSecret("db/password"));

  console.log("[child] trying ungranted secret 'db/root-password'...");
  try {
    await getSecret("db/root-password");
  } catch (error) {
    console.log("[child] correctly denied:", describe(error));
  }

  console.log("[child] sleeping past TTL, then retrying granted secret...");
  await sleep(3000);
  try {
    const value = await getSecret("db/password");
    console.log("[child] unexpectedly still got:", value);
  } catch (error) {
    console.log("[child] correctly revoked after TTL:", describe(error));
  }
}

async function runAsCli(): Promise<void> {
  const store = new MemorySecretStore();
  store.put("db/password", "hunter2-but-actually-random");
  store.put("db/root-password", "top-secret-do-not-leak");

  const self = process.argv[1];
  if (!self) {
    throw new Error("cannot re-invoke this program: process.argv[1] is missing");
  }

  console.log("[cli] granting the child process access to db/password for 2s...\n");

  const { exitCode } = await runWithGrant({
    store,
    secretNames: ["db/password"],
    ttlMs: 2000,
    command: process.execPath,
    args: [...process.execArgv, self, "child"],
  });

  console.log(`\n[cli] child exited with code ${exitCode}`);
}

function describe(error: unknown): string {
  if (isSealError(error)) {
    return `${error.code}: ${error.message}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const mode = process.argv[2];
if (mode === "child") {
  await runAsChild();
} else {
  await runAsCli();
}
