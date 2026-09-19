import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { startBroker, runWithGrant, type Broker } from "../src/broker.js";
import { getSecret } from "../src/client.js";
import { SealError } from "../src/errors.js";
import { MemorySecretStore } from "../src/store.js";

const probePath = fileURLToPath(new URL("./probe.ts", import.meta.url));

const brokers: Broker[] = [];

afterEach(() => {
  for (const broker of brokers.splice(0)) {
    broker.close();
  }
});

async function openBroker(ttlMs = 5_000): Promise<Broker> {
  const store = new MemorySecretStore();
  store.put("db/password", "hunter2-but-actually-random");
  store.put("db/root-password", "top-secret-do-not-leak");
  const broker = await startBroker({
    store,
    secretNames: ["db/password"],
    ttlMs,
  });
  brokers.push(broker);
  return broker;
}

describe("broker", () => {
  it("returns a granted secret and denies anything else", async () => {
    const broker = await openBroker();
    await expect(getSecret("db/password", broker)).resolves.toBe("hunter2-but-actually-random");
    await expect(getSecret("db/root-password", broker)).rejects.toMatchObject({
      code: "not_granted",
    } satisfies Partial<SealError>);
  });

  it("rejects a request with the wrong token", async () => {
    const broker = await openBroker();
    await expect(
      getSecret("db/password", { socketPath: broker.socketPath, token: "nope" }),
    ).rejects.toMatchObject({ code: "unauthorized" });
  });

  it("stops serving after close and after TTL", async () => {
    const broker = await openBroker(40);
    await new Promise((resolve) => setTimeout(resolve, 50));
    await expect(getSecret("db/password", broker)).rejects.toMatchObject({
      code: "grant_expired",
    });

    const closed = await openBroker();
    closed.close();
    await expect(getSecret("db/password", closed)).rejects.toThrow();
  });

  it("injects socket and token into a child process", async () => {
    const store = new MemorySecretStore();
    store.put("db/password", "from-child");

    const result = await runWithGrant({
      store,
      secretNames: ["db/password"],
      ttlMs: 5_000,
      command: process.execPath,
      args: ["--import", "tsx", probePath, "db/password"],
      stdio: "pipe",
    });

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ ok: true, value: "from-child" });
  });
});
