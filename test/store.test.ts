import { describe, expect, it } from "vitest";
import { SealError } from "../src/errors.js";
import { MemorySecretStore } from "../src/store.js";

describe("MemorySecretStore", () => {
  it("puts a named secret and uses it without leaking the store slot", async () => {
    const store = new MemorySecretStore();
    store.put("db/password", "hunter2");
    expect(store.has("db/password")).toBe(true);
    expect(store.has("db/root-password")).toBe(false);

    const used = await store.use("db/password", (value) => value.toUpperCase());
    expect(used).toBe("HUNTER2");
    expect(await store.use("db/password", (value) => value)).toBe("hunter2");
  });

  it("replaces a name and wipes the previous DEK", async () => {
    const store = new MemorySecretStore();
    store.put("token", "old");
    store.put("token", "new");
    expect(await store.use("token", (value) => value)).toBe("new");
  });

  it("fails closed on unknown names and after wipe", async () => {
    const store = new MemorySecretStore();
    await expect(store.use("missing", (value) => value)).rejects.toBeInstanceOf(
      SealError,
    );

    store.put("token", "alive");
    store.wipe("token");
    expect(store.has("token")).toBe(false);
    store.put("a", "1");
    store.put("b", "2");
    store.wipe();
    expect(store.has("a")).toBe(false);
    expect(store.has("b")).toBe(false);
  });
});
