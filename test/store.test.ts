import { describe, expect, it } from "vitest";
import { SealError } from "../src/errors.js";
import { generateKeyPair, unseal } from "../src/seal.js";
import { decryptValue, MemorySecretStore } from "../src/store.js";

describe("MemorySecretStore", () => {
  it("issues a grant that decrypts only the named secrets", () => {
    const store = new MemorySecretStore();
    store.put("db/password", "hunter2");
    store.put("db/root-password", "nope");

    const recipient = generateKeyPair();
    store.issueGrant("g1", ["db/password"], recipient.publicKey, 60_000);

    const grant = store.fetchGrant("g1");
    expect(grant).toBeDefined();
    expect(grant?.entries.map((entry) => entry.name)).toEqual(["db/password"]);

    const entry = grant?.entries[0];
    expect(entry).toBeDefined();
    if (!entry) {
      return;
    }
    const dek = unseal(entry.wrappedDek, recipient.secretKey);
    expect(decryptValue(entry, dek)).toBe("hunter2");
  });

  it("hides expired and revoked grants", async () => {
    const store = new MemorySecretStore();
    store.put("db/password", "hunter2");
    const recipient = generateKeyPair();

    store.issueGrant("short", ["db/password"], recipient.publicKey, 20);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(store.fetchGrant("short")).toBeUndefined();

    store.issueGrant("revoked", ["db/password"], recipient.publicKey, 60_000);
    store.revokeGrant("revoked");
    expect(store.fetchGrant("revoked")).toBeUndefined();
  });

  it("fails closed on unknown secret names", () => {
    const store = new MemorySecretStore();
    const recipient = generateKeyPair();
    expect(() =>
      store.issueGrant("g1", ["missing"], recipient.publicKey, 1000),
    ).toThrow(SealError);
  });
});
