import { describe, expect, it } from "vitest";
import { wipe } from "../src/bytes.js";
import { generateKeyPair, seal, unseal } from "../src/seal.js";

describe("seal", () => {
  it("round-trips plaintext to the intended recipient", () => {
    const recipient = generateKeyPair();
    const plaintext = new TextEncoder().encode(
      "only the parent can unwrap this",
    );
    const boxed = seal(plaintext, recipient.publicKey);
    expect(unseal(boxed, recipient.secretKey)).toEqual(plaintext);
  });

  it("rejects a box opened with the wrong key", () => {
    const recipient = generateKeyPair();
    const stranger = generateKeyPair();
    const boxed = seal(new TextEncoder().encode("secret"), recipient.publicKey);
    expect(() => unseal(boxed, stranger.secretKey)).toThrow();
  });

  it("rejects a truncated or empty box", () => {
    const recipient = generateKeyPair();
    expect(() => unseal(new Uint8Array(10), recipient.secretKey)).toThrow(
      /too short/,
    );
  });

  it("rejects a tampered ciphertext", () => {
    const recipient = generateKeyPair();
    const boxed = seal(new TextEncoder().encode("secret"), recipient.publicKey);
    const last = boxed.length - 1;
    boxed[last] = (boxed[last] ?? 0) ^ 0xff;
    expect(() => unseal(boxed, recipient.secretKey)).toThrow();
  });

  it("wipes buffers in place", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    wipe(bytes);
    expect(bytes).toEqual(new Uint8Array([0, 0, 0]));
  });
});
