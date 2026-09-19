import { describe, expect, it } from "vitest";
import * as seal from "../src/index.js";
import * as script from "../src/script.js";

describe("public exports", () => {
  it("keeps disclosure APIs off the agent entrypoint", () => {
    expect(seal).not.toHaveProperty("getSecret");
    expect(seal).not.toHaveProperty("startBroker");
    expect(seal).not.toHaveProperty("runWithGrant");
    expect(seal).not.toHaveProperty("unseal");
    expect(seal).toHaveProperty("agent");
    expect(seal).toHaveProperty("assertCompatible");
    expect(seal).toHaveProperty("startAgentSession");
    expect(seal).toHaveProperty("SEAL_SCHEMA");
  });

  it("exposes the script broker on seal/script", () => {
    expect(script).toHaveProperty("getSecret");
    expect(script).toHaveProperty("startBroker");
    expect(script).toHaveProperty("runWithGrant");
    expect(script).not.toHaveProperty("agent");
  });
});
