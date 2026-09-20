import { describe, expect, it } from "vitest";
import * as seal from "../src/index.js";

describe("public exports", () => {
  it("keeps disclosure APIs off the package", () => {
    expect(seal).not.toHaveProperty("getSecret");
    expect(seal).not.toHaveProperty("startBroker");
    expect(seal).not.toHaveProperty("runWithGrant");
    expect(seal).not.toHaveProperty("unseal");
    expect(seal).not.toHaveProperty("SEAL_SCHEMA");
    expect(seal).toHaveProperty("agent");
    expect(seal).toHaveProperty("startAgentSession");
    expect(seal).toHaveProperty("MemorySecretStore");
    expect(seal.builtinPluginNames()).toEqual(["http", "sign", "github"]);
    expect(seal.agent).toHaveProperty("use");
    expect(seal.agent).toHaveProperty("put");
    expect(seal.agent).toHaveProperty("request");
    expect(seal.agent).not.toHaveProperty("http");
    expect(seal.agent).not.toHaveProperty("sign");
    expect(seal.agent).not.toHaveProperty("openapi");
  });
});
